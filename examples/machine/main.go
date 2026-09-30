// Command machine demonstrates the client-credentials machine surface: mint a
// token for the application itself, describe it, read its scopes, list a page of
// the directory and pull one page of the change stream from a stored cursor.
//
// It never needs a browser and never sees an employee token. Run it with the
// application's own OpenAPI credentials:
//
//	export AUTH_BASE_URL=https://auth.example.com
//	export AUTH_CLIENT_ID=42
//	# Inject AUTH_CLIENT_SECRET through the environment or a secret manager.
//	go run ./examples/machine
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	auth "github.com/waywake/auth-sdk-go"
)

type config struct {
	baseURL      string
	clientID     int64
	clientSecret string
	// scopes are the machine scopes to request. Only scopes the administrator
	// granted the application may be requested.
	scopes []auth.Scope
	// cursor is the stored change-stream cursor; zero starts at the oldest
	// retained event.
	cursor int64
	// httpClient is nil in production, where the default client is used. A test
	// injects the one that trusts its own TLS server.
	httpClient *http.Client
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, "configuration error:", err)
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := run(ctx, cfg, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "machine call failed:", err)
		os.Exit(1)
	}
}

func loadConfig() (config, error) {
	cfg := config{baseURL: os.Getenv("AUTH_BASE_URL"), clientSecret: os.Getenv("AUTH_CLIENT_SECRET")}
	id, err := strconv.ParseInt(os.Getenv("AUTH_CLIENT_ID"), 10, 64)
	if err != nil || id <= 0 {
		return cfg, errors.New("AUTH_CLIENT_ID must be a positive integer")
	}
	cfg.clientID = id
	raw := os.Getenv("AUTH_MACHINE_SCOPES")
	if raw == "" {
		raw = string(auth.ScopeDirectoryRead) + " " + string(auth.ScopeEventsRead)
	}
	for _, name := range strings.Fields(raw) {
		cfg.scopes = append(cfg.scopes, auth.Scope(name))
	}
	if cursor := os.Getenv("AUTH_CURSOR"); cursor != "" {
		value, err := strconv.ParseInt(cursor, 10, 64)
		if err != nil || value < 0 {
			return cfg, errors.New("AUTH_CURSOR must be a non-negative integer")
		}
		cfg.cursor = value
	}
	return cfg, nil
}

// run mints one token and uses it for the whole machine surface. The token is
// cached by the caller in production, not re-minted per request.
func run(ctx context.Context, cfg config, out io.Writer) error {
	client, err := auth.NewClient(auth.Config{
		BaseURL: cfg.baseURL, ClientID: cfg.clientID, ClientSecret: cfg.clientSecret,
		HTTPClient: cfg.httpClient,
	})
	if err != nil {
		return err
	}
	token, err := client.ClientCredentials(ctx, auth.ClientCredentialsParams{Scopes: cfg.scopes})
	if err != nil {
		return err
	}
	// The token itself is never printed: it stays in process memory or in a
	// server-side cache.
	emit(out, "token", map[string]any{
		"expires_in": token.ExpiresIn, "scope": token.Scope, "has_refresh_token": token.RefreshToken != "",
	})

	identity, err := client.GetMachineIdentity(ctx, token.AccessToken)
	if err != nil {
		return err
	}
	emit(out, "machine", identity)

	scopes, err := client.GetMachineScopes(ctx, token.AccessToken)
	if err != nil {
		return err
	}
	emit(out, "scopes", scopes)

	if hasScope(token, auth.ScopeDirectoryRead) {
		page, err := client.ListDirectoryUsers(ctx, token.AccessToken, auth.ListDirectoryUsersParams{
			PageParams: auth.PageParams{Limit: auth.DefaultPageSize},
		})
		if err != nil {
			return err
		}
		// Next is the only cursor: persist it and pass it back as After. A zero
		// Next means the listing ended.
		emit(out, "directory", map[string]any{"items": len(page.Data.Items), "next": page.Data.Next})
	}

	if hasScope(token, auth.ScopeEventsRead) {
		events, err := client.PullEvents(ctx, token.AccessToken, auth.PullEventsParams{
			After: cfg.cursor, Limit: auth.MaxPageSize,
		})
		if err != nil {
			// 410 snapshot_required: the cursor is older than the retention
			// window, so the caller must rebuild its snapshot from zero.
			var apiErr *auth.APIError
			if errors.As(err, &apiErr) && apiErr.Code == auth.ErrorSnapshotRequired {
				return errors.New("cursor expired: rebuild the snapshot and restart from after=0")
			}
			return err
		}
		for _, event := range events.Data.Events {
			emit(out, "event", map[string]any{
				"id": event.ID, "type": event.Type, "subject": event.Subject, "subject_id": event.SubjectID,
			})
		}
		emit(out, "cursor", map[string]any{"next": events.Data.Next, "has_more": events.Data.HasMore})
	}
	return nil
}

func hasScope(token *auth.Token, want auth.Scope) bool {
	for _, scope := range token.Scopes() {
		if scope == want {
			return true
		}
	}
	return false
}

// emit writes one JSON line per step so the output can be piped into jq.
func emit(out io.Writer, label string, value any) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return
	}
	fmt.Fprintf(out, "%s %s\n", label, encoded)
}
