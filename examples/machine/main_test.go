package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	auth "github.com/waywake/auth-sdk-go"
)

const (
	testSecret = "oas_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"
	testToken  = "oam_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"
)

func TestRunUsesMachineCredentials(t *testing.T) {
	var paths []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/openapi/v1/oauth/token":
			if id, secret, ok := r.BasicAuth(); !ok || id != "42" || secret != testSecret {
				t.Error("the token request must use the application's client credentials")
			}
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
			if r.PostForm.Get("grant_type") != "client_credentials" || r.PostForm.Get("scope") != "directory:read events:read" {
				t.Errorf("form=%v", r.PostForm)
			}
			io.WriteString(w, `{"access_token":"`+testToken+`","token_type":"Bearer","expires_in":86400,"scope":"directory:read events:read"}`)
		default:
			if r.Header.Get("Authorization") != "Bearer "+testToken {
				t.Error("machine resources must present the machine token")
			}
			switch r.URL.Path {
			case "/openapi/v1/machine/me":
				io.WriteString(w, `{"data":{"app_id":42,"subject":"machine","scopes":["directory:read","events:read"],"credential_id":3},"request_id":"r"}`)
			case "/openapi/v1/machine/me/permissions":
				io.WriteString(w, `{"data":{"app_id":42,"scopes":["directory:read","events:read"]},"request_id":"r"}`)
			case "/openapi/v1/directory/users":
				if r.URL.Query().Get("limit") != "50" {
					t.Errorf("query=%v", r.URL.Query())
				}
				io.WriteString(w, `{"data":{"items":[],"next":7},"request_id":"r"}`)
			case "/openapi/v1/events":
				if r.URL.Query().Get("after") != "12" || r.URL.Query().Get("limit") != "200" {
					t.Errorf("query=%v", r.URL.Query())
				}
				io.WriteString(w, `{"data":{"next":13,"events":[{"id":13,"sequence":13,"type":"user.updated","subject":"user","subject_id":7,"occurred_at":"2026-09-30T10:00:00Z","expires_at":"2026-10-30T10:00:00Z","data":{"user_id":7}}],"has_more":false},"request_id":"r"}`)
			default:
				t.Errorf("unexpected path %s", r.URL.Path)
				w.WriteHeader(404)
			}
		}
	}))
	defer server.Close()

	cfg := config{
		baseURL: server.URL, clientID: 42, clientSecret: testSecret,
		scopes: []auth.Scope{auth.ScopeDirectoryRead, auth.ScopeEventsRead}, cursor: 12, httpClient: server.Client(),
	}
	var out bytes.Buffer
	if err := run(context.Background(), cfg, &out); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		"/openapi/v1/oauth/token", "/openapi/v1/machine/me", "/openapi/v1/machine/me/permissions",
		"/openapi/v1/directory/users", "/openapi/v1/events",
	} {
		if !strings.Contains(strings.Join(paths, " "), path) {
			t.Errorf("missing call to %s", path)
		}
	}
	printed := out.String()
	for _, want := range []string{`"expires_in":86400`, `"has_refresh_token":false`, `"app_id":42`, `"items":0`, `"next":13`, `"type":"user.updated"`} {
		if !strings.Contains(printed, want) {
			t.Errorf("output is missing %s: %s", want, printed)
		}
	}
	if strings.Contains(printed, testToken) || strings.Contains(printed, testSecret) {
		t.Fatal("the example must never print a credential")
	}
}

func TestRunStopsOnAnExpiredCursor(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/openapi/v1/oauth/token" {
			io.WriteString(w, `{"access_token":"`+testToken+`","token_type":"Bearer","expires_in":86400,"scope":"events:read"}`)
			return
		}
		if r.URL.Path == "/openapi/v1/events" {
			w.WriteHeader(http.StatusGone)
			io.WriteString(w, `{"error":"snapshot_required","request_id":"r"}`)
			return
		}
		io.WriteString(w, `{"data":{"app_id":42,"subject":"machine","scopes":["events:read"]},"request_id":"r"}`)
	}))
	defer server.Close()

	cfg := config{
		baseURL: server.URL, clientID: 42, clientSecret: testSecret,
		scopes: []auth.Scope{auth.ScopeEventsRead}, httpClient: server.Client(),
	}
	err := run(context.Background(), cfg, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "rebuild the snapshot") {
		t.Fatalf("err=%v", err)
	}
}

func TestLoadConfig(t *testing.T) {
	t.Setenv("AUTH_CLIENT_ID", "42")
	t.Setenv("AUTH_CLIENT_SECRET", testSecret)
	t.Setenv("AUTH_BASE_URL", "https://auth.example.com")
	t.Setenv("AUTH_MACHINE_SCOPES", "")
	t.Setenv("AUTH_CURSOR", "")
	cfg, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.clientID != 42 || cfg.baseURL == "" || len(cfg.scopes) != 2 || cfg.cursor != 0 {
		t.Fatalf("config=%+v", cfg)
	}
	t.Setenv("AUTH_CLIENT_ID", "not-a-number")
	if _, err := loadConfig(); err == nil {
		t.Fatal("accepted an invalid client ID")
	}
	t.Setenv("AUTH_CLIENT_ID", "42")
	t.Setenv("AUTH_CURSOR", "-1")
	if _, err := loadConfig(); err == nil {
		t.Fatal("accepted a negative cursor")
	}
}

// TestRunRejectsInvalidInput keeps the local validation visible: the SDK
// refuses a request the server would reject anyway.
func TestRunRejectsInvalidInput(t *testing.T) {
	client, err := auth.NewClient(auth.Config{BaseURL: "https://auth.example.com", ClientID: 42, ClientSecret: testSecret})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.ClientCredentials(context.Background(), auth.ClientCredentialsParams{Scopes: []auth.Scope{auth.ScopeProfileRead}})
	if !errors.Is(err, auth.ErrInvalidArgument) {
		t.Fatalf("err=%v", err)
	}
}
