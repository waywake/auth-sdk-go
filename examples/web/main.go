// Command web demonstrates browser-bound, single-use OAuth transactions.
// Run behind an HTTPS reverse proxy using a registered callback URL.
package main

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"

	auth "github.com/waywake/auth-sdk-go"
)

const (
	cookieName = "__Host-auth-sdk-example"
	loginTTL   = 5 * time.Minute
	maxPending = 1024
)

type pendingLogin struct {
	authorization auth.Authorization
	expiresAt     time.Time
}

// This demonstration store is process-local. A multi-instance application needs
// shared storage with an atomic state comparison and transaction deletion.
type loginStore struct {
	mu      sync.Mutex
	entries map[string]pendingLogin
}

func (s *loginStore) put(id string, a auth.Authorization, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, entry := range s.entries {
		if !now.Before(entry.expiresAt) {
			delete(s.entries, key)
		}
	}
	if len(s.entries) >= maxPending {
		return false
	}
	s.entries[id] = pendingLogin{authorization: a, expiresAt: now.Add(loginTTL)}
	return true
}

func (s *loginStore) consume(id, state string, now time.Time) (auth.Authorization, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[id]
	if !ok {
		return auth.Authorization{}, false
	}
	if !now.Before(entry.expiresAt) {
		delete(s.entries, id)
		return auth.Authorization{}, false
	}
	if auth.VerifyState(entry.authorization.State, state) != nil {
		return auth.Authorization{}, false
	}
	delete(s.entries, id)
	return entry.authorization, true
}

type application struct {
	client      *auth.Client
	redirectURI string
	logins      loginStore
}

func (a *application) login(w http.ResponseWriter, r *http.Request) {
	tx, err := a.client.NewAuthorization(a.redirectURI, auth.ScopeProfileRead)
	if err != nil {
		a.fail(w, err)
		return
	}
	id, err := auth.GenerateState()
	if err != nil {
		a.fail(w, err)
		return
	}
	if !a.logins.put(id, *tx, time.Now()) {
		http.Error(w, "Too many pending logins", http.StatusServiceUnavailable)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: id, Path: "/", Secure: true,
		HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: int(loginTTL.Seconds())})
	http.Redirect(w, r, tx.URL, http.StatusFound)
}

func (a *application) callback(w http.ResponseWriter, r *http.Request) {
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(query["state"]) != 1 || len(query["code"]) != 1 || query.Has("error") {
		http.Error(w, "Invalid authorization callback", http.StatusBadRequest)
		return
	}
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		http.Error(w, "Missing login session", http.StatusBadRequest)
		return
	}
	// Compare state and delete under one lock, before exchanging the code.
	tx, ok := a.logins.consume(cookie.Value, query.Get("state"), time.Now())
	if !ok {
		http.Error(w, "Invalid or expired login session", http.StatusBadRequest)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Path: "/", Secure: true,
		HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	token, err := a.client.ExchangeCode(r.Context(), auth.ExchangeCodeParams{
		Code: query.Get("code"), RedirectURI: tx.RedirectURI, CodeVerifier: tx.CodeVerifier,
	})
	if err != nil {
		a.fail(w, err)
		return
	}
	profile, err := a.client.GetCurrentUser(r.Context(), token.AccessToken)
	if err != nil {
		a.fail(w, err)
		return
	}
	// Only the profile is returned. A real application would create its own
	// session here and retain the token only in server-side storage if needed.
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(profile)
}

func (*application) fail(w http.ResponseWriter, err error) {
	var apiErr *auth.APIError
	if errors.As(err, &apiErr) {
		log.Printf("Auth request failed: status=%d code=%q request_id=%q", apiErr.StatusCode, apiErr.Code, apiErr.RequestID)
	} else {
		log.Print("Auth request failed")
	}
	http.Error(w, "Authentication failed; start a new login", http.StatusBadGateway)
}

func main() {
	id, err := strconv.ParseInt(os.Getenv("AUTH_CLIENT_ID"), 10, 64)
	if err != nil {
		log.Fatal("AUTH_CLIENT_ID must be a positive integer")
	}
	if os.Getenv("AUTH_CLIENT_SECRET") == "" {
		log.Fatal("AUTH_CLIENT_SECRET is required")
	}
	client, err := auth.NewClient(auth.Config{
		BaseURL: os.Getenv("AUTH_BASE_URL"), ClientID: id, ClientSecret: os.Getenv("AUTH_CLIENT_SECRET"),
	})
	if err != nil {
		log.Fatal(err)
	}
	redirectURI := os.Getenv("AUTH_REDIRECT_URI")
	if _, err := client.NewAuthorization(redirectURI, auth.ScopeProfileRead); err != nil {
		log.Fatal(err)
	}
	callbackURL, _ := url.Parse(redirectURI)
	if callbackURL.Path != "/callback" {
		log.Fatal("AUTH_REDIRECT_URI must use the /callback path")
	}
	app := &application{client: client, redirectURI: redirectURI, logins: loginStore{entries: make(map[string]pendingLogin)}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", app.login)
	mux.HandleFunc("GET /callback", app.callback)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		mux.ServeHTTP(w, r)
	})
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}
	server := &http.Server{Addr: addr, Handler: handler, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second, WriteTimeout: 40 * time.Second, IdleTimeout: time.Minute, MaxHeaderBytes: 16 << 10}
	log.Printf("OAuth example listening on %s behind HTTPS; open /login on the callback domain", addr)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
