package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/waywake/auth-sdk-go"
)

func TestTransactionBindingExpiryAndAtomicConsumption(t *testing.T) {
	s := &loginStore{entries: make(map[string]pendingLogin)}
	now := time.Now()
	tx := auth.Authorization{State: strings.Repeat("s", 43), CodeVerifier: "server-only"}
	if !s.put("browser-1", tx, now) {
		t.Fatal("put failed")
	}
	for _, input := range [][2]string{{"browser-2", tx.State}, {"browser-1", strings.Repeat("x", 43)}} {
		if _, ok := s.consume(input[0], input[1], now); ok {
			t.Fatal("accepted incorrect browser/state")
		}
	}
	var wg sync.WaitGroup
	var consumed atomic.Int32
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if got, ok := s.consume("browser-1", tx.State, now); ok {
				consumed.Add(1)
				if got.CodeVerifier != tx.CodeVerifier {
					t.Error("incorrect transaction")
				}
			}
		}()
	}
	wg.Wait()
	if consumed.Load() != 1 {
		t.Fatalf("consumed %d times", consumed.Load())
	}
	s.put("expired", tx, now)
	if _, ok := s.consume("expired", tx.State, now.Add(loginTTL)); ok {
		t.Fatal("accepted expired transaction")
	}
	s.put("stale", tx, now)
	s.put("fresh", tx, now.Add(loginTTL))
	if _, ok := s.entries["stale"]; ok {
		t.Fatal("stale transaction not pruned")
	}
}

func TestLoginAndCallback(t *testing.T) {
	const token = "oat_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"
	const code = "oac_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"
	var exchanges atomic.Int32
	var expectedVerifier string
	authServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/openapi/v1/oauth/token":
			exchanges.Add(1)
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
			if r.PostForm.Get("code_verifier") != expectedVerifier || r.PostForm.Get("redirect_uri") != "https://app.example.com/callback" || r.PostForm.Get("code") != code {
				t.Error("incorrect exchange transaction")
			}
			w.Write([]byte(`{"access_token":"` + token + `","token_type":"Bearer","expires_in":900,"scope":"profile:read"}`))
		case "/openapi/v1/me":
			w.Write([]byte(`{"data":{"id":1,"username":"u","name":"n","avatar":""},"request_id":"test"}`))
		default:
			t.Error("unexpected Auth request")
			w.WriteHeader(404)
		}
	}))
	defer authServer.Close()
	client, err := auth.NewClient(auth.Config{BaseURL: authServer.URL, ClientID: 42,
		ClientSecret: "oas_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG", HTTPClient: authServer.Client()})
	if err != nil {
		t.Fatal(err)
	}
	a := &application{client: client, redirectURI: "https://app.example.com/callback", logins: loginStore{entries: make(map[string]pendingLogin)}}
	login := httptest.NewRecorder()
	a.login(login, httptest.NewRequest("GET", "https://app.example.com/login", nil))
	if login.Code != 302 {
		t.Fatal(login.Code)
	}
	cookies := login.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteLaxMode {
		t.Fatal("invalid login cookie")
	}
	u, err := url.Parse(login.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	state := u.Query().Get("state")
	expectedVerifier = a.logins.entries[cookies[0].Value].authorization.CodeVerifier
	callbackURL := "https://app.example.com/callback?code=" + code + "&state=" + state
	for _, target := range []string{callbackURL + "&state=" + state, callbackURL + "&code=" + code, "https://app.example.com/callback?state=%", "https://app.example.com/callback?code=" + code + "&state=" + strings.Repeat("x", 43)} {
		r := httptest.NewRequest("GET", target, nil)
		r.AddCookie(cookies[0])
		w := httptest.NewRecorder()
		a.callback(w, r)
		if w.Code != http.StatusBadRequest {
			t.Fatal("invalid callback accepted")
		}
	}
	for i := 0; i < 2; i++ {
		r := httptest.NewRequest("GET", callbackURL, nil)
		r.AddCookie(cookies[0])
		w := httptest.NewRecorder()
		a.callback(w, r)
		if i == 0 {
			if w.Code != 200 || !strings.Contains(w.Body.String(), `"username":"u"`) || strings.Contains(w.Body.String(), token) {
				t.Fatal("invalid callback response")
			}
		} else if w.Code != 400 {
			t.Fatal("callback replay accepted")
		}
	}
	if exchanges.Load() != 1 {
		t.Fatal("code was exchanged multiple times")
	}
}
