package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func clientForServer(t *testing.T, server *httptest.Server) *Client {
	t.Helper()
	c, err := NewClient(Config{BaseURL: server.URL + "/", ClientID: 42, ClientSecret: testSecret,
		HTTPClient: server.Client(), AllowInsecureHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestNewClient(t *testing.T) {
	for _, config := range []Config{
		{BaseURL: "https://auth.example.com", ClientID: 42},
		{BaseURL: "https://auth.example.com/", ClientID: 1, ClientSecret: testSecret},
		{BaseURL: "https://auth.example.com:8443", ClientID: 2147483647, MaxResponseBytes: 512},
		{BaseURL: "http://127.0.0.1:8080", ClientID: 42, AllowInsecureHTTP: true},
	} {
		c, err := NewClient(config)
		if err != nil {
			t.Fatal(err)
		}
		if c.httpClient.Timeout != DefaultTimeout {
			t.Fatal("missing default timeout")
		}
		if c.maxResponseBytes == 0 {
			t.Fatal("missing response limit")
		}
	}
	for _, raw := range []string{"", "/relative", "auth.example.com", "http://auth.example.com", "ftp://auth.example.com", "https://", "https://user:secret@auth.example.com", "https://auth.example.com/openapi/v1", "https://auth.example.com?", "https://auth.example.com?x=1", "https://auth.example.com#", "https://auth.example.com/#x", "https://auth.example.com/%"} {
		if _, err := NewClient(Config{BaseURL: raw, ClientID: 42}); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("accepted invalid origin %q: %v", raw, err)
		}
	}
	for _, id := range []int64{0, -1, 2147483648} {
		if _, err := NewClient(Config{BaseURL: "https://auth.example.com", ClientID: id}); !errors.Is(err, ErrInvalidArgument) {
			t.Fatal(err)
		}
	}
	for _, secret := range []string{"legacy-secret", "oas_short", testSecret + "\n"} {
		if _, err := NewClient(Config{BaseURL: "https://auth.example.com", ClientID: 42, ClientSecret: secret}); !errors.Is(err, ErrInvalidArgument) {
			t.Fatal(err)
		}
	}
	for _, limit := range []int64{-1, 1<<63 - 1} {
		if _, err := NewClient(Config{BaseURL: "https://auth.example.com", ClientID: 42, MaxResponseBytes: limit}); !errors.Is(err, ErrInvalidArgument) {
			t.Fatal(err)
		}
	}
	jar, _ := cookiejar.New(nil)
	hc := &http.Client{Timeout: time.Second, Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return nil }}
	c, err := NewClient(Config{BaseURL: "https://auth.example.com", ClientID: 42, HTTPClient: hc})
	if err != nil {
		t.Fatal(err)
	}
	if c.httpClient.Timeout != time.Second || c.httpClient.Jar != nil {
		t.Fatal("injected client not configured")
	}
	if hc.Jar != jar || hc.CheckRedirect(nil, nil) != nil {
		t.Fatal("caller client was mutated")
	}
	if c.httpClient.CheckRedirect(nil, nil) != http.ErrUseLastResponse {
		t.Fatal("redirects enabled")
	}
}

func TestOAuthAndResourcesOverTLS(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.RawQuery != "" {
			t.Error("credentials or selectors in query")
		}
		if r.Header.Get("Accept") != "application/json" || r.Header.Get("User-Agent") == "" || r.Header.Get("Cookie") != "" {
			t.Error("invalid common headers")
		}
		if r.TLS == nil {
			t.Error("expected TLS")
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("X-Request-ID", "request-header")
		if strings.HasPrefix(r.URL.Path, apiPath+"/oauth/") {
			id, secret, ok := r.BasicAuth()
			if !ok || id != "42" || secret != testSecret || r.Method != http.MethodPost {
				t.Error("invalid client auth")
			}
			if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
				t.Error("invalid form media type")
			}
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
		} else if r.Header.Get("Authorization") != "Bearer "+testToken {
			t.Error("invalid bearer auth")
		}
		switch r.URL.Path {
		case apiPath + "/oauth/token":
			want := url.Values{"grant_type": {"authorization_code"}, "code": {testCode}, "redirect_uri": {testRedirect}, "code_verifier": {testVerifier}}
			if !reflect.DeepEqual(r.PostForm, want) {
				t.Errorf("form=%v", r.PostForm)
			}
			fmt.Fprintf(w, `{"access_token":%q,"token_type":"Bearer","expires_in":900,"scope":"profile:read permissions:read permissions:check","future_field":true}`, testToken)
		case apiPath + "/oauth/revoke":
			want := url.Values{"token": {"unknown-token"}, "token_type_hint": {"access_token"}}
			if !reflect.DeepEqual(r.PostForm, want) {
				t.Errorf("form=%v", r.PostForm)
			}
			w.WriteHeader(http.StatusOK)
		case apiPath + "/me":
			if r.Method != http.MethodGet || r.ContentLength != 0 {
				t.Error("invalid profile request")
			}
			io.WriteString(w, `{"data":{"id":9007199254740993,"username":"alice","name":"测试用户","avatar":"https://img.example.com/a.png","hire_date":"2026-09-01","hire_date_source":"wecom_hr","departments":[{"id":10,"parent_id":1,"name":"技术部","order":1},{"id":11,"parent_id":10,"name":"后端组","order":2}],"future_field":true},"request_id":"profile-1","future_field":true}`)
		case apiPath + "/me/permissions":
			if r.Method != http.MethodGet {
				t.Error("invalid permissions method")
			}
			io.WriteString(w, `{"data":{"app_id":42,"user_id":9007199254740993,"roles":["reader"],"permissions":["order.read"]},"request_id":"permissions-1"}`)
		case apiPath + "/me/permissions/check":
			if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
				t.Error("invalid check request")
			}
			var input map[string]string
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
				t.Error(err)
			}
			if len(input) != 1 {
				t.Error("extra fields in check")
			}
			fmt.Fprintf(w, `{"data":{"allowed":%t},"request_id":"check-1"}`, input["permission"] == "order.read")
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	c := clientForServer(t, server)
	ctx := context.Background()
	token, err := c.ExchangeCode(ctx, ExchangeCodeParams{Code: testCode, RedirectURI: testRedirect, CodeVerifier: testVerifier})
	if err != nil {
		t.Fatal(err)
	}
	if token.AccessToken != testToken || token.ExpiresIn != 900 || token.TokenType != "Bearer" || token.Scope != "profile:read permissions:read permissions:check" {
		t.Fatal("invalid token")
	}
	profile, err := c.GetCurrentUser(ctx, token.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	wantDepartments := []Department{
		{ID: 10, ParentID: 1, Name: "技术部", Order: 1},
		{ID: 11, ParentID: 10, Name: "后端组", Order: 2},
	}
	if profile.Data.ID != 9007199254740993 || profile.Data.Name != "测试用户" || profile.Data.HireDate == nil || *profile.Data.HireDate != "2026-09-01" || profile.Data.HireDateSource != "wecom_hr" || !reflect.DeepEqual(profile.Data.Departments, wantDepartments) || profile.RequestID != "profile-1" {
		t.Fatalf("profile=%+v", profile)
	}
	permissions, err := c.GetCurrentPermissions(ctx, token.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if permissions.Data.AppID != 42 || !reflect.DeepEqual(permissions.Data.Permissions, []string{"order.read"}) || !reflect.DeepEqual(permissions.Data.Roles, []string{"reader"}) || permissions.RequestID != "permissions-1" {
		t.Fatalf("permissions=%+v", permissions)
	}
	for _, key := range []string{"order.read", "order.unknown"} {
		check, err := c.CheckCurrentPermission(ctx, token.AccessToken, key)
		if err != nil {
			t.Fatal(err)
		}
		if check.Data.Allowed != (key == "order.read") || check.RequestID != "check-1" {
			t.Fatalf("check=%+v", check)
		}
	}
	if err := c.RevokeToken(ctx, RevokeTokenParams{Token: "unknown-token", TokenTypeHint: "access_token"}); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 6 {
		t.Fatalf("requests=%d", requests.Load())
	}
}

func TestAPIErrors(t *testing.T) {
	cases := []struct {
		status int
		code   ErrorCode
	}{
		{400, ErrorInvalidRequest}, {400, ErrorInvalidScope}, {400, ErrorInvalidGrant}, {400, ErrorUnsupportedGrantType},
		{401, ErrorInvalidClient}, {401, ErrorInvalidToken}, {401, ErrorLoginRequired},
		{403, ErrorHTTPSRequired}, {403, ErrorIPNotAllowed}, {403, ErrorInsufficientScope},
		{429, ErrorRateLimitExceeded}, {503, ErrorTemporarilyUnavailable}, {500, "future_error"},
	}
	for _, tc := range cases {
		t.Run(string(tc.code), func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("X-Request-ID", "header-id")
				w.Header().Set("Retry-After", "60")
				w.Header().Set("WWW-Authenticate", `Bearer realm="OpenAPI"`)
				w.WriteHeader(tc.status)
				fmt.Fprintf(w, `{"error":%q,"request_id":"body-id"}`, tc.code)
			}))
			defer server.Close()
			_, err := clientForServer(t, server).GetCurrentUser(context.Background(), testToken)
			var apiErr *APIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("err=%v", err)
			}
			if apiErr.StatusCode != tc.status || apiErr.Code != tc.code || apiErr.RequestID != "body-id" || apiErr.RetryAfter != "60" || apiErr.WWWAuthenticate != `Bearer realm="OpenAPI"` {
				t.Fatalf("error=%+v", apiErr)
			}
			if !strings.Contains(err.Error(), string(tc.code)) || errors.Unwrap(apiErr) != nil {
				t.Fatal(err)
			}
			if calls.Load() != 1 {
				t.Fatal("request was retried")
			}
		})
	}
}

func TestMalformedErrorResponses(t *testing.T) {
	for _, body := range []string{"<html>proxy error secret</html>", "null", `{}`, `{"error":"invalid_token","request_id":7}`, `{"error":"<script>secret</script>"}`, `{"error":"invalid_token"} {}`} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Request-ID", "proxy-id")
			w.WriteHeader(502)
			io.WriteString(w, body)
		}))
		c := clientForServer(t, server)
		_, err := c.GetCurrentUser(context.Background(), testToken)
		server.Close()
		var apiErr *APIError
		if !errors.As(err, &apiErr) || apiErr.StatusCode != 502 || apiErr.Code != "" || apiErr.RequestID != "proxy-id" || apiErr.Error() != "auth: HTTP 502" {
			t.Fatalf("error=%v", err)
		}
	}
}

func TestInvalidSuccessResponses(t *testing.T) {
	cases := []struct{ name, body, contentType, operation string }{
		{"empty", "", "application/json", "profile"},
		{"HTML", "<html>secret</html>", "text/html", "profile"},
		{"missing content type", `{}`, "", "profile"},
		{"null", "null", "application/json", "profile"},
		{"missing data", `{"request_id":"x"}`, "application/json", "profile"},
		{"null data", `{"data":null,"request_id":"x"}`, "application/json", "profile"},
		{"missing request id", `{"data":{"id":1}}`, "application/json", "profile"},
		{"wrong ID type", `{"data":{"id":"secret"},"request_id":"x"}`, "application/json", "profile"},
		{"missing ID", `{"data":{},"request_id":"x"}`, "application/json", "profile"},
		{"trailing JSON", `{"data":{"id":1},"request_id":"x"} {}`, "application/json", "profile"},
		{"missing app", `{"data":{"user_id":1},"request_id":"x"}`, "application/json", "permissions"},
		{"missing decision", `{"data":{},"request_id":"x"}`, "application/json", "check"},
		{"null decision", `{"data":{"allowed":null},"request_id":"x"}`, "application/json", "check"},
		{"bad decision", `{"data":{"allowed":"true"},"request_id":"x"}`, "application/json", "check"},
		{"invalid token", `{"access_token":"secret","token_type":"Bearer","expires_in":900,"scope":"profile:read"}`, "application/json", "token"},
		{"null token", "null", "application/json", "token"},
		{"bad revoke", `{"error":"secret"}`, "application/json", "revoke"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header()["Content-Type"] = []string{tc.contentType}
				io.WriteString(w, tc.body)
			}))
			defer server.Close()
			c := clientForServer(t, server)
			ctx := context.Background()
			var err error
			switch tc.operation {
			case "profile":
				_, err = c.GetCurrentUser(ctx, testToken)
			case "permissions":
				_, err = c.GetCurrentPermissions(ctx, testToken)
			case "check":
				_, err = c.CheckCurrentPermission(ctx, testToken, "order.read")
			case "token":
				_, err = c.ExchangeCode(ctx, ExchangeCodeParams{Code: testCode, RedirectURI: testRedirect, CodeVerifier: testVerifier})
			case "revoke":
				err = c.RevokeToken(ctx, RevokeTokenParams{Token: testToken})
			}
			if !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("err=%v", err)
			}
			if strings.Contains(err.Error(), "secret") {
				t.Fatal("response body leaked")
			}
		})
	}
}

func TestOptionalProfileFields(t *testing.T) {
	for _, extra := range []string{"", `,"hire_date":null,"hire_date_source":"","departments":null`} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"data":{"id":1,"username":"u","name":"n","avatar":""%s},"request_id":"r"}`, extra)
		}))
		profile, err := clientForServer(t, server).GetCurrentUser(context.Background(), testToken)
		server.Close()
		if err != nil {
			t.Fatal(err)
		}
		if profile.Data.HireDate != nil || profile.Data.HireDateSource != "" || profile.Data.Departments != nil {
			t.Fatal("expected unknown profile fields")
		}
	}
}

func TestRedirectsNeverForwardCredentials(t *testing.T) {
	for _, status := range []int{301, 302, 303, 307, 308} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			var forwarded atomic.Int32
			destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { forwarded.Add(1) }))
			defer destination.Close()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, destination.URL, status) }))
			defer server.Close()
			c := clientForServer(t, server)
			_, err := c.ExchangeCode(context.Background(), ExchangeCodeParams{Code: testCode, RedirectURI: testRedirect, CodeVerifier: testVerifier})
			var apiErr *APIError
			if !errors.As(err, &apiErr) || apiErr.StatusCode != status {
				t.Fatalf("err=%v", err)
			}
			if forwarded.Load() != 0 {
				t.Fatal("credentials forwarded")
			}
		})
	}
}

func TestResponseLimit(t *testing.T) {
	for _, status := range []int{200, 500} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
			io.WriteString(w, strings.Repeat("x", 65))
		}))
		c := clientForServer(t, server)
		c.maxResponseBytes = 64
		_, err := c.GetCurrentUser(context.Background(), testToken)
		server.Close()
		if !errors.Is(err, ErrResponseTooLarge) {
			t.Fatal(err)
		}
		if status != 200 {
			var apiErr *APIError
			if !errors.As(err, &apiErr) || apiErr.StatusCode != 500 {
				t.Fatal(err)
			}
		}
	}
}

func TestCancellationAndTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer server.Close()
	c := clientForServer(t, server)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.GetCurrentUser(ctx, testToken); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := c.GetCurrentUser(ctx, testToken); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	c.httpClient.Timeout = 20 * time.Millisecond
	if _, err := c.GetCurrentUser(context.Background(), testToken); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
}

type failingBody struct{ closed bool }

var errRead = errors.New("read failed")

func (*failingBody) Read([]byte) (int, error) { return 0, errRead }
func (b *failingBody) Close() error           { b.closed = true; return nil }

func TestTransportAndBodyErrors(t *testing.T) {
	c := newTestClient(t)
	transportErr := errors.New("network unavailable")
	c.httpClient.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, transportErr })
	if _, err := c.GetCurrentUser(context.Background(), testToken); !errors.Is(err, transportErr) {
		t.Fatal(err)
	}
	for _, status := range []int{200, 503} {
		body := &failingBody{}
		c.httpClient.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: status, Header: make(http.Header), Body: body}, nil
		})
		_, err := c.GetCurrentUser(context.Background(), testToken)
		if !errors.Is(err, errRead) || !body.closed {
			t.Fatalf("error=%v, body closed=%t", err, body.closed)
		}
	}
}

func TestClientConcurrentUsers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"data":{"id":1,"username":"u","name":"n","avatar":""},"request_id":"r"}`)
		if len(r.Header.Values("Authorization")) != 1 || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer oat_") {
			t.Error("invalid authorization")
		}
	}))
	defer server.Close()
	c := clientForServer(t, server)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			token := fmt.Sprintf("oat_%043d", i)
			if _, err := c.GetCurrentUser(context.Background(), token); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
}
