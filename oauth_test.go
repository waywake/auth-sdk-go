package auth

import (
	"context"
	"errors"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

const (
	testSecret    = "oas_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"
	testCode      = "oac_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"
	testToken     = "oat_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"
	testVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	testChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	testState     = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"
	testRedirect  = "https://app.example.com/callback?next=%2Forders&tag=a%20b"
)

func newTestClient(t *testing.T) *Client {
	t.Helper()
	c, err := NewClient(Config{BaseURL: "https://auth.example.com", ClientID: 42, ClientSecret: testSecret})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCodeChallengeRFC7636Vector(t *testing.T) {
	got, err := CodeChallenge(testVerifier)
	if err != nil || got != testChallenge {
		t.Fatalf("challenge=%q, err=%v", got, err)
	}
	for _, value := range []string{"", strings.Repeat("a", 42), strings.Repeat("a", 129), strings.Repeat("a", 42) + "+", strings.Repeat("a", 42) + "="} {
		if _, err := CodeChallenge(value); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("invalid verifier accepted")
		}
	}
	for _, value := range []string{strings.Repeat("a", 43), strings.Repeat("~", 128), strings.Repeat("._-~", 20)} {
		if _, err := CodeChallenge(value); err != nil {
			t.Fatal(err)
		}
	}
}

func TestGenerateAuthorization(t *testing.T) {
	c := newTestClient(t)
	seen := make(map[string]bool)
	for i := 0; i < 32; i++ {
		a, err := c.NewAuthorization(testRedirect, ScopeProfileRead, ScopePermissionsCheck)
		if err != nil {
			t.Fatal(err)
		}
		if !digestPattern.MatchString(a.State) || !verifierPattern.MatchString(a.CodeVerifier) {
			t.Fatal("invalid random material")
		}
		if seen[a.State] || seen[a.CodeVerifier] || a.State == a.CodeVerifier {
			t.Fatal("reused random material")
		}
		seen[a.State], seen[a.CodeVerifier] = true, true
		u, err := url.Parse(a.URL)
		if err != nil {
			t.Fatal(err)
		}
		challenge, _ := CodeChallenge(a.CodeVerifier)
		if u.Query().Get("code_challenge") != challenge || u.Query().Get("state") != a.State || a.RedirectURI != testRedirect {
			t.Fatal("transaction does not match its URL")
		}
	}
	if _, err := c.NewAuthorization("http://app.example.com/cb", ScopeProfileRead); !errors.Is(err, ErrInvalidArgument) {
		t.Fatal(err)
	}
}

func TestAuthorizeURL(t *testing.T) {
	c := newTestClient(t)
	got, err := c.AuthorizeURL(AuthorizeParams{
		RedirectURI: testRedirect, Scopes: []Scope{ScopeProfileRead, ScopePermissionsRead, ScopePermissionsCheck},
		State: testState, CodeChallenge: testChallenge,
	})
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "https" || u.Host != "auth.example.com" || u.Path != "/openapi/v1/oauth/authorize" {
		t.Fatal(got)
	}
	want := url.Values{
		"response_type": {"code"}, "client_id": {"42"}, "redirect_uri": {testRedirect},
		"scope": {"profile:read permissions:read permissions:check"}, "state": {testState},
		"code_challenge": {testChallenge}, "code_challenge_method": {"S256"},
	}
	if !reflect.DeepEqual(u.Query(), want) {
		t.Fatalf("query=%v, want=%v", u.Query(), want)
	}
	if strings.Contains(got, testSecret) || strings.Contains(got, testVerifier) {
		t.Fatal("secret material in authorization URL")
	}

	cases := map[string]func(*AuthorizeParams){
		"no redirect":    func(p *AuthorizeParams) { p.RedirectURI = "" },
		"HTTP redirect":  func(p *AuthorizeParams) { p.RedirectURI = "http://app.example.com/cb" },
		"fragment":       func(p *AuthorizeParams) { p.RedirectURI = "https://app.example.com/cb#" },
		"userinfo":       func(p *AuthorizeParams) { p.RedirectURI = "https://user:secret@app.example.com/cb" },
		"unicode":        func(p *AuthorizeParams) { p.RedirectURI = "https://app.example.com/回调" },
		"space":          func(p *AuthorizeParams) { p.RedirectURI = "https://app.example.com/a b" },
		"backslash":      func(p *AuthorizeParams) { p.RedirectURI = `https://app.example.com/a\b` },
		"malformed URL":  func(p *AuthorizeParams) { p.RedirectURI = "https://app.example.com/%" },
		"reserved code":  func(p *AuthorizeParams) { p.RedirectURI = "https://app.example.com/cb?%63ode=" },
		"reserved state": func(p *AuthorizeParams) { p.RedirectURI = "https://app.example.com/cb?state=x" },
		"reserved error": func(p *AuthorizeParams) { p.RedirectURI = "https://app.example.com/cb?error=x" },
		"invalid query":  func(p *AuthorizeParams) { p.RedirectURI = "https://app.example.com/cb?a=%" },
		"long redirect":  func(p *AuthorizeParams) { p.RedirectURI = "https://app.example.com/" + strings.Repeat("a", 2048) },
		"short state":    func(p *AuthorizeParams) { p.State = strings.Repeat("a", 31) },
		"long state":     func(p *AuthorizeParams) { p.State = strings.Repeat("a", 513) },
		"state newline":  func(p *AuthorizeParams) { p.State = testState + "\n" },
		"empty scopes":   func(p *AuthorizeParams) { p.Scopes = nil },
		"unknown scope":  func(p *AuthorizeParams) { p.Scopes = []Scope{"admin"} },
		"too many scopes": func(p *AuthorizeParams) {
			p.Scopes = []Scope{ScopeProfileRead, ScopeProfileRead, ScopeProfileRead, ScopeProfileRead}
		},
		"invalid challenge": func(p *AuthorizeParams) { p.CodeChallenge = "plain" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			p := AuthorizeParams{RedirectURI: testRedirect, Scopes: []Scope{ScopeProfileRead}, State: testState, CodeChallenge: testChallenge}
			change(&p)
			if _, err := c.AuthorizeURL(p); !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("err=%v", err)
			}
		})
	}
	got, err = c.AuthorizeURL(AuthorizeParams{RedirectURI: testRedirect, Scopes: []Scope{ScopeProfileRead, ScopeProfileRead}, State: testState, CodeChallenge: testChallenge})
	if err != nil {
		t.Fatal(err)
	}
	u, _ = url.Parse(got)
	if u.Query().Get("scope") != "profile:read" {
		t.Fatal("scopes were not deduplicated")
	}
}

func TestVerifyState(t *testing.T) {
	for _, value := range []string{testState, strings.Repeat("x", 32), strings.Repeat("x", 512)} {
		if err := VerifyState(value, value); err != nil {
			t.Fatal(err)
		}
	}
	for _, pair := range [][2]string{{"", ""}, {"short", "short"}, {testState, ""}, {testState, testState + "x"}, {testState, strings.Repeat("x", len(testState))}, {testState + "\r", testState + "\r"}, {strings.Repeat("x", 513), strings.Repeat("x", 513)}} {
		if !errors.Is(VerifyState(pair[0], pair[1]), ErrStateMismatch) {
			t.Fatal("invalid state accepted")
		}
	}
}

func TestInvalidRequestInput(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()
	good := ExchangeCodeParams{Code: testCode, RedirectURI: testRedirect, CodeVerifier: testVerifier}
	for _, change := range []func(*ExchangeCodeParams){
		func(p *ExchangeCodeParams) { p.Code = "old-code" },
		func(p *ExchangeCodeParams) { p.RedirectURI = "http://app.example.com/cb" },
		func(p *ExchangeCodeParams) { p.CodeVerifier = "short" },
	} {
		p := good
		change(&p)
		if _, err := c.ExchangeCode(ctx, p); !errors.Is(err, ErrInvalidArgument) {
			t.Fatal(err)
		}
	}
	for _, p := range []RevokeTokenParams{{}, {Token: strings.Repeat("x", 8193)}, {Token: "x", TokenTypeHint: strings.Repeat("x", 8193)}} {
		if err := c.RevokeToken(ctx, p); !errors.Is(err, ErrInvalidArgument) {
			t.Fatal(err)
		}
	}
	for _, permission := range []string{"", strings.Repeat("x", 129), string([]byte{0xff})} {
		if _, err := c.CheckCurrentPermission(ctx, testToken, permission); !errors.Is(err, ErrInvalidArgument) {
			t.Fatal(err)
		}
	}
	if _, err := c.GetCurrentUser(ctx, "legacy-token"); !errors.Is(err, ErrInvalidArgument) {
		t.Fatal(err)
	}
	if _, err := c.GetCurrentUser(nil, testToken); !errors.Is(err, ErrInvalidArgument) {
		t.Fatal(err)
	}
	c.clientSecret = ""
	if _, err := c.ExchangeCode(ctx, good); !errors.Is(err, ErrInvalidArgument) {
		t.Fatal(err)
	}
	if err := c.RevokeToken(ctx, RevokeTokenParams{Token: testToken}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatal(err)
	}
}
