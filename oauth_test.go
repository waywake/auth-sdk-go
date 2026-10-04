package auth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
)

const (
	testSecret        = "oas_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"
	testCode          = "oac_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"
	testToken         = "oat_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"
	testMachineToken  = "oam_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"
	testRefreshToken  = "oar_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"
	testVerifier      = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	testChallenge     = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	testState         = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"
	testRedirect      = "https://app.example.com/callback?next=%2Forders&tag=a%20b"
	testMiniProgramID = "wx0123456789abcdef"
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
		a, err := c.NewAuthorization(AuthorizeParams{
			RedirectURI: testRedirect, Scopes: []Scope{ScopeProfileRead, ScopePermissionsCheck},
		})
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
	// The caller's own PKCE material belongs to AuthorizeURL, not here.
	for _, change := range []func(*AuthorizeParams){
		func(p *AuthorizeParams) { p.State = testState },
		func(p *AuthorizeParams) { p.CodeChallenge = testChallenge },
	} {
		params := AuthorizeParams{RedirectURI: testRedirect, Scopes: []Scope{ScopeProfileRead}}
		change(&params)
		if _, err := c.NewAuthorization(params); !errors.Is(err, ErrInvalidArgument) {
			t.Fatal("accepted caller-supplied transaction material")
		}
	}
	if _, err := c.NewAuthorization(AuthorizeParams{RedirectURI: "http://app.example.com/cb", Scopes: []Scope{ScopeProfileRead}}); !errors.Is(err, ErrInvalidArgument) {
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

	// The optional OIDC parameters, including the max_age=0 form that forces a
	// fresh login rather than being indistinguishable from an absent value.
	maxAge := int64(0)
	got, err = c.AuthorizeURL(AuthorizeParams{
		RedirectURI: testRedirect, Scopes: []Scope{ScopeOpenID, ScopeProfile},
		State: testState, CodeChallenge: testChallenge, Nonce: "n-0S6_WzA2Mj", MaxAge: &maxAge, Prompt: PromptLogin,
	})
	if err != nil {
		t.Fatal(err)
	}
	u, _ = url.Parse(got)
	if u.Query().Get("nonce") != "n-0S6_WzA2Mj" || u.Query().Get("max_age") != "0" || u.Query().Get("prompt") != "login" ||
		u.Query().Get("scope") != "openid profile" {
		t.Fatalf("query=%v", u.Query())
	}
	if strings.Contains(got, "response_mode") {
		t.Fatal("the SDK never requests another response mode")
	}

	cases := map[string]func(*AuthorizeParams){
		"no redirect":       func(p *AuthorizeParams) { p.RedirectURI = "" },
		"HTTP redirect":     func(p *AuthorizeParams) { p.RedirectURI = "http://app.example.com/cb" },
		"fragment":          func(p *AuthorizeParams) { p.RedirectURI = "https://app.example.com/cb#" },
		"userinfo":          func(p *AuthorizeParams) { p.RedirectURI = "https://user:secret@app.example.com/cb" },
		"unicode":           func(p *AuthorizeParams) { p.RedirectURI = "https://app.example.com/回调" },
		"space":             func(p *AuthorizeParams) { p.RedirectURI = "https://app.example.com/a b" },
		"backslash":         func(p *AuthorizeParams) { p.RedirectURI = `https://app.example.com/a\b` },
		"malformed URL":     func(p *AuthorizeParams) { p.RedirectURI = "https://app.example.com/%" },
		"reserved code":     func(p *AuthorizeParams) { p.RedirectURI = "https://app.example.com/cb?%63ode=" },
		"reserved state":    func(p *AuthorizeParams) { p.RedirectURI = "https://app.example.com/cb?state=x" },
		"reserved error":    func(p *AuthorizeParams) { p.RedirectURI = "https://app.example.com/cb?error=x" },
		"invalid query":     func(p *AuthorizeParams) { p.RedirectURI = "https://app.example.com/cb?a=%" },
		"long redirect":     func(p *AuthorizeParams) { p.RedirectURI = "https://app.example.com/" + strings.Repeat("a", 2048) },
		"short state":       func(p *AuthorizeParams) { p.State = strings.Repeat("a", 31) },
		"long state":        func(p *AuthorizeParams) { p.State = strings.Repeat("a", 513) },
		"state newline":     func(p *AuthorizeParams) { p.State = testState + "\n" },
		"empty scopes":      func(p *AuthorizeParams) { p.Scopes = nil },
		"unknown scope":     func(p *AuthorizeParams) { p.Scopes = []Scope{"admin"} },
		"machine scope":     func(p *AuthorizeParams) { p.Scopes = []Scope{ScopeDirectoryRead} },
		"mixed scopes":      func(p *AuthorizeParams) { p.Scopes = []Scope{ScopeProfileRead, ScopeEventsRead} },
		"invalid challenge": func(p *AuthorizeParams) { p.CodeChallenge = "plain" },
		"long nonce":        func(p *AuthorizeParams) { p.Nonce = strings.Repeat("n", 129) },
		"nonce newline":     func(p *AuthorizeParams) { p.Nonce = "nonce\n" },
		"negative max age":  func(p *AuthorizeParams) { age := int64(-1); p.MaxAge = &age },
		"large max age":     func(p *AuthorizeParams) { age := int64(MaximumMaxAge + 1); p.MaxAge = &age },
		"unknown prompt":    func(p *AuthorizeParams) { p.Prompt = "consent" },
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
	got, err = c.AuthorizeURL(AuthorizeParams{
		RedirectURI: testRedirect, Scopes: []Scope{ScopeProfileRead, ScopeProfileRead},
		State: testState, CodeChallenge: testChallenge,
	})
	if err != nil {
		t.Fatal(err)
	}
	u, _ = url.Parse(got)
	if u.Query().Get("scope") != "profile:read" {
		t.Fatal("scopes were not deduplicated")
	}
	if _, err := c.AuthorizeURL(AuthorizeParams{
		RedirectURI: testRedirect, Scopes: UserScopeVocabulary(), State: testState, CodeChallenge: testChallenge,
	}); err != nil {
		t.Fatal("the whole employee vocabulary must be requestable")
	}
	// The employee vocabulary is exactly the size the server accepts, so a
	// repeated scope collapses instead of overflowing the bound.
	got, err = c.AuthorizeURL(AuthorizeParams{
		RedirectURI: testRedirect, Scopes: append(UserScopeVocabulary(), ScopeProfileRead),
		State: testState, CodeChallenge: testChallenge,
	})
	if err != nil {
		t.Fatal(err)
	}
	u, _ = url.Parse(got)
	if strings.Count(u.Query().Get("scope"), "profile:read") != 1 {
		t.Fatalf("scope=%q", u.Query().Get("scope"))
	}
}

func TestAuthorizePost(t *testing.T) {
	c := newTestClient(t)
	endpoint, form, err := c.AuthorizePost(AuthorizeParams{
		RedirectURI: testRedirect, Scopes: []Scope{ScopeProfileRead}, State: testState, CodeChallenge: testChallenge,
	})
	if err != nil {
		t.Fatal(err)
	}
	if endpoint != "https://auth.example.com/openapi/v1/oauth/authorize" {
		t.Fatal(endpoint)
	}
	want := url.Values{
		"response_type": {"code"}, "client_id": {"42"}, "redirect_uri": {testRedirect},
		"scope": {"profile:read"}, "state": {testState},
		"code_challenge": {testChallenge}, "code_challenge_method": {"S256"},
	}
	if !reflect.DeepEqual(form, want) {
		t.Fatalf("form=%v, want=%v", form, want)
	}
	if _, _, err := c.AuthorizePost(AuthorizeParams{RedirectURI: testRedirect, Scopes: nil, State: testState, CodeChallenge: testChallenge}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatal(err)
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

func TestTokenGrantsOverHTTP(t *testing.T) {
	type recorded struct {
		basic bool
		form  url.Values
	}
	var (
		mu   sync.Mutex
		seen []recorded
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		_, _, basic := r.BasicAuth()
		mu.Lock()
		seen = append(seen, recorded{basic: basic, form: r.PostForm})
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.PostForm.Get("grant_type") == string(GrantClientCredentials) {
			fmt.Fprintf(w, `{"access_token":%q,"token_type":"Bearer","expires_in":86400,"scope":"directory:read iam:read"}`, testMachineToken)
			return
		}
		fmt.Fprintf(w, `{"access_token":%q,"token_type":"Bearer","expires_in":86400,"scope":"profile:read","refresh_token":%q,"id_token":"header.payload.signature"}`, testToken, testRefreshToken)
	}))
	defer server.Close()
	c := clientForServer(t, server)
	ctx := context.Background()

	token, err := c.ExchangeCode(ctx, ExchangeCodeParams{Code: testCode, RedirectURI: testRedirect, CodeVerifier: testVerifier})
	if err != nil {
		t.Fatal(err)
	}
	if token.AccessToken != testToken || token.RefreshToken != testRefreshToken || token.IDToken == "" || token.Machine() {
		t.Fatalf("token=%+v", token)
	}
	if !reflect.DeepEqual(token.Scopes(), []Scope{ScopeProfileRead}) {
		t.Fatal("scope list")
	}
	if _, err := c.Refresh(ctx, RefreshParams{RefreshToken: testRefreshToken}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Refresh(ctx, RefreshParams{RefreshToken: testRefreshToken, Scopes: []Scope{ScopeProfileRead}}); err != nil {
		t.Fatal(err)
	}
	machine, err := c.ClientCredentials(ctx, ClientCredentialsParams{Scopes: []Scope{ScopeDirectoryRead, ScopeIAMRead}})
	if err != nil {
		t.Fatal(err)
	}
	if !machine.Machine() || machine.AccessToken != testMachineToken {
		t.Fatalf("token=%+v", machine)
	}
	mini, err := c.ExchangeMiniProgramCode(ctx, MiniProgramParams{
		MiniProgramAppID: testMiniProgramID, WeComCode: "code-1", Scopes: []Scope{ScopeProfileRead, ScopePermissionsCheck},
	})
	if err != nil {
		t.Fatal(err)
	}
	if mini.Machine() {
		t.Fatal("the mini-program grant issues an employee token")
	}

	mu.Lock()
	forms := append([]recorded(nil), seen...)
	mu.Unlock()
	want := []url.Values{
		{"grant_type": {"authorization_code"}, "code": {testCode}, "redirect_uri": {testRedirect}, "code_verifier": {testVerifier}},
		{"grant_type": {"refresh_token"}, "refresh_token": {testRefreshToken}},
		{"grant_type": {"refresh_token"}, "refresh_token": {testRefreshToken}, "scope": {"profile:read"}},
		{"grant_type": {"client_credentials"}, "scope": {"directory:read iam:read"}},
		{"grant_type": {string(GrantWeComMiniProgram)}, "mini_program_appid": {testMiniProgramID}, "wecom_code": {"code-1"}, "scope": {"profile:read permissions:check"}},
	}
	if len(forms) != len(want) {
		t.Fatalf("forms=%v", forms)
	}
	for i, entry := range forms {
		if !reflect.DeepEqual(entry.form, want[i]) {
			t.Errorf("form %d=%v, want=%v", i, entry.form, want[i])
		}
		if !entry.basic {
			t.Errorf("request %d did not use HTTP Basic", i)
		}
		if _, ok := entry.form["client_id"]; ok {
			t.Errorf("request %d mixed Basic with form credentials", i)
		}
	}
}

func TestClientSecretPost(t *testing.T) {
	var (
		mu            sync.Mutex
		form          url.Values
		authorization string
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		mu.Lock()
		form, authorization = r.PostForm, r.Header.Get("Authorization")
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":%q,"token_type":"Bearer","expires_in":900,"scope":"profile:read"}`, testToken)
	}))
	defer server.Close()
	c, err := NewClient(Config{
		BaseURL: server.URL, ClientID: 42, ClientSecret: testSecret,
		TokenEndpointAuth: TokenEndpointAuthPost, AllowInsecureHTTP: true, HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ExchangeCode(context.Background(), ExchangeCodeParams{Code: testCode, RedirectURI: testRedirect, CodeVerifier: testVerifier}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	gotForm, gotAuth := form, authorization
	mu.Unlock()
	if gotForm.Get("client_id") != "42" || gotForm.Get("client_secret") != testSecret || gotAuth != "" {
		t.Fatalf("form=%v authorization=%q", gotForm, gotAuth)
	}
	if _, err := NewClient(Config{BaseURL: server.URL, ClientID: 42, TokenEndpointAuth: "client_secret_jwt"}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatal(err)
	}
}

func TestIntrospectAndRevokeOverHTTP(t *testing.T) {
	var (
		mu    sync.Mutex
		forms []url.Values
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id, secret, ok := r.BasicAuth(); !ok || id != "42" || secret != testSecret {
			t.Error("invalid client auth")
		}
		_ = r.ParseForm()
		mu.Lock()
		forms = append(forms, r.PostForm)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case apiPath + "/oauth/introspect":
			if r.PostForm.Get("token") == testMachineToken {
				io.WriteString(w, `{"active":false}`)
				return
			}
			io.WriteString(w, `{"active":true,"exp":1893456000,"sub":"7","client_id":"42","aud":["42"],"username":"alice","scope":"profile:read permissions:check","token_type":"Bearer","subject_kind":"user","future":1}`)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()
	c := clientForServer(t, server)
	ctx := context.Background()

	introspection, err := c.Introspect(ctx, IntrospectParams{Token: testToken, TokenTypeHint: TokenTypeHintAccessToken})
	if err != nil {
		t.Fatal(err)
	}
	if !introspection.Active || introspection.ExpiresAt == nil || *introspection.ExpiresAt != 1893456000 ||
		introspection.SubjectKind != SubjectKindUser || introspection.Subject != "7" ||
		!reflect.DeepEqual(introspection.Scopes(), []Scope{ScopeProfileRead, ScopePermissionsCheck}) {
		t.Fatalf("introspection=%+v", introspection)
	}
	inactive, err := c.Introspect(ctx, IntrospectParams{Token: testMachineToken})
	if err != nil {
		t.Fatal(err)
	}
	if inactive.Active || inactive.ExpiresAt != nil || inactive.Subject != "" {
		t.Fatalf("inactive introspection leaked details: %+v", inactive)
	}
	if err := c.RevokeToken(ctx, RevokeTokenParams{Token: testRefreshToken, TokenTypeHint: TokenTypeHintRefreshToken}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	recorded := append([]url.Values(nil), forms...)
	mu.Unlock()
	if want := (url.Values{"token": {testToken}, "token_type_hint": {"access_token"}}); !reflect.DeepEqual(recorded[0], want) {
		t.Fatalf("form=%v", recorded[0])
	}
	if want := (url.Values{"token": {testMachineToken}}); !reflect.DeepEqual(recorded[1], want) {
		t.Fatalf("form=%v", recorded[1])
	}
	if want := (url.Values{"token": {testRefreshToken}, "token_type_hint": {"refresh_token"}}); !reflect.DeepEqual(recorded[2], want) {
		t.Fatalf("form=%v", recorded[2])
	}
}

func TestLogoutURL(t *testing.T) {
	c := newTestClient(t)
	target, err := c.LogoutURL(LogoutParams{
		IDTokenHint: "header.payload.signature", PostLogoutRedirectURI: testRedirect, State: testState,
	})
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	if u.Path != "/openapi/v1/oauth/logout" || u.Query().Get("id_token_hint") != "header.payload.signature" ||
		u.Query().Get("post_logout_redirect_uri") != testRedirect || u.Query().Get("state") != testState {
		t.Fatal(target)
	}
	if strings.Contains(target, testSecret) {
		t.Fatal("secret material in the logout URL")
	}
	minimal, err := c.LogoutURL(LogoutParams{IDTokenHint: "header.payload.signature"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(minimal, "post_logout_redirect_uri") || strings.Contains(minimal, "state=") {
		t.Fatal(minimal)
	}
	for _, params := range []LogoutParams{
		{},
		{IDTokenHint: "not-a-token"},
		{IDTokenHint: "a.b.c", PostLogoutRedirectURI: "http://app.example.com/after"},
		{IDTokenHint: "a.b.c", State: strings.Repeat("s", 513)},
	} {
		if _, err := c.LogoutURL(params); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("accepted %+v", params)
		}
	}
}

func TestInvalidRequestInput(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()
	good := ExchangeCodeParams{Code: testCode, RedirectURI: testRedirect, CodeVerifier: testVerifier}
	for _, change := range []func(*ExchangeCodeParams){
		func(p *ExchangeCodeParams) { p.Code = "old-code" },
		func(p *ExchangeCodeParams) { p.Code = testToken },
		func(p *ExchangeCodeParams) { p.RedirectURI = "http://app.example.com/cb" },
		func(p *ExchangeCodeParams) { p.CodeVerifier = "short" },
	} {
		p := good
		change(&p)
		if _, err := c.ExchangeCode(ctx, p); !errors.Is(err, ErrInvalidArgument) {
			t.Fatal(err)
		}
	}
	for _, p := range []RevokeTokenParams{{}, {Token: strings.Repeat("x", 8193)}, {Token: "x", TokenTypeHint: TokenTypeHint(strings.Repeat("x", 8193))}} {
		if err := c.RevokeToken(ctx, p); !errors.Is(err, ErrInvalidArgument) {
			t.Fatal(err)
		}
	}
	for _, p := range []IntrospectParams{{}, {Token: "x", TokenTypeHint: "id_token"}} {
		if _, err := c.Introspect(ctx, p); !errors.Is(err, ErrInvalidArgument) {
			t.Fatal(err)
		}
	}
	for _, p := range []RefreshParams{{}, {RefreshToken: testToken}, {RefreshToken: testRefreshToken, Scopes: []Scope{ScopeDirectoryRead}}} {
		if _, err := c.Refresh(ctx, p); !errors.Is(err, ErrInvalidArgument) {
			t.Fatal(err)
		}
	}
	for _, scopes := range [][]Scope{nil, {}, MachineScopeVocabulary()[0:0], {ScopeProfileRead, ScopeDirectoryRead}} {
		if _, err := c.ClientCredentials(ctx, ClientCredentialsParams{Scopes: scopes}); !errors.Is(err, ErrInvalidArgument) {
			t.Fatal(err)
		}
	}
	for _, params := range []MiniProgramParams{
		{},
		{MiniProgramAppID: "wx0123456789ABCDEF", WeComCode: "c", Scopes: []Scope{ScopeProfileRead}},
		{MiniProgramAppID: testMiniProgramID, WeComCode: "", Scopes: []Scope{ScopeProfileRead}},
		{MiniProgramAppID: testMiniProgramID, WeComCode: "c", Scopes: nil},
		{MiniProgramAppID: testMiniProgramID, WeComCode: "c", Scopes: []Scope{ScopeOpenID}},
		{MiniProgramAppID: testMiniProgramID, WeComCode: "c", Scopes: []Scope{ScopeDirectoryRead}},
	} {
		if _, err := c.ExchangeMiniProgramCode(ctx, params); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("accepted %+v", params)
		}
	}
	for _, permission := range []string{"", strings.Repeat("x", 129), string([]byte{0xff})} {
		if _, err := c.CheckCurrentPermission(ctx, testToken, permission); !errors.Is(err, ErrInvalidArgument) {
			t.Fatal(err)
		}
	}
	if _, err := c.CheckCurrentPermissions(ctx, testToken); !errors.Is(err, ErrInvalidArgument) {
		t.Fatal(err)
	}
	tooMany := make([]string, MaxBatchChecks+1)
	for i := range tooMany {
		tooMany[i] = "order.read"
	}
	if _, err := c.CheckCurrentPermissions(ctx, testToken, tooMany...); !errors.Is(err, ErrInvalidArgument) {
		t.Fatal(err)
	}
	if _, err := c.GetCurrentUser(ctx, "legacy-token"); !errors.Is(err, ErrInvalidArgument) {
		t.Fatal(err)
	}
	if _, err := c.GetCurrentUser(ctx, testMachineToken); !errors.Is(err, ErrInvalidArgument) {
		t.Fatal("an employee resource accepted a machine token")
	}
	if _, err := c.GetMachineIdentity(ctx, testToken); !errors.Is(err, ErrInvalidArgument) {
		t.Fatal("a machine resource accepted an employee token")
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
	if _, err := c.Introspect(ctx, IntrospectParams{Token: testToken}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatal(err)
	}
}

func TestInvalidTokenResponses(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		machine bool
	}{
		{"employee token for a machine grant", `{"access_token":"` + testToken + `","token_type":"Bearer","expires_in":900,"scope":"directory:read"}`, true},
		{"machine token for an employee grant", `{"access_token":"` + testMachineToken + `","token_type":"Bearer","expires_in":900,"scope":"profile:read"}`, false},
		{"foreign token", `{"access_token":"secret","token_type":"Bearer","expires_in":900,"scope":"profile:read"}`, false},
		{"wrong token type", `{"access_token":"` + testToken + `","token_type":"mac","expires_in":900,"scope":"profile:read"}`, false},
		{"no expiry", `{"access_token":"` + testToken + `","token_type":"Bearer","expires_in":0,"scope":"profile:read"}`, false},
		{"no scope", `{"access_token":"` + testToken + `","token_type":"Bearer","expires_in":900,"scope":""}`, false},
		{"bad refresh token", `{"access_token":"` + testToken + `","token_type":"Bearer","expires_in":900,"scope":"profile:read","refresh_token":"oar_short"}`, false},
		{"bad ID token", `{"access_token":"` + testToken + `","token_type":"Bearer","expires_in":900,"scope":"profile:read","id_token":"not-a-jws"}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				io.WriteString(w, tc.body)
			}))
			defer server.Close()
			c := clientForServer(t, server)
			var err error
			if tc.machine {
				_, err = c.ClientCredentials(context.Background(), ClientCredentialsParams{Scopes: []Scope{ScopeDirectoryRead}})
			} else {
				_, err = c.ExchangeCode(context.Background(), ExchangeCodeParams{Code: testCode, RedirectURI: testRedirect, CodeVerifier: testVerifier})
			}
			if !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("err=%v", err)
			}
			if strings.Contains(err.Error(), "secret") {
				t.Fatal("response body leaked")
			}
		})
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"active":true}`)
	}))
	defer server.Close()
	if _, err := clientForServer(t, server).Introspect(context.Background(), IntrospectParams{Token: testToken}); !errors.Is(err, ErrInvalidResponse) {
		t.Fatal("an active credential without an expiry was accepted")
	}
}

func TestClientCredentialsExpandedMachineScopes(t *testing.T) {
	scopes := MachineScopeVocabulary()
	c, m := jsonMock(t, `{"access_token":"`+testMachineToken+`","token_type":"Bearer","expires_in":86400,"scope":"`+joinScopeList(scopes)+`"}`)
	token, err := c.ClientCredentials(context.Background(), ClientCredentialsParams{Scopes: scopes})
	if err != nil {
		t.Fatal(err)
	}
	request := m.only(t)
	form, err := url.ParseQuery(request.body)
	if err != nil {
		t.Fatal(err)
	}
	want := "directory:read leave:read iam:read iam:write events:read audit:read stores:read stores:delivery:read stores:members:read"
	if form.Get("scope") != want || token.Scope != want {
		t.Fatalf("scope request=%q response=%q", form.Get("scope"), token.Scope)
	}
	for _, scope := range []Scope{ScopeLeaveRead, ScopeStoresRead, ScopeStoresDeliveryRead, ScopeStoresMembersRead} {
		t.Run(string(scope), func(t *testing.T) {
			if _, err := c.AuthorizeURL(AuthorizeParams{RedirectURI: testRedirect, Scopes: []Scope{scope}, State: testState, CodeChallenge: testChallenge}); !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("machine scope accepted in employee authorization: %v", err)
			}
			if _, err := c.Refresh(context.Background(), RefreshParams{RefreshToken: testRefreshToken, Scopes: []Scope{scope}}); !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("machine scope accepted in employee refresh: %v", err)
			}
		})
	}
	if len(m.requests()) != 1 {
		t.Fatal("invalid employee requests reached the server")
	}
}
