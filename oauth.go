package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

var (
	verifierPattern   = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)
	digestPattern     = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	miniProgramIDExpr = regexp.MustCompile(`^wx[0-9a-f]{16}$`)
)

// MaximumMaxAge is the largest OIDC max_age the authorization endpoint accepts.
const MaximumMaxAge int64 = 30 * 24 * 60 * 60

// MaximumNonceLength is the largest OIDC nonce the authorization endpoint
// accepts.
const MaximumNonceLength = 128

func validCredential(value, prefix string) bool {
	return strings.HasPrefix(value, prefix) && digestPattern.MatchString(strings.TrimPrefix(value, prefix))
}

// GenerateState generates a URL-safe OAuth state using 32 random bytes.
func GenerateState() (string, error) { return randomValue() }

// GenerateCodeVerifier generates an RFC 7636 verifier using 32 random bytes.
func GenerateCodeVerifier() (string, error) { return randomValue() }

func randomValue() (string, error) {
	var value [32]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("auth: generate random value: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(value[:]), nil
}

// CodeChallenge derives a mandatory S256 challenge from a valid PKCE verifier.
func CodeChallenge(verifier string) (string, error) {
	if !verifierPattern.MatchString(verifier) {
		return "", invalid("code verifier", "must contain 43–128 RFC 7636 unreserved characters")
	}
	digest := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(digest[:]), nil
}

func validState(value string) bool {
	return len(value) >= 32 && len(value) <= 512 && !strings.ContainsAny(value, "\r\n")
}

// VerifyState compares the expected browser-bound state and callback state in
// constant time after hashing. It rejects missing/invalid state even if equal.
// The caller must also atomically consume the stored transaction to stop replay.
func VerifyState(expected, received string) error {
	if !validState(expected) || !validState(received) {
		return ErrStateMismatch
	}
	a, b := sha256.Sum256([]byte(expected)), sha256.Sum256([]byte(received))
	if subtle.ConstantTimeCompare(a[:], b[:]) != 1 {
		return ErrStateMismatch
	}
	return nil
}

func validateRedirectURI(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || len(raw) > maxRedirectURI || u.Scheme != "https" || u.Hostname() == "" ||
		u.User != nil || u.Opaque != "" || strings.ContainsAny(raw, "#\\") {
		return invalid("RedirectURI", "must be an absolute HTTPS callback without credentials or fragment")
	}
	for _, ch := range raw {
		if ch < 33 || ch > 126 {
			return invalid("RedirectURI", "must use ASCII with percent-encoded paths")
		}
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil || q.Has("code") || q.Has("state") || q.Has("error") {
		return invalid("RedirectURI", "must not contain malformed queries or reserved code/state/error parameters")
	}
	return nil
}

// AuthorizeParams are the parameters of one browser authorization request.
// RedirectURI, Scopes, State and CodeChallenge are required by AuthorizeURL;
// NewAuthorization generates the state and the S256 PKCE material itself.
type AuthorizeParams struct {
	// RedirectURI must exactly match a registered callback, including its
	// encoding.
	RedirectURI string
	// Scopes must be one to six employee scopes. The application must have been
	// granted each of them.
	Scopes []Scope
	// State is the browser-bound anti-forgery value: 32 to 512 bytes without
	// CR/LF.
	State string
	// CodeChallenge is the 43-character S256 digest of the request's verifier.
	CodeChallenge string
	// Nonce is the optional OIDC nonce echoed into the ID Token when ScopeOpenID
	// is requested. At most 128 characters.
	Nonce string
	// MaxAge is the optional OIDC max_age in seconds (0 to 2592000): only a
	// browser login at most this old may be reused. A zero value forces a fresh
	// interactive authentication for this exact request, which is why it is a
	// pointer rather than a plain number.
	MaxAge *int64
	// Prompt is the optional OIDC prompt. Empty, PromptLogin and PromptNone are
	// the entire closed vocabulary.
	Prompt Prompt
}

func (p AuthorizeParams) values() (url.Values, error) {
	if err := validateRedirectURI(p.RedirectURI); err != nil {
		return nil, err
	}
	if !validState(p.State) {
		return nil, invalid("State", "must contain 32–512 bytes and no CR/LF")
	}
	if !digestPattern.MatchString(p.CodeChallenge) {
		return nil, invalid("CodeChallenge", "must be a 43-character S256 digest")
	}
	scopes, err := validateScopes(p.Scopes, false)
	if err != nil {
		return nil, err
	}
	if len(scopes) == 0 || len(scopes) > 6 {
		return nil, invalid("Scopes", "must contain one to six employee scopes")
	}
	if len(p.Nonce) > MaximumNonceLength || strings.ContainsAny(p.Nonce, "\r\n") {
		return nil, invalid("Nonce", "must be at most 128 characters and contain no CR/LF")
	}
	if p.MaxAge != nil && (*p.MaxAge < 0 || *p.MaxAge > MaximumMaxAge) {
		return nil, invalid("MaxAge", "must be between 0 and 2592000 seconds")
	}
	switch p.Prompt {
	case "", PromptLogin, PromptNone:
	default:
		return nil, invalid("Prompt", "must be empty, login or none")
	}
	values := url.Values{
		"response_type": {"code"}, "redirect_uri": {p.RedirectURI}, "scope": {joinScopeList(scopes)},
		"state": {p.State}, "code_challenge": {p.CodeChallenge},
		"code_challenge_method": {"S256"},
	}
	if p.Nonce != "" {
		values.Set("nonce", p.Nonce)
	}
	if p.MaxAge != nil {
		values.Set("max_age", fmt.Sprint(*p.MaxAge))
	}
	if p.Prompt != "" {
		values.Set("prompt", string(p.Prompt))
	}
	return values, nil
}

// AuthorizeURL builds the URL to which the user's browser must be redirected.
// It does not perform an HTTP request or carry the application's secret.
func (c *Client) AuthorizeURL(params AuthorizeParams) (string, error) {
	values, err := params.values()
	if err != nil {
		return "", err
	}
	query := make(url.Values, len(values))
	for key, entries := range values {
		query.Set(key, entries[0])
	}
	query.Set("client_id", c.clientID)
	return c.baseURL + apiPath + "/oauth/authorize?" + query.Encode(), nil
}

// AuthorizePost returns the authorization endpoint and the form a backend posts
// to start the same flow without a redirect. The server answers 303 to the
// equivalent GET request; it issues no grant itself.
func (c *Client) AuthorizePost(params AuthorizeParams) (string, url.Values, error) {
	values, err := params.values()
	if err != nil {
		return "", nil, err
	}
	values.Set("client_id", c.clientID)
	return c.baseURL + apiPath + "/oauth/authorize", values, nil
}

// Authorization is a newly generated login transaction. Store State,
// CodeVerifier and RedirectURI on the backend, bound to the initiating browser
// with a short expiry. Redirect only URL to the browser.
type Authorization struct {
	URL          string
	State        string
	CodeVerifier string
	RedirectURI  string
}

// NewAuthorization creates random state and PKCE material and builds an
// authorization URL. It does not store the transaction or start a browser.
//
// State and CodeChallenge must be left empty: this call owns both so the
// returned CodeVerifier always matches the challenge that was sent. Use
// AuthorizeURL directly to supply your own material.
func (c *Client) NewAuthorization(params AuthorizeParams) (*Authorization, error) {
	if params.State != "" {
		return nil, invalid("State", "is generated by NewAuthorization and must be empty")
	}
	if params.CodeChallenge != "" {
		return nil, invalid("CodeChallenge", "is derived from a generated verifier; use AuthorizeURL to supply your own")
	}
	state, err := GenerateState()
	if err != nil {
		return nil, err
	}
	verifier, err := GenerateCodeVerifier()
	if err != nil {
		return nil, err
	}
	challenge, err := CodeChallenge(verifier)
	if err != nil {
		return nil, err
	}
	params.State, params.CodeChallenge = state, challenge
	authorizeURL, err := c.AuthorizeURL(params)
	if err != nil {
		return nil, err
	}
	return &Authorization{URL: authorizeURL, State: state, CodeVerifier: verifier, RedirectURI: params.RedirectURI}, nil
}

// ExchangeCodeParams binds an authorization code to its original transaction.
type ExchangeCodeParams struct {
	Code         string
	RedirectURI  string
	CodeVerifier string
}

// RefreshParams rotates a refresh token. Scopes may narrow the access token
// this rotation returns; leaving them empty keeps the original authorization.
// The new refresh token always keeps the full original scope.
type RefreshParams struct {
	RefreshToken string
	Scopes       []Scope
}

// ClientCredentialsParams requests a machine token. One to five machine scopes
// are required: an application that was granted no machine scope cannot mint
// one.
type ClientCredentialsParams struct {
	Scopes []Scope
}

// MiniProgramParams exchanges a wx.qy.login code through one of the
// application's registered enterprise mini-program bindings.
type MiniProgramParams struct {
	// MiniProgramAppID is the mini-program AppID, wx followed by 16 lowercase
	// hexadecimal digits, and must match a registered binding.
	MiniProgramAppID string
	// WeComCode is the one-time code returned by wx.qy.login. It is consumed
	// upstream and cannot be retried.
	WeComCode string
	// Scopes must be one to six employee scopes without ScopeOpenID: the
	// mini-program grant issues no ID Token.
	Scopes []Scope
}

func (c *Client) tokenRequest(ctx context.Context, values url.Values, machine bool) (*Token, error) {
	values, cred, err := c.clientForm(values)
	if err != nil {
		return nil, err
	}
	body, err := formBody(values)
	if err != nil {
		return nil, err
	}
	var token Token
	if err := c.do(ctx, request{
		method: http.MethodPost, path: "/oauth/token",
		contentType: formContentType, body: body, cred: cred,
	}, &token); err != nil {
		return nil, err
	}
	if err := validateToken(&token, machine); err != nil {
		return nil, err
	}
	return &token, nil
}

func validateToken(token *Token, machine bool) error {
	prefix := tokenPrefix
	if machine {
		prefix = machineTokenPrefix
	}
	if !validCredential(token.AccessToken, prefix) {
		return invalidResponse("invalid access token shape")
	}
	if token.TokenType != "Bearer" || token.ExpiresIn <= 0 || token.Scope == "" {
		return invalidResponse("invalid OAuth token fields")
	}
	if token.RefreshToken != "" && !validCredential(token.RefreshToken, refreshTokenPrefix) {
		return invalidResponse("invalid refresh token shape")
	}
	if token.IDToken != "" && strings.Count(token.IDToken, ".") != 2 {
		return invalidResponse("invalid ID Token shape")
	}
	return nil
}

// ExchangeCode exchanges a single-use code with the application's client
// credentials. The caller must verify and consume its browser-bound state
// before calling.
func (c *Client) ExchangeCode(ctx context.Context, params ExchangeCodeParams) (*Token, error) {
	if !validCredential(params.Code, codePrefix) {
		return nil, invalid("Code", "must be an OpenAPI authorization code (oac_)")
	}
	if err := validateRedirectURI(params.RedirectURI); err != nil {
		return nil, err
	}
	if !verifierPattern.MatchString(params.CodeVerifier) {
		return nil, invalid("CodeVerifier", "must contain 43–128 RFC 7636 unreserved characters")
	}
	return c.tokenRequest(ctx, url.Values{
		"grant_type": {string(GrantAuthorizationCode)}, "code": {params.Code},
		"redirect_uri": {params.RedirectURI}, "code_verifier": {params.CodeVerifier},
	}, false)
}

// Refresh rotates a refresh token. The returned refresh token must overwrite
// the stored one: the presented token is void the moment this call returns, and
// presenting it again revokes the whole authorization. The access token cannot
// outlive the authorization session's absolute deadline, which no refresh
// extends.
func (c *Client) Refresh(ctx context.Context, params RefreshParams) (*Token, error) {
	if !validCredential(params.RefreshToken, refreshTokenPrefix) {
		return nil, invalid("RefreshToken", "must be an OpenAPI refresh token (oar_)")
	}
	values := url.Values{
		"grant_type": {string(GrantRefreshToken)}, "refresh_token": {params.RefreshToken},
	}
	if len(params.Scopes) > 0 {
		scopes, err := validateScopes(params.Scopes, false)
		if err != nil {
			return nil, err
		}
		if len(scopes) == 0 || len(scopes) > 6 {
			return nil, invalid("Scopes", "must contain at most six employee scopes")
		}
		values.Set("scope", joinScopeList(scopes))
	}
	return c.tokenRequest(ctx, values, false)
}

// ClientCredentials mints a machine token for the calling application itself.
// The scopes are a subset of the application's registered machine scopes.
func (c *Client) ClientCredentials(ctx context.Context, params ClientCredentialsParams) (*Token, error) {
	scopes, err := validateScopes(params.Scopes, true)
	if err != nil {
		return nil, err
	}
	if len(scopes) == 0 || len(scopes) > 5 {
		return nil, invalid("Scopes", "must contain one to five machine scopes")
	}
	return c.tokenRequest(ctx, url.Values{
		"grant_type": {string(GrantClientCredentials)}, "scope": {joinScopeList(scopes)},
	}, true)
}

// ExchangeMiniProgramCode exchanges a wx.qy.login code for the same employee
// identity and IAM authorizations browser login produces. The returned access
// token is an employee token: it is refused on every machine resource.
func (c *Client) ExchangeMiniProgramCode(ctx context.Context, params MiniProgramParams) (*Token, error) {
	if !miniProgramIDExpr.MatchString(params.MiniProgramAppID) {
		return nil, invalid("MiniProgramAppID", "must be wx followed by 16 lowercase hexadecimal digits")
	}
	if params.WeComCode == "" || len(params.WeComCode) > 512 || strings.ContainsAny(params.WeComCode, "\r\n") {
		return nil, invalid("WeComCode", "must contain 1–512 characters and no CR/LF")
	}
	for _, scope := range params.Scopes {
		if scope == ScopeOpenID {
			return nil, invalid("Scopes", "must not contain openid: the mini-program grant issues no ID Token")
		}
	}
	scopes, err := validateScopes(params.Scopes, false)
	if err != nil {
		return nil, err
	}
	if len(scopes) == 0 || len(scopes) > 6 {
		return nil, invalid("Scopes", "must contain one to six employee scopes")
	}
	return c.tokenRequest(ctx, url.Values{
		"grant_type":         {string(GrantWeComMiniProgram)},
		"mini_program_appid": {params.MiniProgramAppID},
		"wecom_code":         {params.WeComCode},
		"scope":              {joinScopeList(scopes)},
	}, false)
}

// RevokeTokenParams identifies a credential to revoke. TokenTypeHint is
// optional. The server returns success for unknown credentials and credentials
// of other applications, so the endpoint cannot be used to probe for live
// tokens.
type RevokeTokenParams struct {
	Token         string
	TokenTypeHint TokenTypeHint
}

// RevokeToken revokes one credential with the application's client credentials.
// Revoking a refresh token atomically ends its authorization session, the whole
// refresh family and the employee's access tokens in this application.
func (c *Client) RevokeToken(ctx context.Context, params RevokeTokenParams) error {
	if params.Token == "" || len(params.Token) > maxTokenBytes || strings.ContainsAny(params.Token, "\r\n") {
		return invalid("Token", "must contain 1–4096 characters and no CR/LF")
	}
	values := url.Values{"token": {params.Token}}
	if err := setTokenTypeHint(values, params.TokenTypeHint); err != nil {
		return err
	}
	values, cred, err := c.clientForm(values)
	if err != nil {
		return err
	}
	body, err := formBody(values)
	if err != nil {
		return err
	}
	return c.do(ctx, request{
		method: http.MethodPost, path: "/oauth/revoke",
		contentType: formContentType, body: body, cred: cred,
	}, nil)
}

// IntrospectParams identifies the credential to report on.
type IntrospectParams struct {
	Token         string
	TokenTypeHint TokenTypeHint
}

// Introspect reports whether a credential is currently usable (RFC 7662). An
// unknown, expired, revoked or foreign credential reports Active false with
// nothing else, so the answer never leaks another application's credentials.
func (c *Client) Introspect(ctx context.Context, params IntrospectParams) (*Introspection, error) {
	if params.Token == "" || len(params.Token) > maxTokenBytes || strings.ContainsAny(params.Token, "\r\n") {
		return nil, invalid("Token", "must contain 1–4096 characters and no CR/LF")
	}
	values := url.Values{"token": {params.Token}}
	if err := setTokenTypeHint(values, params.TokenTypeHint); err != nil {
		return nil, err
	}
	values, cred, err := c.clientForm(values)
	if err != nil {
		return nil, err
	}
	body, err := formBody(values)
	if err != nil {
		return nil, err
	}
	var introspection Introspection
	if err := c.do(ctx, request{
		method: http.MethodPost, path: "/oauth/introspect",
		contentType: formContentType, body: body, cred: cred,
	}, &introspection); err != nil {
		return nil, err
	}
	if introspection.Active && introspection.ExpiresAt == nil {
		return nil, invalidResponse("missing expiry for an active credential")
	}
	return &introspection, nil
}

func setTokenTypeHint(values url.Values, hint TokenTypeHint) error {
	switch hint {
	case "":
		return nil
	case TokenTypeHintAccessToken, TokenTypeHintRefreshToken:
		values.Set("token_type_hint", string(hint))
		return nil
	default:
		return invalid("TokenTypeHint", "must be access_token or refresh_token")
	}
}

// LogoutParams end the browser session a relying party asks to close
// (RP-Initiated Logout). IDTokenHint must be an ID Token this deployment
// issued, and it must name the browser session being ended.
type LogoutParams struct {
	// IDTokenHint is required. Expired hints remain usable when they name the
	// current browser session; a hint without a session identifier is rejected.
	IDTokenHint string
	// PostLogoutRedirectURI is optional and must be registered for this
	// application.
	PostLogoutRedirectURI string
	// State is echoed back on the post-logout target.
	State string
}

// LogoutURL builds the URL the browser is sent to in order to end its session.
// The call needs the original browser's cookie, so it is a browser navigation,
// never a backend request.
func (c *Client) LogoutURL(params LogoutParams) (string, error) {
	if params.IDTokenHint == "" || strings.Count(params.IDTokenHint, ".") != 2 ||
		len(params.IDTokenHint) > maxTokenBytes {
		return "", invalid("IDTokenHint", "must be a compact ID Token this deployment issued")
	}
	query := url.Values{"id_token_hint": {params.IDTokenHint}}
	if params.PostLogoutRedirectURI != "" {
		if err := validateRedirectURI(params.PostLogoutRedirectURI); err != nil {
			return "", err
		}
		query.Set("post_logout_redirect_uri", params.PostLogoutRedirectURI)
	}
	if params.State != "" {
		if len(params.State) > 512 || strings.ContainsAny(params.State, "\r\n") {
			return "", invalid("State", "must contain at most 512 bytes and no CR/LF")
		}
		query.Set("state", params.State)
	}
	return c.baseURL + apiPath + "/oauth/logout?" + query.Encode(), nil
}
