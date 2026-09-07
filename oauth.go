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
	verifierPattern = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)
	digestPattern   = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
)

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
	if err != nil || len(raw) > 2048 || u.Scheme != "https" || u.Hostname() == "" ||
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

// AuthorizeURL builds the URL to which the user's browser must be redirected.
// It does not perform an HTTP request or carry the application's secret.
// RedirectURI must exactly match a registered callback, including its encoding.
func (c *Client) AuthorizeURL(params AuthorizeParams) (string, error) {
	if err := validateRedirectURI(params.RedirectURI); err != nil {
		return "", err
	}
	if !validState(params.State) {
		return "", invalid("State", "must contain 32–512 bytes and no CR/LF")
	}
	if !digestPattern.MatchString(params.CodeChallenge) {
		return "", invalid("CodeChallenge", "must be a 43-character S256 digest")
	}
	if len(params.Scopes) == 0 || len(params.Scopes) > 3 {
		return "", invalid("Scopes", "must contain one to three supported scopes")
	}
	scopes := make([]string, 0, len(params.Scopes))
	seen := make(map[Scope]bool, len(params.Scopes))
	for _, scope := range params.Scopes {
		switch scope {
		case ScopeProfileRead, ScopePermissionsRead, ScopePermissionsCheck:
		default:
			return "", invalid("Scopes", "contains an unsupported scope")
		}
		if !seen[scope] {
			scopes = append(scopes, string(scope))
			seen[scope] = true
		}
	}
	q := url.Values{
		"response_type": {"code"}, "client_id": {c.clientID},
		"redirect_uri": {params.RedirectURI}, "scope": {strings.Join(scopes, " ")},
		"state": {params.State}, "code_challenge": {params.CodeChallenge},
		"code_challenge_method": {"S256"},
	}
	return c.baseURL + apiPath + "/oauth/authorize?" + q.Encode(), nil
}

// NewAuthorization creates random state and PKCE material and builds an
// authorization URL. It does not store the transaction or start a browser.
func (c *Client) NewAuthorization(redirectURI string, scopes ...Scope) (*Authorization, error) {
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
	authorizeURL, err := c.AuthorizeURL(AuthorizeParams{
		RedirectURI: redirectURI, Scopes: scopes, State: state, CodeChallenge: challenge,
	})
	if err != nil {
		return nil, err
	}
	return &Authorization{URL: authorizeURL, State: state, CodeVerifier: verifier, RedirectURI: redirectURI}, nil
}

// ExchangeCode exchanges a single-use code with HTTP Basic client credentials.
// The caller must verify and consume its browser-bound state before calling.
func (c *Client) ExchangeCode(ctx context.Context, params ExchangeCodeParams) (*Token, error) {
	if !validCredential(params.Code, "oac_") {
		return nil, invalid("Code", "must be an OpenAPI authorization code (oac_)")
	}
	if err := validateRedirectURI(params.RedirectURI); err != nil {
		return nil, err
	}
	if !verifierPattern.MatchString(params.CodeVerifier) {
		return nil, invalid("CodeVerifier", "must contain 43–128 RFC 7636 unreserved characters")
	}
	body := url.Values{
		"grant_type": {"authorization_code"}, "code": {params.Code},
		"redirect_uri": {params.RedirectURI}, "code_verifier": {params.CodeVerifier},
	}.Encode()
	if len(body) > 8192 {
		return nil, invalid("form body", "exceeds 8192 bytes")
	}
	var token Token
	if err := c.do(ctx, http.MethodPost, "/oauth/token", "application/x-www-form-urlencoded", body, "", true, &token); err != nil {
		return nil, err
	}
	if !validCredential(token.AccessToken, "oat_") || token.TokenType != "Bearer" || token.ExpiresIn <= 0 || token.Scope == "" {
		return nil, fmt.Errorf("%w: invalid OAuth token fields", ErrInvalidResponse)
	}
	return &token, nil
}

// RevokeToken revokes a token with HTTP Basic client credentials.
func (c *Client) RevokeToken(ctx context.Context, params RevokeTokenParams) error {
	if params.Token == "" {
		return invalid("Token", "must not be empty")
	}
	values := url.Values{"token": {params.Token}}
	if params.TokenTypeHint != "" {
		values.Set("token_type_hint", params.TokenTypeHint)
	}
	body := values.Encode()
	if len(body) > 8192 {
		return invalid("form body", "exceeds 8192 bytes")
	}
	return c.do(ctx, http.MethodPost, "/oauth/revoke", "application/x-www-form-urlencoded", body, "", true, nil)
}
