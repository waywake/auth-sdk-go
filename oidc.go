package auth

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// Discovery reads the issuer's OIDC discovery document. It needs no
// credential: a client fetches it with nothing but the issuer URL, and it may
// be cached for DiscoveryCacheSeconds. The document's issuer is the same string
// an ID Token states as `iss`.
func (c *Client) Discovery(ctx context.Context) (*OpenIDConfiguration, error) {
	var document OpenIDConfiguration
	if err := c.do(ctx, request{method: http.MethodGet, path: discoveryPath, root: true}, &document); err != nil {
		return nil, err
	}
	if document.Issuer == "" || document.TokenEndpoint == "" || document.JWKSURI == "" {
		return nil, invalidResponse("incomplete discovery document")
	}
	return &document, nil
}

// JSONWebKeySet reads the public keys an ID Token or a logout token is verified
// against. The document may be cached for DiscoveryCacheSeconds. An
// installation with no signing keyring answers 503 rather than an empty list.
func (c *Client) JSONWebKeySet(ctx context.Context) (*JSONWebKeySet, error) {
	var keys JSONWebKeySet
	if err := c.do(ctx, request{method: http.MethodGet, path: jwksPath}, &keys); err != nil {
		return nil, err
	}
	if len(keys.Keys) == 0 {
		return nil, invalidResponse("empty JSON Web Key Set")
	}
	return &keys, nil
}

// GetUserInfo reads the subject the presented employee token stands for. The
// standard answer is a bare object rather than this API's data envelope, and
// `sub` is the same decimal employee identifier the ID Token states.
//
// Name, preferred_username and picture require ScopeProfile or ScopeProfileRead;
// email requires ScopeEmail.
func (c *Client) GetUserInfo(ctx context.Context, accessToken string) (*UserInfo, error) {
	var info UserInfo
	if err := c.do(ctx, request{
		method: http.MethodGet, path: "/userinfo", cred: credentialUserToken, token: accessToken,
	}, &info); err != nil {
		return nil, err
	}
	if info.Subject == "" {
		return nil, invalidResponse("missing userinfo subject")
	}
	return &info, nil
}

// IDTokenParams binds an ID Token to the deployment and application that must
// have issued it. Issuer and ClientID are required.
type IDTokenParams struct {
	// Issuer is the deployment's public Base URL. It is compared character by
	// character; no prefix or case-insensitive match is accepted.
	Issuer string
	// ClientID is the application the token's audience must name.
	ClientID int64
	// Nonce is the nonce the authorization request carried. When it is set, the
	// token's nonce must equal it exactly. An empty value means the request
	// carried none and the claim is not checked.
	Nonce string
	// Now overrides the verification instant. Zero selects time.Now().
	Now time.Time
	// ClockSkew tolerates small clock differences when checking exp and iat. A
	// zero value compares the instants exactly, so a relying party whose clock
	// is not synchronized with the deployment should set it.
	ClockSkew time.Duration
}

// LogoutTokenParams binds a back-channel logout token to the deployment and
// application that must have issued it.
type LogoutTokenParams struct {
	Issuer   string
	ClientID int64
	// Now overrides the verification instant. Zero selects time.Now().
	Now time.Time
	// ClockSkew is the accepted distance between the token's issued-at and Now.
	// Zero or less selects DefaultWebhookTolerance, because a logout token is
	// delivered over the same at-least-once webhook machinery and its window
	// must not be zero-width.
	ClockSkew time.Duration
}

func (p IDTokenParams) now() time.Time {
	if p.Now.IsZero() {
		return time.Now()
	}
	return p.Now
}

// VerifyIDToken verifies the RS256 signature of a compact ID Token against the
// published key set and then its issuer, audience, lifetime and nonce. It never
// takes a key from the token itself.
//
// An unknown `kid` is reported as ErrUnknownKey: refetch the key set once and
// retry rather than accepting another key, because a rotation publishes the new
// key while the old one is still being handed out.
func (ks *JSONWebKeySet) VerifyIDToken(raw string, params IDTokenParams) (*IDTokenClaims, error) {
	if params.Issuer == "" || params.ClientID <= 0 {
		return nil, invalid("Issuer/ClientID", "are required to verify an ID Token")
	}
	payload, err := ks.verifySignature(raw)
	if err != nil {
		return nil, err
	}
	var claims IDTokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, verification("malformed ID Token claims")
	}
	if claims.Issuer != params.Issuer {
		return nil, verification("unexpected issuer")
	}
	if !claims.Audience.Contains(params.ClientID) {
		return nil, verification("unexpected audience")
	}
	if claims.Subject == "" {
		return nil, verification("missing subject")
	}
	if claims.ExpiresAt == 0 || claims.IssuedAt == 0 {
		return nil, verification("missing expiry or issued-at")
	}
	now, skew := params.now(), params.ClockSkew
	if !now.Before(time.Unix(claims.ExpiresAt, 0).Add(skew)) {
		return nil, verification("expired ID Token")
	}
	if time.Unix(claims.IssuedAt, 0).Add(-skew).After(now) {
		return nil, verification("ID Token issued in the future")
	}
	if params.Nonce != "" && claims.Nonce != params.Nonce {
		return nil, verification("nonce mismatch")
	}
	return &claims, nil
}

// VerifyLogoutToken verifies one OIDC back-channel logout token: signature,
// issuer, audience, freshness, the back-channel logout event, and the absence
// of a nonce. Delivery is at least once, so the same jti can arrive repeatedly
// and the caller must deduplicate on it rather than treat it as an error.
//
// A logout token states who was logged out and nothing else. It is not an
// authentication response, which is why a nonce in it is rejected outright.
func (ks *JSONWebKeySet) VerifyLogoutToken(raw string, params LogoutTokenParams) (*LogoutTokenClaims, error) {
	if params.Issuer == "" || params.ClientID <= 0 {
		return nil, invalid("Issuer/ClientID", "are required to verify a logout token")
	}
	payload, err := ks.verifySignature(raw)
	if err != nil {
		return nil, err
	}
	var claims LogoutTokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, verification("malformed logout token claims")
	}
	if claims.Issuer != params.Issuer {
		return nil, verification("unexpected issuer")
	}
	if !claims.Audience.Contains(params.ClientID) {
		return nil, verification("unexpected audience")
	}
	if claims.Subject == "" || claims.TokenID == "" || claims.IssuedAt == 0 {
		return nil, verification("incomplete logout token claims")
	}
	if claims.Nonce != nil {
		return nil, verification("logout token carries a nonce")
	}
	if !claims.LoggedOutEvent() {
		return nil, verification("missing back-channel logout event")
	}
	now, skew := params.Now, params.ClockSkew
	if now.IsZero() {
		now = time.Now()
	}
	if skew <= 0 {
		skew = DefaultWebhookTolerance
	}
	if drift := now.Sub(time.Unix(claims.IssuedAt, 0)); drift > skew || drift < -skew {
		return nil, verification("logout token outside the accepted window")
	}
	return &claims, nil
}

// verifySignature checks the compact JWS against the key named by its `kid` and
// returns the raw payload segment.
func (ks *JSONWebKeySet) verifySignature(raw string) ([]byte, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, verification("not a compact JWS")
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, verification("malformed JWS header")
	}
	var fields struct {
		Algorithm string `json:"alg"`
		KeyID     string `json:"kid"`
	}
	if err := json.Unmarshal(header, &fields); err != nil {
		return nil, verification("malformed JWS header")
	}
	if fields.Algorithm != "RS256" {
		return nil, verification("unsupported signing algorithm")
	}
	if ks == nil {
		return nil, verification("no JSON Web Key Set")
	}
	var signing *JSONWebKey
	for i := range ks.Keys {
		if ks.Keys[i].KeyID == fields.KeyID && fields.KeyID != "" {
			signing = &ks.Keys[i]
			break
		}
	}
	if signing == nil {
		return nil, fmt.Errorf("%w: %w", ErrUnknownKey, verification("unknown kid "+fields.KeyID))
	}
	public, err := signing.publicKey()
	if err != nil {
		return nil, err
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, verification("malformed JWS signature")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(public, crypto.SHA256, digest[:], signature); err != nil {
		return nil, verification("invalid signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, verification("malformed JWS payload")
	}
	return payload, nil
}

func (k JSONWebKey) publicKey() (*rsa.PublicKey, error) {
	if k.KeyType != "" && k.KeyType != "RSA" {
		return nil, verification("unsupported key type")
	}
	if k.Algorithm != "" && k.Algorithm != "RS256" {
		return nil, verification("unsupported key algorithm")
	}
	modulus, err := base64.RawURLEncoding.DecodeString(k.Modulus)
	if err != nil || len(modulus) == 0 {
		return nil, verification("malformed key modulus")
	}
	exponent, err := base64.RawURLEncoding.DecodeString(k.Exponent)
	if err != nil || len(exponent) == 0 || len(exponent) > 4 {
		return nil, verification("malformed key exponent")
	}
	value := new(big.Int).SetBytes(exponent)
	if !value.IsInt64() || value.Int64() < 3 || value.Int64() > 1<<31-1 {
		return nil, verification("unsupported key exponent")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: int(value.Int64())}, nil
}
