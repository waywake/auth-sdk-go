package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"
)

const discoveryBody = `{"issuer":"https://auth.example.com","authorization_endpoint":"https://auth.example.com/openapi/v1/oauth/authorize","token_endpoint":"https://auth.example.com/openapi/v1/oauth/token","userinfo_endpoint":"https://auth.example.com/openapi/v1/userinfo","end_session_endpoint":"https://auth.example.com/openapi/v1/oauth/logout","jwks_uri":"https://auth.example.com/openapi/v1/.well-known/jwks.json","scopes_supported":["profile:read","permissions:read","permissions:check","openid","profile","email"],"claims_supported":["iss","sub"],"response_types_supported":["code"],"response_modes_supported":["query"],"grant_types_supported":["authorization_code","refresh_token"],"code_challenge_methods_supported":["S256"],"id_token_signing_alg_values_supported":["RS256"],"subject_types_supported":["public"],"token_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post"]}`

func TestDiscoveryAndJWKSRequests(t *testing.T) {
	c, m := jsonMock(t, discoveryBody)
	document, err := c.Discovery(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	request := m.only(t)
	if request.method != http.MethodGet || request.path != discoveryPath || request.token != "" {
		t.Fatalf("the discovery document needs no credential: %+v", request)
	}
	if document.Issuer != "https://auth.example.com" || document.JWKSURI != "https://auth.example.com/openapi/v1/.well-known/jwks.json" ||
		document.EndSessionEndpoint == "" || len(document.ScopesSupported) != 6 {
		t.Fatalf("document=%+v", document)
	}

	c, m = jsonMock(t, `{"keys":[{"kty":"RSA","use":"sig","alg":"RS256","kid":"k1","n":"AQAB","e":"AQAB"}]}`)
	keys, err := c.JSONWebKeySet(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	request = m.only(t)
	if request.path != apiPath+jwksPath || request.token != "" {
		t.Fatalf("the key document needs no credential: %+v", request)
	}
	if len(keys.Keys) != 1 || keys.Keys[0].KeyID != "k1" || keys.Keys[0].Modulus != "AQAB" {
		t.Fatalf("keys=%+v", keys)
	}
}

func TestInvalidOIDCDocuments(t *testing.T) {
	c, _ := jsonMock(t, `{"issuer":"","token_endpoint":"","jwks_uri":""}`)
	if _, err := c.Discovery(context.Background()); !errors.Is(err, ErrInvalidResponse) {
		t.Fatal("accepted an incomplete discovery document")
	}
	// An installation without a signing keyring answers 503 rather than an
	// empty list, so an empty list is a contract violation.
	c, _ = jsonMock(t, `{"keys":[]}`)
	if _, err := c.JSONWebKeySet(context.Background()); !errors.Is(err, ErrInvalidResponse) {
		t.Fatal("accepted an empty key set")
	}
	c, _ = errorMock(t, 503, ErrorTemporarilyUnavailable)
	_, err := c.JSONWebKeySet(context.Background())
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != 503 || apiErr.Code != ErrorTemporarilyUnavailable {
		t.Fatalf("err=%v", err)
	}
}

func TestGetUserInfoRequest(t *testing.T) {
	c, m := jsonMock(t, `{"sub":"7","name":"Alice","preferred_username":"alice","picture":"https://img.example.com/a.png","email":"alice@example.com","email_verified":false}`)
	info, err := c.GetUserInfo(context.Background(), testToken)
	if err != nil {
		t.Fatal(err)
	}
	request := m.only(t)
	if request.method != http.MethodGet || request.path != apiPath+"/userinfo" || request.token != bearer(testToken) {
		t.Fatalf("request=%+v", request)
	}
	if info.Subject != "7" || info.Name != "Alice" || info.PreferredUsername != "alice" || info.Email != "alice@example.com" ||
		info.EmailVerified == nil || *info.EmailVerified {
		t.Fatalf("userinfo=%+v", info)
	}

	// A token without the profile or email scopes answers a subject and nothing
	// else: the absent claims stay empty rather than becoming empty strings.
	c, _ = jsonMock(t, `{"sub":"7"}`)
	info, err = c.GetUserInfo(context.Background(), testToken)
	if err != nil {
		t.Fatal(err)
	}
	if info.Subject != "7" || info.Name != "" || info.Email != "" || info.EmailVerified != nil {
		t.Fatalf("userinfo=%+v", info)
	}
	c, _ = jsonMock(t, `{"name":"Alice"}`)
	if _, err := c.GetUserInfo(context.Background(), testToken); !errors.Is(err, ErrInvalidResponse) {
		t.Fatal("accepted a userinfo answer without a subject")
	}
}

// The verification tests sign with a generated key so the signature, issuer,
// audience and freshness checks are exercised for real.
type signingKey struct {
	key  *rsa.PrivateKey
	kid  string
	jwks *JSONWebKeySet
}

func newSigningKey(t *testing.T, kid string) signingKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	encode := func(value *big.Int) string { return base64.RawURLEncoding.EncodeToString(value.Bytes()) }
	exponent := big.NewInt(int64(key.PublicKey.E))
	return signingKey{
		key: key, kid: kid,
		jwks: &JSONWebKeySet{Keys: []JSONWebKey{{
			KeyType: "RSA", Use: "sig", Algorithm: "RS256", KeyID: kid,
			Modulus: encode(key.PublicKey.N), Exponent: encode(exponent),
		}}},
	}
}

// sign builds a compact JWS over the claims with the given header overrides.
func (s signingKey) sign(t *testing.T, claims map[string]any, header map[string]any) string {
	t.Helper()
	if header == nil {
		header = map[string]any{"alg": "RS256", "typ": "JWT", "kid": s.kid}
	}
	encode := func(value any) string {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(data)
	}
	signing := encode(header) + "." + encode(claims)
	digest := sha256.Sum256([]byte(signing))
	signature, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func idTokenClaims(now time.Time) map[string]any {
	return map[string]any{
		"iss": "https://auth.example.com", "sub": "7", "aud": "42",
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "auth_time": now.Add(-time.Minute).Unix(),
		"nonce": "n-0S6_WzA2Mj", "sid": testToken,
	}
}

func TestVerifyIDToken(t *testing.T) {
	now := time.Date(2026, 9, 30, 10, 0, 0, 0, time.UTC)
	signing := newSigningKey(t, "k1")
	raw := signing.sign(t, idTokenClaims(now), nil)
	params := IDTokenParams{Issuer: "https://auth.example.com", ClientID: 42, Nonce: "n-0S6_WzA2Mj", Now: now}

	claims, err := signing.jwks.VerifyIDToken(raw, params)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "7" || !claims.Audience.Contains(42) || claims.AuthTime == 0 || claims.SessionID != testToken ||
		claims.ExpiresAt != now.Add(time.Hour).Unix() {
		t.Fatalf("claims=%+v", claims)
	}

	// An audience encoded as an array is equally valid.
	arrayAudience := idTokenClaims(now)
	arrayAudience["aud"] = []string{"42"}
	if _, err := signing.jwks.VerifyIDToken(signing.sign(t, arrayAudience, nil), params); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name   string
		claims map[string]any
		header map[string]any
		params IDTokenParams
		want   error
	}{
		{"wrong issuer", map[string]any{"iss": "https://other.example.com"}, nil, params, nil},
		{"wrong audience", map[string]any{"aud": "43"}, nil, params, nil},
		{"missing subject", map[string]any{"sub": ""}, nil, params, nil},
		{"expired", map[string]any{"exp": now.Add(-time.Second).Unix()}, nil, params, nil},
		{"issued in the future", map[string]any{"iat": now.Add(time.Hour).Unix()}, nil, params, nil},
		{"nonce mismatch", map[string]any{"nonce": "other"}, nil, params, nil},
		{"missing expiry", map[string]any{"exp": 0}, nil, params, nil},
		{"unsigned algorithm", nil, map[string]any{"alg": "none", "kid": "k1"}, params, nil},
		{"unknown key", nil, map[string]any{"alg": "RS256", "kid": "rotated"}, params, ErrUnknownKey},
		{"no key identifier", nil, map[string]any{"alg": "RS256"}, params, ErrUnknownKey},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims := idTokenClaims(now)
			for key, value := range tc.claims {
				claims[key] = value
			}
			_, err := signing.jwks.VerifyIDToken(signing.sign(t, claims, tc.header), tc.params)
			if !errors.Is(err, ErrTokenVerification) {
				t.Fatalf("err=%v", err)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("err=%v, want %v", err, tc.want)
			}
		})
	}

	// A tampered payload keeps the original signature and must be refused.
	parts := strings.Split(raw, ".")
	tampered := parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"https://auth.example.com","sub":"8","aud":"42"}`)) + "." + parts[2]
	if _, err := signing.jwks.VerifyIDToken(tampered, params); !errors.Is(err, ErrTokenVerification) {
		t.Fatal("a tampered payload was accepted")
	}
	if _, err := signing.jwks.VerifyIDToken("not-a-jws", params); !errors.Is(err, ErrTokenVerification) {
		t.Fatal("a non-JWS was accepted")
	}
	if _, err := signing.jwks.VerifyIDToken(raw, IDTokenParams{ClientID: 42}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatal("verification without an issuer was attempted")
	}
	// A nonce is only checked when the caller names one: an authorization that
	// carried none has nothing to compare.
	if _, err := signing.jwks.VerifyIDToken(raw, IDTokenParams{Issuer: params.Issuer, ClientID: 42, Now: now}); err != nil {
		t.Fatal(err)
	}
	// Clock tolerance is applied to exp and iat.
	skewed := IDTokenParams{Issuer: params.Issuer, ClientID: 42, Now: now.Add(2 * time.Hour), ClockSkew: 3 * time.Hour}
	if _, err := signing.jwks.VerifyIDToken(raw, skewed); err != nil {
		t.Fatal(err)
	}
	// A key the document does not publish is never taken from the token.
	if _, err := (&JSONWebKeySet{}).VerifyIDToken(raw, params); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("err=%v", err)
	}
}

func logoutClaims(now time.Time) map[string]any {
	return map[string]any{
		"iss": "https://auth.example.com", "sub": "7", "aud": "42", "iat": now.Unix(), "jti": "logout-1",
		"sid":    testToken,
		"events": map[string]any{BackChannelLogoutEvent: map[string]any{}},
	}
}

func TestVerifyLogoutToken(t *testing.T) {
	now := time.Date(2026, 9, 30, 10, 0, 0, 0, time.UTC)
	signing := newSigningKey(t, "k1")
	params := LogoutTokenParams{Issuer: "https://auth.example.com", ClientID: 42, Now: now, ClockSkew: DefaultWebhookTolerance}
	raw := signing.sign(t, logoutClaims(now), nil)

	claims, err := signing.jwks.VerifyLogoutToken(raw, params)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "7" || claims.TokenID != "logout-1" || claims.SessionID != testToken || !claims.LoggedOutEvent() {
		t.Fatalf("claims=%+v", claims)
	}
	// Redelivery is normal, so the same token verifies again and the receiver
	// deduplicates on jti.
	if _, err := signing.jwks.VerifyLogoutToken(raw, params); err != nil {
		t.Fatal("a redelivered logout token was refused")
	}
	// A zero ClockSkew selects the webhook tolerance rather than a zero-width
	// window, so a token issued half a minute ago is still accepted.
	issued := logoutClaims(now.Add(-30 * time.Second))
	if _, err := signing.jwks.VerifyLogoutToken(signing.sign(t, issued, nil), LogoutTokenParams{
		Issuer: params.Issuer, ClientID: 42, Now: now,
	}); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name   string
		claims map[string]any
	}{
		{"nonce present", map[string]any{"nonce": "forbidden"}},
		{"missing events", map[string]any{"events": map[string]any{}}},
		{"foreign issuer", map[string]any{"iss": "https://other.example.com"}},
		{"foreign audience", map[string]any{"aud": "43"}},
		{"missing token id", map[string]any{"jti": ""}},
		{"missing subject", map[string]any{"sub": ""}},
		{"stale", map[string]any{"iat": now.Add(-time.Hour).Unix()}},
		{"future", map[string]any{"iat": now.Add(time.Hour).Unix()}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims := logoutClaims(now)
			for key, value := range tc.claims {
				claims[key] = value
			}
			if _, err := signing.jwks.VerifyLogoutToken(signing.sign(t, claims, nil), params); !errors.Is(err, ErrTokenVerification) {
				t.Fatalf("err=%v", err)
			}
		})
	}
	if _, err := signing.jwks.VerifyLogoutToken(raw, LogoutTokenParams{Issuer: params.Issuer}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatal("verification without an audience was attempted")
	}
	// A logout token that carries a nonce is rejected even when the value looks
	// harmless: the claim itself is forbidden.
	withNonce := logoutClaims(now)
	withNonce["nonce"] = "anything"
	if _, err := signing.jwks.VerifyLogoutToken(signing.sign(t, withNonce, nil), params); !errors.Is(err, ErrTokenVerification) {
		t.Fatal("a logout token with a nonce was accepted")
	}
}

func TestUnsupportedKeyParameters(t *testing.T) {
	now := time.Date(2026, 9, 30, 10, 0, 0, 0, time.UTC)
	signing := newSigningKey(t, "k1")
	raw := signing.sign(t, idTokenClaims(now), nil)
	params := IDTokenParams{Issuer: "https://auth.example.com", ClientID: 42, Now: now}
	for name, mutate := range map[string]func(*JSONWebKey){
		"unsupported key type":      func(k *JSONWebKey) { k.KeyType = "EC" },
		"unsupported key algorithm": func(k *JSONWebKey) { k.Algorithm = "RS512" },
		"malformed modulus":         func(k *JSONWebKey) { k.Modulus = "!!" },
		"unsupported exponent":      func(k *JSONWebKey) { k.Exponent = base64.RawURLEncoding.EncodeToString([]byte{0, 0, 0, 1, 0}) },
		"missing exponent":          func(k *JSONWebKey) { k.Exponent = "" },
		"truncated key modulus":     func(k *JSONWebKey) { k.Modulus = base64.RawURLEncoding.EncodeToString([]byte{1, 2, 3}) },
	} {
		t.Run(name, func(t *testing.T) {
			keys := &JSONWebKeySet{Keys: append([]JSONWebKey(nil), signing.jwks.Keys...)}
			mutate(&keys.Keys[0])
			if _, err := keys.VerifyIDToken(raw, params); !errors.Is(err, ErrTokenVerification) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}
