package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	apiPath        = "/openapi/v1"
	discoveryPath  = "/.well-known/openid-configuration"
	jwksPath       = "/.well-known/jwks.json"
	userAgent      = "waywake-auth-sdk-go/1"
	maxFormBytes   = 8192
	maxJSONBytes   = 65536
	maxRedirectURI = 2048

	// DefaultPageSize is the server's page size when a request omits Limit.
	DefaultPageSize = 50
	// MaxPageSize is the largest page size for numeric-cursor listings.
	// Store listings use MaxStorePageSize instead.
	MaxPageSize = 200
	// MaxBatchChecks is the number of permission questions one batch check may
	// ask.
	MaxBatchChecks = 100
	// MaxEventTypeFilters is the number of repeatable event-type filters one
	// change-stream pull may carry.
	MaxEventTypeFilters = 8
	// MaxAuditUsageDays is the longest audit usage window the server serves.
	MaxAuditUsageDays = 30
	// DefaultAuditUsageDays is the audit usage window when one is not requested.
	DefaultAuditUsageDays = 7
	// DiscoveryCacheSeconds is how long the discovery document and the key set
	// may be cached, as the contract advertises.
	DiscoveryCacheSeconds = 300

	formContentType = "application/x-www-form-urlencoded"
	jsonContentType = "application/json"

	DefaultTimeout                = 15 * time.Second
	DefaultMaxResponseBytes int64 = 4 << 20

	codePrefix         = "oac_"
	tokenPrefix        = "oat_"
	machineTokenPrefix = "oam_"
	refreshTokenPrefix = "oar_"
	secretPrefix       = "oas_"

	maxTokenBytes = 4096
)

// Config configures a Client. BaseURL is the deployment origin, for example
// https://auth.example.com, without /openapi/v1 or any query/fragment.
type Config struct {
	BaseURL  string
	ClientID int64
	// ClientSecret is one of the application's independent oas_ credentials.
	// It is optional for URL-only use and for calls that present a bearer token,
	// and required for the token, revoke and introspect endpoints.
	ClientSecret string
	// TokenEndpointAuth selects how the client authenticates at the token,
	// revoke and introspect endpoints. Empty selects TokenEndpointAuthBasic.
	TokenEndpointAuth TokenEndpointAuth
	// HTTPClient is copied, with redirects disabled and its cookie jar removed.
	// A nil value uses DefaultTimeout. An injected client's timeout is preserved.
	// Its transport must be safe for concurrent use.
	HTTPClient *http.Client
	// AllowInsecureHTTP permits plain HTTP for local development only.
	AllowInsecureHTTP bool
	// MaxResponseBytes bounds memory use; zero selects DefaultMaxResponseBytes.
	MaxResponseBytes int64
}

// Client is an immutable, concurrency-safe OpenAPI client. Construct it with
// NewClient; the zero value is not usable. It never caches user permissions or
// tokens, and does not automatically retry requests.
type Client struct {
	baseURL           string
	clientID          string
	clientSecret      string
	tokenEndpointAuth TokenEndpointAuth
	httpClient        http.Client
	maxResponseBytes  int64
}

func NewClient(config Config) (*Client, error) {
	u, err := url.Parse(config.BaseURL)
	if err != nil || u.Hostname() == "" || u.User != nil || u.Opaque != "" ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery ||
		strings.Contains(config.BaseURL, "#") {
		return nil, invalid("BaseURL", "must be an absolute origin without credentials, path, query or fragment")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && config.AllowInsecureHTTP) {
		return nil, invalid("BaseURL", "must use HTTPS (HTTP requires AllowInsecureHTTP)")
	}
	if config.ClientID < 1 || config.ClientID > 2147483647 {
		return nil, invalid("ClientID", "must be between 1 and 2147483647")
	}
	if config.ClientSecret != "" && !validCredential(config.ClientSecret, secretPrefix) {
		return nil, invalid("ClientSecret", "must be an independent OpenAPI secret (oas_)")
	}
	switch config.TokenEndpointAuth {
	case "", TokenEndpointAuthBasic, TokenEndpointAuthPost:
	default:
		return nil, invalid("TokenEndpointAuth", "must be client_secret_basic or client_secret_post")
	}
	if config.MaxResponseBytes < 0 || config.MaxResponseBytes == 1<<63-1 {
		return nil, invalid("MaxResponseBytes", "must be nonnegative and smaller than MaxInt64")
	}
	limit := config.MaxResponseBytes
	if limit == 0 {
		limit = DefaultMaxResponseBytes
	}
	tokenAuth := config.TokenEndpointAuth
	if tokenAuth == "" {
		tokenAuth = TokenEndpointAuthBasic
	}
	hc := http.Client{Timeout: DefaultTimeout}
	if config.HTTPClient != nil {
		hc = *config.HTTPClient
	}
	// Even a same-host 307/308 can forward a code, verifier or secret-bearing body.
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	hc.Jar = nil
	u.Path, u.RawPath = "", ""
	return &Client{
		baseURL: u.String(), clientID: strconv.FormatInt(config.ClientID, 10),
		clientSecret: config.ClientSecret, tokenEndpointAuth: tokenAuth,
		httpClient: hc, maxResponseBytes: limit,
	}, nil
}

// ClientID returns the application identifier the client authenticates with.
func (c *Client) ClientID() int64 {
	id, _ := strconv.ParseInt(c.clientID, 10, 64)
	return id
}

var errorCodePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// credential selects the authentication one request carries.
type credential int

const (
	// credentialNone sends no credential: the public OIDC documents, and the
	// client_secret_post token family whose credentials travel in the body.
	credentialNone credential = iota
	// credentialBasic sends HTTP Basic APP_ID:OPENAPI_SECRET.
	credentialBasic
	// credentialUserToken sends an employee bearer token (oat_).
	credentialUserToken
	// credentialMachineToken sends a machine bearer token (oam_).
	credentialMachineToken
)

// request is one call of the public OpenAPI.
type request struct {
	method      string
	path        string // Relative to /openapi/v1, or absolute from the origin when root is set.
	root        bool
	query       url.Values
	contentType string
	body        string
	cred        credential
	token       string
}

func (c *Client) do(ctx context.Context, req request, out any) error {
	if ctx == nil {
		return invalid("context", "must not be nil")
	}
	switch req.cred {
	case credentialBasic:
		if c.clientSecret == "" {
			return invalid("ClientSecret", "is required for token exchange, revocation and introspection")
		}
	case credentialUserToken:
		if !validCredential(req.token, tokenPrefix) {
			return invalid("access token", "must be an OpenAPI employee bearer token (oat_)")
		}
	case credentialMachineToken:
		if !validCredential(req.token, machineTokenPrefix) {
			return invalid("machine token", "must be an OpenAPI machine bearer token (oam_)")
		}
	}
	target := c.baseURL + apiPath + req.path
	if req.root {
		target = c.baseURL + req.path
	}
	if len(req.query) != 0 {
		target += "?" + req.query.Encode()
	}
	httpReq, err := http.NewRequestWithContext(ctx, req.method, target, strings.NewReader(req.body))
	if err != nil {
		return fmt.Errorf("auth: create request: %w", err)
	}
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("User-Agent", userAgent)
	if req.contentType != "" {
		httpReq.Header.Set("Content-Type", req.contentType)
	}
	switch req.cred {
	case credentialBasic:
		httpReq.SetBasicAuth(c.clientID, c.clientSecret)
	case credentialUserToken, credentialMachineToken:
		httpReq.Header.Set("Authorization", "Bearer "+req.token)
	}
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("auth: request failed: %w", err)
	}
	defer resp.Body.Close()
	data, readErr := io.ReadAll(io.LimitReader(resp.Body, c.maxResponseBytes+1))
	if int64(len(data)) > c.maxResponseBytes {
		readErr = ErrResponseTooLarge
	}
	if resp.StatusCode != http.StatusOK {
		apiErr := &APIError{
			StatusCode: resp.StatusCode, RequestID: resp.Header.Get("X-Request-ID"),
			RetryAfter: resp.Header.Get("Retry-After"), WWWAuthenticate: resp.Header.Get("WWW-Authenticate"),
			cause: readErr,
		}
		var envelope struct {
			Code      string `json:"error"`
			RequestID string `json:"request_id"`
		}
		if readErr == nil && json.Unmarshal(data, &envelope) == nil && errorCodePattern.MatchString(envelope.Code) {
			apiErr.Code = ErrorCode(envelope.Code)
			if envelope.RequestID != "" {
				apiErr.RequestID = envelope.RequestID
			}
		}
		return apiErr
	}
	if readErr != nil {
		return fmt.Errorf("auth: read response: %w", readErr)
	}
	if out == nil {
		if len(strings.TrimSpace(string(data))) != 0 {
			return invalidResponse("expected an empty revocation response")
		}
		return nil
	}
	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return invalidResponse("expected application/json")
	}
	// Unmarshal rejects trailing JSON documents. Unknown fields remain compatible
	// with additive v1 changes. Never include raw response data in an error.
	if err := json.Unmarshal(data, out); err != nil {
		return invalidResponse("malformed JSON")
	}
	return nil
}

// readResource decodes one `{data, request_id}` resource envelope. A missing or
// null data member, and a missing request_id, are rejected: the server always
// emits both.
func readResource[T any](ctx context.Context, c *Client, req request) (*Response[T], error) {
	var envelope struct {
		Data      *T      `json:"data"`
		RequestID *string `json:"request_id"`
	}
	if err := c.do(ctx, req, &envelope); err != nil {
		return nil, err
	}
	if envelope.Data == nil || envelope.RequestID == nil {
		return nil, invalidResponse("missing data or request_id")
	}
	return &Response[T]{Data: *envelope.Data, RequestID: *envelope.RequestID}, nil
}

// ensureNotNilItems rejects a page whose items member is absent. The server
// always emits an array, so a missing one is a contract violation rather than
// an empty page. An explicitly empty array stays valid and non-nil.
func ensureNotNilItems[T any](items []T) error {
	if items == nil {
		return invalidResponse("missing page items")
	}
	return nil
}

// pageQuery builds the shared after/limit cursor query. A zero value omits the
// parameter, which leaves the server default in place.
func pageQuery(after int64, limit int) (url.Values, error) {
	if after < 0 {
		return nil, invalid("After", "must not be negative")
	}
	if limit < 0 || limit > MaxPageSize {
		return nil, invalid("Limit", "must be between 1 and 200")
	}
	query := url.Values{}
	if after > 0 {
		query.Set("after", strconv.FormatInt(after, 10))
	}
	if limit > 0 {
		query.Set("limit", strconv.Itoa(limit))
	}
	return query, nil
}

func validID(field string, id int64) error {
	if id <= 0 {
		return invalid(field, "must be a positive identifier")
	}
	return nil
}

// jsonBody marshals one request payload, rejecting an oversized body before it
// reaches the network.
func jsonBody(payload any) (string, error) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("auth: encode request: %w", err)
	}
	if len(encoded) > maxJSONBytes {
		return "", invalid("request body", "exceeds 65536 bytes")
	}
	return string(encoded), nil
}

// formBody encodes one form payload under the endpoint's documented bound.
func formBody(values url.Values) (string, error) {
	encoded := values.Encode()
	if len(encoded) > maxFormBytes {
		return "", invalid("form body", "exceeds 8192 bytes")
	}
	return encoded, nil
}

// clientForm adds the client credentials to a form when the configured method
// is client_secret_post. The default method sends them as HTTP Basic instead.
func (c *Client) clientForm(values url.Values) (url.Values, credential, error) {
	if c.clientSecret == "" {
		return nil, credentialNone, invalid("ClientSecret", "is required for token exchange, revocation and introspection")
	}
	switch c.tokenEndpointAuth {
	case TokenEndpointAuthPost:
		values.Set("client_id", c.clientID)
		values.Set("client_secret", c.clientSecret)
		return values, credentialNone, nil
	default:
		return values, credentialBasic, nil
	}
}

// splitFields splits a space-separated list, where an absent or blank value
// yields no entries rather than one empty entry.
func splitFields(raw string) []string { return strings.Fields(raw) }

// validateScopes checks one requested scope list against one vocabulary and
// returns it deduplicated in request order, so the count the caller passes is
// the count the server is asked for.
func validateScopes(scopes []Scope, machine bool) ([]Scope, error) {
	seen := make(map[Scope]bool, len(scopes))
	unique := make([]Scope, 0, len(scopes))
	for _, scope := range scopes {
		if !scope.valid() {
			return nil, invalid("Scopes", "contains an unsupported scope")
		}
		if scope.Machine() != machine {
			return nil, invalid("Scopes", "mixes employee and machine scopes")
		}
		if !seen[scope] {
			unique = append(unique, scope)
			seen[scope] = true
		}
	}
	return unique, nil
}

// joinScopeList renders one validated scope list for the wire.
func joinScopeList(scopes []Scope) string {
	values := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		values = append(values, string(scope))
	}
	return strings.Join(values, " ")
}
