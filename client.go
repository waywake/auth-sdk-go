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
	apiPath                       = "/openapi/v1"
	DefaultTimeout                = 15 * time.Second
	DefaultMaxResponseBytes int64 = 4 << 20
)

// Config configures a Client. BaseURL is the deployment origin, for example
// https://auth.example.com, without /openapi/v1 or any query/fragment.
type Config struct {
	BaseURL      string
	ClientID     int64
	ClientSecret string // Independent oas_ secret; optional for URL/resource-only use.
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
	baseURL          string
	clientID         string
	clientSecret     string
	httpClient       http.Client
	maxResponseBytes int64
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
	if config.ClientSecret != "" && !validCredential(config.ClientSecret, "oas_") {
		return nil, invalid("ClientSecret", "must be an independent OpenAPI secret (oas_)")
	}
	if config.MaxResponseBytes < 0 || config.MaxResponseBytes == 1<<63-1 {
		return nil, invalid("MaxResponseBytes", "must be nonnegative and smaller than MaxInt64")
	}
	limit := config.MaxResponseBytes
	if limit == 0 {
		limit = DefaultMaxResponseBytes
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
		clientSecret: config.ClientSecret, httpClient: hc, maxResponseBytes: limit,
	}, nil
}

var errorCodePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

func (c *Client) do(ctx context.Context, method, path, contentType, body, token string, basic bool, out any) error {
	if ctx == nil {
		return invalid("context", "must not be nil")
	}
	if basic && c.clientSecret == "" {
		return invalid("ClientSecret", "is required for token exchange and revocation")
	}
	if !basic && !validCredential(token, "oat_") {
		return invalid("access token", "must be an OpenAPI bearer token (oat_)")
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+apiPath+path, strings.NewReader(body))
	if err != nil {
		return fmt.Errorf("auth: create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "waywake-auth-sdk-go/1")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if basic {
		req.SetBasicAuth(c.clientID, c.clientSecret)
	} else {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.httpClient.Do(req)
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
			return fmt.Errorf("%w: expected an empty revocation response", ErrInvalidResponse)
		}
		return nil
	}
	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return fmt.Errorf("%w: expected application/json", ErrInvalidResponse)
	}
	// Unmarshal rejects trailing JSON documents. Unknown fields remain compatible
	// with additive v1 changes. Never include raw response data in an error.
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("%w: malformed JSON", ErrInvalidResponse)
	}
	return nil
}

func readResource[T any](ctx context.Context, c *Client, method, path, contentType, body, token string) (*Response[T], error) {
	var envelope struct {
		Data      *T      `json:"data"`
		RequestID *string `json:"request_id"`
	}
	if err := c.do(ctx, method, path, contentType, body, token, false, &envelope); err != nil {
		return nil, err
	}
	if envelope.Data == nil || envelope.RequestID == nil {
		return nil, fmt.Errorf("%w: missing data or request_id", ErrInvalidResponse)
	}
	return &Response[T]{Data: *envelope.Data, RequestID: *envelope.RequestID}, nil
}
