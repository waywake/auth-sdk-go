package auth

import (
	"errors"
	"fmt"
)

var (
	// ErrInvalidArgument indicates invalid configuration or request input.
	ErrInvalidArgument = errors.New("auth: invalid argument")
	// ErrStateMismatch indicates an absent, invalid or mismatched OAuth state.
	ErrStateMismatch = errors.New("auth: OAuth state mismatch")
	// ErrInvalidResponse indicates a malformed or unexpected success response.
	ErrInvalidResponse = errors.New("auth: invalid response")
	// ErrResponseTooLarge indicates that the configured response limit was exceeded.
	ErrResponseTooLarge = errors.New("auth: response too large")
	// ErrTokenVerification indicates an ID Token or logout token that failed
	// signature, issuer, audience, freshness or claim validation.
	ErrTokenVerification = errors.New("auth: token verification failed")
	// ErrUnknownKey indicates that a token names a signing key the fetched JSON
	// Web Key Set does not publish.
	ErrUnknownKey = errors.New("auth: unknown signing key")
)

// ErrorCode is a stable error value returned by the server. The vocabulary is
// frozen by the OpenAPI contract; an unknown code is still carried verbatim.
type ErrorCode string

const (
	ErrorInvalidRequest         ErrorCode = "invalid_request"
	ErrorInvalidScope           ErrorCode = "invalid_scope"
	ErrorInvalidGrant           ErrorCode = "invalid_grant"
	ErrorUnsupportedGrantType   ErrorCode = "unsupported_grant_type"
	ErrorInvalidClient          ErrorCode = "invalid_client"
	ErrorInvalidToken           ErrorCode = "invalid_token"
	ErrorLoginRequired          ErrorCode = "login_required"
	ErrorHTTPSRequired          ErrorCode = "https_required"
	ErrorIPNotAllowed           ErrorCode = "ip_not_allowed"
	ErrorInsufficientScope      ErrorCode = "insufficient_scope"
	ErrorNotFound               ErrorCode = "not_found"
	ErrorConflict               ErrorCode = "conflict"
	ErrorSnapshotRequired       ErrorCode = "snapshot_required"
	ErrorRateLimitExceeded      ErrorCode = "rate_limit_exceeded"
	ErrorTemporarilyUnavailable ErrorCode = "temporarily_unavailable"
)

// APIError is returned for every non-200 HTTP response, including redirects and
// non-JSON gateway errors. Use errors.As to inspect it. Code is empty when no
// valid error envelope was returned. Response bodies are never included.
type APIError struct {
	StatusCode      int
	Code            ErrorCode
	RequestID       string
	RetryAfter      string // Raw Retry-After header (seconds or HTTP date).
	WWWAuthenticate string
	cause           error
}

func (e *APIError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("auth: HTTP %d (%s)", e.StatusCode, e.Code)
	}
	return fmt.Sprintf("auth: HTTP %d", e.StatusCode)
}

// Unwrap preserves errors encountered while reading an error response.
func (e *APIError) Unwrap() error { return e.cause }

func invalid(field, reason string) error {
	return fmt.Errorf("%w: %s %s", ErrInvalidArgument, field, reason)
}

func invalidResponse(reason string) error {
	return fmt.Errorf("%w: %s", ErrInvalidResponse, reason)
}

func verification(reason string) error {
	return fmt.Errorf("%w: %s", ErrTokenVerification, reason)
}
