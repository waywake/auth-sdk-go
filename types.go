package auth

// Scope identifies an application capability granted during authorization.
type Scope string

const (
	ScopeProfileRead      Scope = "profile:read"
	ScopePermissionsRead  Scope = "permissions:read"
	ScopePermissionsCheck Scope = "permissions:check"
)

// Response is the resource envelope returned by OpenAPI v1.
type Response[T any] struct {
	Data      T      `json:"data"`
	RequestID string `json:"request_id"`
}

// Profile contains the public fields of the authorized user.
type Profile struct {
	ID             int64   `json:"id"`
	Username       string  `json:"username"`
	Name           string  `json:"name"`
	Avatar         string  `json:"avatar"`
	HireDate       *string `json:"hire_date"`        // YYYY-MM-DD; nil when absent or null.
	HireDateSource string  `json:"hire_date_source"` // wecom_hr, created_at, or empty.
}

// Permissions contains effective roles and permissions within this application.
type Permissions struct {
	AppID       int64    `json:"app_id"`
	UserID      int64    `json:"user_id"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
}

// Check is a live permission decision. An unknown permission returns false.
type Check struct {
	Allowed bool `json:"allowed"`
}

type ProfileResponse = Response[Profile]
type PermissionsResponse = Response[Permissions]
type CheckResponse = Response[Check]

// Token is the unwrapped OAuth token response. ExpiresIn is measured in seconds.
// The server does not issue refresh tokens; applications must authorize again
// after expiry or revocation. Treat AccessToken as a secret.
type Token struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	Scope       string `json:"scope"`
}

// AuthorizeParams are required to construct an S256 authorization URL.
type AuthorizeParams struct {
	RedirectURI   string
	Scopes        []Scope
	State         string
	CodeChallenge string
}

// ExchangeCodeParams binds an authorization code to its original transaction.
type ExchangeCodeParams struct {
	Code         string
	RedirectURI  string
	CodeVerifier string
}

// RevokeTokenParams identifies a token to revoke. TokenTypeHint is optional.
// The server returns success for unknown tokens and tokens of other apps.
type RevokeTokenParams struct {
	Token         string
	TokenTypeHint string
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
