package auth

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"
)

// Scope identifies an application capability. The deployment keeps two disjoint
// vocabularies: employee scopes are granted by a browser authorization or the
// enterprise mini-program grant, machine scopes by the client-credentials
// grant. A token of one kind is refused on every resource of the other kind.
type Scope string

const (
	// Employee scopes.

	// ScopeProfileRead grants the minimal profile of the authorizing employee.
	ScopeProfileRead Scope = "profile:read"
	// ScopePermissionsRead grants the employee's effective roles and permissions.
	ScopePermissionsRead Scope = "permissions:read"
	// ScopePermissionsCheck grants a live permission decision for the employee.
	ScopePermissionsCheck Scope = "permissions:check"
	// ScopeOpenID asks for an RS256 ID Token alongside the access token.
	ScopeOpenID Scope = "openid"
	// ScopeProfile grants the OIDC name, preferred_username and picture claims.
	// It does not grant the HR fields of ScopeProfileRead.
	ScopeProfile Scope = "profile"
	// ScopeEmail grants the OIDC email and email_verified claims.
	ScopeEmail Scope = "email"

	// Machine scopes.

	// ScopeDirectoryRead reads the organization inside the directory range.
	ScopeDirectoryRead Scope = "directory:read"
	// ScopeLeaveRead reads employee leave summaries inside the directory range.
	ScopeLeaveRead Scope = "leave:read"
	// ScopeIAMRead reads the application's roles, permission points and grants.
	ScopeIAMRead Scope = "iam:read"
	// ScopeIAMWrite manages the application's roles, permission points and grants.
	ScopeIAMWrite Scope = "iam:write"
	// ScopeEventsRead pulls the application's change stream.
	ScopeEventsRead Scope = "events:read"
	// ScopeAuditRead reads the application's audit history and call statistics.
	ScopeAuditRead Scope = "audit:read"
	// ScopeStoresRead reads the store directory inside the configured store range.
	ScopeStoresRead Scope = "stores:read"
	// ScopeStoresDeliveryRead additionally reads store receiving addresses.
	ScopeStoresDeliveryRead Scope = "stores:delivery:read"
	// ScopeStoresMembersRead reads assignments within both store and directory ranges.
	ScopeStoresMembersRead Scope = "stores:members:read"
)

// Machine reports whether the scope belongs to the machine vocabulary. The two
// vocabularies are never interchangeable.
func (s Scope) Machine() bool {
	switch s {
	case ScopeDirectoryRead, ScopeLeaveRead, ScopeIAMRead, ScopeIAMWrite, ScopeEventsRead, ScopeAuditRead,
		ScopeStoresRead, ScopeStoresDeliveryRead, ScopeStoresMembersRead:
		return true
	default:
		return false
	}
}

func (s Scope) valid() bool {
	switch s {
	case ScopeProfileRead, ScopePermissionsRead, ScopePermissionsCheck,
		ScopeOpenID, ScopeProfile, ScopeEmail,
		ScopeDirectoryRead, ScopeLeaveRead, ScopeIAMRead, ScopeIAMWrite, ScopeEventsRead, ScopeAuditRead,
		ScopeStoresRead, ScopeStoresDeliveryRead, ScopeStoresMembersRead:
		return true
	default:
		return false
	}
}

// UserScopeVocabulary returns the employee scope vocabulary in the order the
// discovery document publishes it.
func UserScopeVocabulary() []Scope {
	return []Scope{ScopeProfileRead, ScopePermissionsRead, ScopePermissionsCheck, ScopeOpenID, ScopeProfile, ScopeEmail}
}

// MachineScopeVocabulary returns the machine scope vocabulary.
func MachineScopeVocabulary() []Scope {
	return []Scope{ScopeDirectoryRead, ScopeLeaveRead, ScopeIAMRead, ScopeIAMWrite, ScopeEventsRead, ScopeAuditRead,
		ScopeStoresRead, ScopeStoresDeliveryRead, ScopeStoresMembersRead}
}

// GrantType is one grant the token endpoint serves. An application is
// configured per grant; an unconfigured grant answers unsupported_grant_type.
type GrantType string

const (
	GrantAuthorizationCode GrantType = "authorization_code"
	GrantRefreshToken      GrantType = "refresh_token"
	GrantClientCredentials GrantType = "client_credentials"
	// GrantWeComMiniProgram exchanges a wx.qy.login code through the
	// application's registered mini-program binding.
	GrantWeComMiniProgram GrantType = "urn:waywake:params:oauth:grant-type:wecom-mini-program"
)

// Prompt is the closed OIDC prompt vocabulary. This deployment shows no consent
// or account-selection page, so nothing else is accepted.
type Prompt string

const (
	// PromptLogin forces a fresh interactive authentication before the code is
	// issued.
	PromptLogin Prompt = "login"
	// PromptNone answers login_required instead of an interactive login when the
	// browser session is absent or insufficiently fresh.
	PromptNone Prompt = "none"
)

// TokenEndpointAuth selects how the client authenticates at the token, revoke
// and introspect endpoints. A request uses exactly one method.
type TokenEndpointAuth string

const (
	// TokenEndpointAuthBasic sends HTTP Basic APP_ID:OPENAPI_SECRET. This is the
	// default.
	TokenEndpointAuthBasic TokenEndpointAuth = "client_secret_basic"
	// TokenEndpointAuthPost sends client_id and client_secret form fields.
	TokenEndpointAuthPost TokenEndpointAuth = "client_secret_post"
)

// TokenTypeHint is the optional RFC 7009 hint passed to revoke and introspect.
type TokenTypeHint string

const (
	TokenTypeHintAccessToken  TokenTypeHint = "access_token"
	TokenTypeHintRefreshToken TokenTypeHint = "refresh_token"
)

// SubjectKind distinguishes the two kinds of credential introspection reports.
type SubjectKind string

const (
	SubjectKindUser    SubjectKind = "user"
	SubjectKindMachine SubjectKind = "machine"
)

// GrantOrigin explains whether an effective authorization came from the
// employee directly or from an approved user group.
type GrantOrigin string

const (
	GrantOriginDirect GrantOrigin = "direct"
	GrantOriginGroup  GrantOrigin = "group"
)

// Response is the resource envelope returned by OpenAPI v1. Data is the
// operation's payload; RequestID correlates the call with the server audit row.
type Response[T any] struct {
	Data      T      `json:"data"`
	RequestID string `json:"request_id"`
}

// Token is the OAuth token response. ExpiresIn is the actual remaining access
// token lifetime in seconds, up to 24 hours and shortened near the
// authorization session's absolute deadline.
//
// RefreshToken is present only for a refreshable employee grant and must
// overwrite the previous value: the old one is void the moment the response is
// sent, and reusing it revokes the whole authorization. IDToken is present
// exactly when the authorization asked for ScopeOpenID.
type Token struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
}

// Scopes splits the space-separated granted scope list.
func (t *Token) Scopes() []Scope {
	if t == nil || t.Scope == "" {
		return nil
	}
	return splitScopeList(t.Scope)
}

// Machine reports whether the token is a client-credentials machine token. A
// machine token never carries an employee identity and is refused on every
// employee resource.
func (t *Token) Machine() bool {
	return t != nil && len(t.AccessToken) > 4 && t.AccessToken[:4] == machineTokenPrefix
}

// Profile contains the public fields of the authorizing employee: never the
// mobile number, the corporate mailbox or any other profile column.
//
// HireDate and RegularizationDate are YYYY-MM-DD or nil. HireDateSource is
// "wecom_hr" for HR-assistant data, "created_at" for the unverified account
// creation date, and empty when unknown. ProbationMonths is a month count
// (0 means no probation) or nil when HR has not filled it in.
type Profile struct {
	ID                 int64   `json:"id"`
	Username           string  `json:"username"`
	Name               string  `json:"name"`
	Avatar             string  `json:"avatar"`
	HireDate           *string `json:"hire_date"`
	HireDateSource     string  `json:"hire_date_source"`
	ProbationMonths    *int    `json:"probation_months"`
	RegularizationDate *string `json:"regularization_date"`
}

// Permissions contains the employee's effective roles and permissions within
// the token's application. Authorization sources are deliberately absent here;
// they are available only to the application's own IAM explanation endpoint.
//
// EvaluatedAt is the instant the answer was computed and NextChangeAt names the
// next scheduled authorization transition, when one exists.
type Permissions struct {
	AppID        int64      `json:"app_id"`
	UserID       int64      `json:"user_id"`
	Roles        []string   `json:"roles"`
	Permissions  []string   `json:"permissions"`
	EvaluatedAt  time.Time  `json:"evaluated_at"`
	NextChangeAt *time.Time `json:"next_change_at"`
}

// Check is a live permission decision. A well-formed key the employee does not
// hold returns Allowed false.
type Check struct {
	Allowed      bool       `json:"allowed"`
	EvaluatedAt  time.Time  `json:"evaluated_at"`
	NextChangeAt *time.Time `json:"next_change_at"`
}

// BatchCheck answers up to 100 permission questions against one authorization
// snapshot. Results appear once each, in request order.
type BatchCheck struct {
	Results      []Check    `json:"results"`
	EvaluatedAt  time.Time  `json:"evaluated_at"`
	NextChangeAt *time.Time `json:"next_change_at"`
}

// Introspection is the RFC 7662 answer. An unknown, expired, revoked or
// foreign credential reports Active false and nothing else.
type Introspection struct {
	Active      bool        `json:"active"`
	ExpiresAt   *int64      `json:"exp"`
	Subject     string      `json:"sub"`
	ClientID    string      `json:"client_id"`
	Audience    []string    `json:"aud"`
	Username    string      `json:"username"`
	Scope       string      `json:"scope"`
	TokenType   string      `json:"token_type"`
	SubjectKind SubjectKind `json:"subject_kind"`
}

// Scopes splits the space-separated scope list of an active introspection.
func (i *Introspection) Scopes() []Scope {
	if i == nil || i.Scope == "" {
		return nil
	}
	return splitScopeList(i.Scope)
}

// MachineIdentity describes the machine that presented a machine token. It has
// no employee field, because a machine token has no user.
type MachineIdentity struct {
	AppID        int64    `json:"app_id"`
	Subject      string   `json:"subject"`
	Scopes       []string `json:"scopes"`
	CredentialID int64    `json:"credential_id"`
}

// MachineScopes lists the machine scopes the presented token currently carries.
type MachineScopes struct {
	AppID  int64    `json:"app_id"`
	Scopes []string `json:"scopes"`
}

// DepartmentRef is one department relation of a directory employee.
type DepartmentRef struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

// GroupRef is one user-group relation of a directory employee.
type GroupRef struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

// DirectoryUser is one employee inside the application's directory range. Only
// the in-scope organization relations are returned.
type DirectoryUser struct {
	ID          int64           `json:"id"`
	Username    string          `json:"username"`
	Name        string          `json:"name"`
	Avatar      string          `json:"avatar"`
	Departments []DepartmentRef `json:"departments"`
	Groups      []GroupRef      `json:"groups"`
}

// Department is one department inside the directory range. ParentID is 0 when
// the parent is outside the range, so an unreadable identifier never leaks.
type Department struct {
	ID       int64  `json:"id"`
	ParentID int64  `json:"parent_id"`
	Name     string `json:"name"`
	Order    int64  `json:"order"`
}

// Group is one user group inside the directory range.
type Group struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// Page is one keyset page. Next is 0 on the last page; otherwise pass it as the
// next request's cursor.
type Page[T any] struct {
	Items []T   `json:"items"`
	Next  int64 `json:"next"`
}

// AppRole is one role owned by the calling application.
type AppRole struct {
	ID          int64  `json:"id"`
	Key         string `json:"key"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// AppPermission is one permission point owned by the calling application.
type AppPermission struct {
	ID          int64  `json:"id"`
	Key         string `json:"key"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// PermissionSource explains one authorization origin. This is the one public
// surface that exposes origins, because explaining them is its purpose.
type PermissionSource struct {
	RoleID    int64       `json:"role_id"`
	Key       string      `json:"key"`
	Name      string      `json:"name"`
	Origin    GrantOrigin `json:"origin"`
	GroupID   int64       `json:"group_id"`
	GroupName string      `json:"group_name"`
	ExpiresAt *time.Time  `json:"expires_at"`
}

// PermissionExplanation is the effective authorization of one in-scope
// employee, with the origin of every source.
type PermissionExplanation struct {
	AppID        int64              `json:"app_id"`
	UserID       int64              `json:"user_id"`
	Roles        []string           `json:"roles"`
	Permissions  []string           `json:"permissions"`
	Sources      []PermissionSource `json:"sources"`
	EvaluatedAt  time.Time          `json:"evaluated_at"`
	NextChangeAt *time.Time         `json:"next_change_at"`
}

// ID names the object a write touched.
type ID struct {
	ID int64 `json:"id"`
}

// EventType is the closed change-stream vocabulary. An event name outside it is
// rejected by the server rather than matched against nothing.
type EventType string

const (
	EventUserCreated            EventType = "user.created"
	EventUserUpdated            EventType = "user.updated"
	EventUserEnabled            EventType = "user.enabled"
	EventUserDisabled           EventType = "user.disabled"
	EventUserDeparted           EventType = "user.departed"
	EventUserRemoved            EventType = "user.removed"
	EventDepartmentUpserted     EventType = "department.upserted"
	EventDepartmentRemoved      EventType = "department.removed"
	EventMembershipAdded        EventType = "membership.added"
	EventMembershipRemoved      EventType = "membership.removed"
	EventGroupCreated           EventType = "group.created"
	EventGroupUpdated           EventType = "group.updated"
	EventGroupDeleted           EventType = "group.deleted"
	EventGroupMemberAdded       EventType = "group.member_added"
	EventGroupMemberRemoved     EventType = "group.member_removed"
	EventAuthorizationGranted   EventType = "authorization.granted"
	EventAuthorizationExpired   EventType = "authorization.expired"
	EventAuthorizationRevoked   EventType = "authorization.revoked"
	EventAuthorizationExpirySet EventType = "authorization.expiry_changed"
	EventAppDisabled            EventType = "app.disabled"
	EventAppEnabled             EventType = "app.enabled"
	EventSessionRevoked         EventType = "session.revoked"
	EventCredentialChanged      EventType = "credential.changed"

	// EventExternalIdentityChanged asks consumers to reread the employee's bindings.
	// Its payload contains only user_id, never external identity values.
	EventExternalIdentityChanged EventType = "external_identity.changed"
)

// EventTypes returns the event vocabulary in the order the contract publishes
// it.
func EventTypes() []EventType {
	return []EventType{
		EventUserCreated, EventUserUpdated, EventUserEnabled, EventUserDisabled,
		EventUserDeparted, EventUserRemoved, EventExternalIdentityChanged,
		EventDepartmentUpserted, EventDepartmentRemoved,
		EventMembershipAdded, EventMembershipRemoved,
		EventGroupCreated, EventGroupUpdated, EventGroupDeleted,
		EventGroupMemberAdded, EventGroupMemberRemoved,
		EventAuthorizationGranted, EventAuthorizationExpired, EventAuthorizationRevoked,
		EventAuthorizationExpirySet,
		EventAppDisabled, EventAppEnabled, EventSessionRevoked, EventCredentialChanged,
	}
}

func (t EventType) valid() bool {
	for _, known := range EventTypes() {
		if t == known {
			return true
		}
	}
	return false
}

// EventSubject names the kind of object an event's SubjectID identifies.
type EventSubject string

const (
	EventSubjectUser           EventSubject = "user"
	EventSubjectDepartment     EventSubject = "department"
	EventSubjectGroup          EventSubject = "group"
	EventSubjectApp            EventSubject = "app"
	EventSubjectSession        EventSubject = "session"
	EventSubjectBrowserSession EventSubject = "browser_session"
)

// Event is one change-stream record. ID is stable across redeliveries and is
// what a receiver deduplicates on; Sequence is this application's own dense
// cursor, assigned at publish time. Data holds the event-specific payload and
// its fields are additive within a type.
type Event struct {
	ID         int64          `json:"id"`
	Sequence   int64          `json:"sequence"`
	Type       EventType      `json:"type"`
	Subject    EventSubject   `json:"subject"`
	SubjectID  int64          `json:"subject_id"`
	OccurredAt time.Time      `json:"occurred_at"`
	ExpiresAt  time.Time      `json:"expires_at"`
	Data       map[string]any `json:"data"`
}

// EventPage is one pull of the change stream. Next is the cursor to continue
// from; HasMore is computed before filtering, so a page with no events still
// requires following Next when HasMore is true.
type EventPage struct {
	Next    int64   `json:"next"`
	Events  []Event `json:"events"`
	HasMore bool    `json:"has_more"`
}

// AuditOutcome is the recorded result of one action.
type AuditOutcome string

const (
	AuditOutcomeSuccess AuditOutcome = "success"
	AuditOutcomeFailure AuditOutcome = "failure"
	AuditOutcomeUnknown AuditOutcome = "unknown"
)

// AuditEvent is one row of the application's own audit history. ActorAppID is
// the application that acted and AppID the application the row concerns; both
// directions belong to the calling application's history.
type AuditEvent struct {
	ID         int64        `json:"id"`
	CreatedAt  time.Time    `json:"created_at"`
	Action     string       `json:"action"`
	Outcome    AuditOutcome `json:"outcome"`
	TargetType string       `json:"target_type"`
	TargetID   int64        `json:"target_id"`
	ActorID    int64        `json:"actor_id"`
	ActorAppID int64        `json:"actor_app_id"`
	AppID      int64        `json:"app_id"`
	UserID     int64        `json:"user_id"`
	RoleID     int64        `json:"role_id"`
	RequestID  string       `json:"request_id"`
	PeerIP     string       `json:"peer_ip"`
	Status     int          `json:"status"`
}

// AuditUsageBucket is one day/action/outcome aggregate. Day is a calendar day
// in the deployment's time zone.
type AuditUsageBucket struct {
	Day     time.Time    `json:"day"`
	Action  string       `json:"action"`
	Outcome AuditOutcome `json:"outcome"`
	Calls   int64        `json:"calls"`
}

// LatencyBucket is one cumulative latency bound: a call within UpperMillis also
// appears in every larger bucket.
type LatencyBucket struct {
	UpperMillis int64 `json:"upper_ms"`
	Calls       int64 `json:"calls"`
}

// LatencyReport summarises the calls of one usage window that carried a
// duration. Measured is the part of the window's Calls the summary describes.
// P95UpperMillis is read off the buckets rather than an exact quantile, and is
// zero when nothing was measured.
type LatencyReport struct {
	Measured       int64           `json:"measured"`
	AverageMillis  int64           `json:"average_ms"`
	MaximumMillis  int64           `json:"maximum_ms"`
	P95UpperMillis int64           `json:"p95_upper_ms"`
	Buckets        []LatencyBucket `json:"buckets"`
}

// RateUsage is one request budget the application spends for itself in the
// current fixed window. ResetsInSeconds is how long until the spent budget is
// refunded; zero means nothing is currently spent.
type RateUsage struct {
	Purpose         string `json:"purpose"`
	Limit           int    `json:"limit"`
	Used            int64  `json:"used"`
	WindowSeconds   int    `json:"window_seconds"`
	ResetsInSeconds int    `json:"resets_in_seconds"`
}

// AuditUsage is the application's recorded activity over a window of calendar
// days, ending today. RateLimit is nil when the counter store could not be
// read: it is never a fabricated zero.
type AuditUsage struct {
	From      time.Time          `json:"from"`
	To        time.Time          `json:"to"`
	Calls     int64              `json:"calls"`
	Success   int64              `json:"success"`
	Failure   int64              `json:"failure"`
	Buckets   []AuditUsageBucket `json:"buckets"`
	RateLimit []RateUsage        `json:"rate_limit"`
	Latency   LatencyReport      `json:"latency"`
}

// OpenIDConfiguration is the OIDC discovery document. Every URL is built from
// the deployment's public Base URL, which is the same value an ID Token states
// as its issuer.
type OpenIDConfiguration struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserInfoEndpoint                  string   `json:"userinfo_endpoint"`
	EndSessionEndpoint                string   `json:"end_session_endpoint"`
	JWKSURI                           string   `json:"jwks_uri"`
	ScopesSupported                   []string `json:"scopes_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	ResponseModesSupported            []string `json:"response_modes_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
}

// JSONWebKey is one public ID Token signing key. Private parameters are never
// published.
type JSONWebKey struct {
	KeyType   string `json:"kty"`
	Use       string `json:"use"`
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	Modulus   string `json:"n"`
	Exponent  string `json:"e"`
}

// JSONWebKeySet is the published key document, in rotation order: the first key
// signs, every published key still verifies. It can be cached for 300 seconds.
type JSONWebKeySet struct {
	Keys []JSONWebKey `json:"keys"`
}

// UserInfo is the standard OIDC userinfo answer, served as a bare object rather
// than inside the API's data envelope. Subject is the same decimal employee
// identifier the ID Token states.
//
// Name, PreferredUsername and Picture are present only when the token also
// carries ScopeProfile or ScopeProfileRead. Email and EmailVerified require
// ScopeEmail; verification is false because the directory holds no verification
// evidence, and both fields are omitted when no address is recorded.
type UserInfo struct {
	Subject           string `json:"sub"`
	PreferredUsername string `json:"preferred_username"`
	Name              string `json:"name"`
	Picture           string `json:"picture"`
	Email             string `json:"email"`
	EmailVerified     *bool  `json:"email_verified"`
}

// Audience is a JWT audience that may be encoded as either a single string or
// an array of strings.
type Audience []string

// UnmarshalJSON accepts both RFC 7519 encodings of `aud`.
func (a *Audience) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*a = Audience{single}
		return nil
	}
	var list []string
	if err := json.Unmarshal(data, &list); err != nil {
		return fmt.Errorf("auth: invalid audience claim")
	}
	*a = Audience(list)
	return nil
}

// Contains reports whether an application identifier is named by the audience.
func (a Audience) Contains(id int64) bool {
	if id <= 0 {
		return false
	}
	want := strconv.FormatInt(id, 10)
	for _, value := range a {
		if value == want {
			return true
		}
	}
	return false
}

// IDTokenClaims are the claims of an ID Token issued by this deployment. They
// describe the authentication, never the authorization: permissions are read
// from the resource endpoints, where scope is enforced on every call.
//
// Subject is the immutable employee key and the account-linking key; AuthTime is
// when the employee actually authenticated, which is not IssuedAt.
type IDTokenClaims struct {
	Issuer            string   `json:"iss"`
	Subject           string   `json:"sub"`
	Audience          Audience `json:"aud"`
	ExpiresAt         int64    `json:"exp"`
	IssuedAt          int64    `json:"iat"`
	AuthTime          int64    `json:"auth_time"`
	Nonce             string   `json:"nonce"`
	SessionID         string   `json:"sid"`
	Name              string   `json:"name"`
	PreferredUsername string   `json:"preferred_username"`
	Picture           string   `json:"picture"`
	Email             string   `json:"email"`
	EmailVerified     bool     `json:"email_verified"`
}

// BackChannelLogoutEvent is the sole member of a logout token's `events` claim.
const BackChannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout"

// LogoutTokenClaims are the claims of an OIDC back-channel logout token. They
// say who was logged out and which application is being told, and nothing else.
//
// SessionID restricts a delayed browser logout to the exact login that ended, so
// redelivery cannot terminate a newer login of the same employee. A logout token
// never carries a nonce; see VerifyLogoutToken.
type LogoutTokenClaims struct {
	Issuer    string          `json:"iss"`
	Subject   string          `json:"sub"`
	Audience  Audience        `json:"aud"`
	IssuedAt  int64           `json:"iat"`
	TokenID   string          `json:"jti"`
	SessionID string          `json:"sid"`
	Events    json.RawMessage `json:"events"`
	Nonce     *string         `json:"nonce"`
}

// LoggedOutEvent reports whether the token announces the back-channel logout
// event the specification defines.
func (c *LogoutTokenClaims) LoggedOutEvent() bool {
	if len(c.Events) == 0 {
		return false
	}
	var events map[string]json.RawMessage
	if err := json.Unmarshal(c.Events, &events); err != nil {
		return false
	}
	_, ok := events[BackChannelLogoutEvent]
	return ok
}

// Resource response aliases.

type (
	ProfileResponse               = Response[Profile]
	PermissionsResponse           = Response[Permissions]
	CheckResponse                 = Response[Check]
	BatchCheckResponse            = Response[BatchCheck]
	MachineIdentityResponse       = Response[MachineIdentity]
	MachineScopesResponse         = Response[MachineScopes]
	DirectoryUserResponse         = Response[DirectoryUser]
	DirectoryUserPageResponse     = Response[Page[DirectoryUser]]
	DepartmentListResponse        = Response[[]Department]
	GroupListResponse             = Response[[]Group]
	DepartmentRefListResponse     = Response[[]DepartmentRef]
	GroupRefListResponse          = Response[[]GroupRef]
	AppRolePageResponse           = Response[Page[AppRole]]
	AppPermissionPageResponse     = Response[Page[AppPermission]]
	IDResponse                    = Response[ID]
	PermissionExplanationResponse = Response[PermissionExplanation]
	EventPageResponse             = Response[EventPage]
	AuditEventPageResponse        = Response[Page[AuditEvent]]
	AuditUsageResponse            = Response[AuditUsage]
)

func splitScopeList(raw string) []Scope {
	fields := splitFields(raw)
	if len(fields) == 0 {
		return nil
	}
	scopes := make([]Scope, 0, len(fields))
	for _, field := range fields {
		scopes = append(scopes, Scope(field))
	}
	return scopes
}
