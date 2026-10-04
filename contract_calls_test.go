package auth

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// contractCalls exercises every operation the SDK covers. Each call goes
// through the recording transport, except the browser-facing URLs the SDK only
// builds, which are turned into the request they would become.
var contractCalls = []struct {
	name   string
	invoke func(t *testing.T, c *Client, ctx context.Context) ([]*http.Request, error)
}{
	{"authorize", func(_ *testing.T, c *Client, _ context.Context) ([]*http.Request, error) {
		maxAge := int64(3600)
		authorization, err := c.NewAuthorization(AuthorizeParams{
			RedirectURI: testRedirect, Scopes: []Scope{ScopeProfileRead, ScopePermissionsCheck},
			Nonce: "contract-nonce", MaxAge: &maxAge, Prompt: PromptNone,
		})
		if err != nil {
			return nil, err
		}
		return one(synthetic(http.MethodGet, authorization.URL, nil))
	}},
	{"postAuthorize", func(_ *testing.T, c *Client, _ context.Context) ([]*http.Request, error) {
		endpoint, form, err := c.AuthorizePost(AuthorizeParams{
			RedirectURI: testRedirect, Scopes: []Scope{ScopeProfileRead},
			State: testState, CodeChallenge: testChallenge,
		})
		if err != nil {
			return nil, err
		}
		return one(synthetic(http.MethodPost, endpoint, form))
	}},
	{"token", func(_ *testing.T, c *Client, ctx context.Context) ([]*http.Request, error) {
		if _, err := c.ExchangeCode(ctx, ExchangeCodeParams{Code: testCode, RedirectURI: testRedirect, CodeVerifier: testVerifier}); err != nil {
			return nil, err
		}
		if _, err := c.Refresh(ctx, RefreshParams{RefreshToken: testRefreshToken}); err != nil {
			return nil, err
		}
		if _, err := c.ClientCredentials(ctx, ClientCredentialsParams{Scopes: MachineScopeVocabulary()}); err != nil {
			return nil, err
		}
		_, err := c.ExchangeMiniProgramCode(ctx, MiniProgramParams{
			MiniProgramAppID: testMiniProgramID, WeComCode: "one-time-code", Scopes: []Scope{ScopeProfileRead},
		})
		return nil, err
	}},
	{"revoke", func(_ *testing.T, c *Client, ctx context.Context) ([]*http.Request, error) {
		return nil, c.RevokeToken(ctx, RevokeTokenParams{Token: testRefreshToken, TokenTypeHint: TokenTypeHintRefreshToken})
	}},
	{"introspect", func(_ *testing.T, c *Client, ctx context.Context) ([]*http.Request, error) {
		_, err := c.Introspect(ctx, IntrospectParams{Token: testToken, TokenTypeHint: TokenTypeHintAccessToken})
		return nil, err
	}},
	{"logout", func(_ *testing.T, c *Client, _ context.Context) ([]*http.Request, error) {
		target, err := c.LogoutURL(LogoutParams{
			IDTokenHint: "header.payload.signature", PostLogoutRedirectURI: testRedirect, State: testState,
		})
		if err != nil {
			return nil, err
		}
		return one(synthetic(http.MethodGet, target, nil))
	}},
	{"userinfo", func(_ *testing.T, c *Client, ctx context.Context) ([]*http.Request, error) {
		_, err := c.GetUserInfo(ctx, testToken)
		return nil, err
	}},
	{"discovery", func(_ *testing.T, c *Client, ctx context.Context) ([]*http.Request, error) {
		_, err := c.Discovery(ctx)
		return nil, err
	}},
	{"jwks", func(_ *testing.T, c *Client, ctx context.Context) ([]*http.Request, error) {
		_, err := c.JSONWebKeySet(ctx)
		return nil, err
	}},
	{"me", func(_ *testing.T, c *Client, ctx context.Context) ([]*http.Request, error) {
		_, err := c.GetCurrentUser(ctx, testToken)
		return nil, err
	}},
	{"me/permissions", func(_ *testing.T, c *Client, ctx context.Context) ([]*http.Request, error) {
		_, err := c.GetCurrentPermissions(ctx, testToken)
		return nil, err
	}},
	{"me/permissions/check", func(_ *testing.T, c *Client, ctx context.Context) ([]*http.Request, error) {
		_, err := c.CheckCurrentPermission(ctx, testToken, "order.read")
		return nil, err
	}},
	{"me/permissions/check-batch", func(_ *testing.T, c *Client, ctx context.Context) ([]*http.Request, error) {
		_, err := c.CheckCurrentPermissions(ctx, testToken, "order.read", "order.write")
		return nil, err
	}},
	{"machine/me", func(_ *testing.T, c *Client, ctx context.Context) ([]*http.Request, error) {
		_, err := c.GetMachineIdentity(ctx, testMachineToken)
		return nil, err
	}},
	{"machine/me/permissions", func(_ *testing.T, c *Client, ctx context.Context) ([]*http.Request, error) {
		_, err := c.GetMachineScopes(ctx, testMachineToken)
		return nil, err
	}},
	{"directory/users", func(_ *testing.T, c *Client, ctx context.Context) ([]*http.Request, error) {
		_, err := c.ListDirectoryUsers(ctx, testMachineToken, ListDirectoryUsersParams{
			PageParams: PageParams{Limit: 50}, DepartmentID: 9, GroupID: 8, Search: "ali",
		})
		return nil, err
	}},
	{"directory/users/{id}", func(_ *testing.T, c *Client, ctx context.Context) ([]*http.Request, error) {
		_, err := c.GetDirectoryUser(ctx, testMachineToken, 7)
		return nil, err
	}},
	{"directory/users/{id}/departments", func(_ *testing.T, c *Client, ctx context.Context) ([]*http.Request, error) {
		_, err := c.ListDirectoryUserDepartments(ctx, testMachineToken, 7)
		return nil, err
	}},
	{"directory/users/{id}/groups", func(_ *testing.T, c *Client, ctx context.Context) ([]*http.Request, error) {
		_, err := c.ListDirectoryUserGroups(ctx, testMachineToken, 7)
		return nil, err
	}},
	{"directory/departments", func(_ *testing.T, c *Client, ctx context.Context) ([]*http.Request, error) {
		_, err := c.ListDirectoryDepartments(ctx, testMachineToken)
		return nil, err
	}},
	{"directory/departments/{id}/members", func(_ *testing.T, c *Client, ctx context.Context) ([]*http.Request, error) {
		_, err := c.ListDirectoryDepartmentMembers(ctx, testMachineToken, 9, PageParams{After: 5, Limit: 10})
		return nil, err
	}},
	{"directory/groups", func(_ *testing.T, c *Client, ctx context.Context) ([]*http.Request, error) {
		_, err := c.ListDirectoryGroups(ctx, testMachineToken, PageParams{Limit: 10})
		return nil, err
	}},
	{"directory/groups/{id}/members", func(_ *testing.T, c *Client, ctx context.Context) ([]*http.Request, error) {
		_, err := c.ListDirectoryGroupMembers(ctx, testMachineToken, 8, PageParams{After: 5})
		return nil, err
	}},
	{"directory/external-identities/lookup", func(_ *testing.T, c *Client, ctx context.Context) ([]*http.Request, error) {
		_, err := c.LookupDirectoryExternalIdentities(ctx, testMachineToken, []ExternalIdentityKey{{Provider: "YOUZAN", TenantID: "tenant-1", Namespace: "SALESMAN", ExternalID: "staff-9"}})
		return nil, err
	}},
	{"directory/users/external-identities", func(_ *testing.T, c *Client, ctx context.Context) ([]*http.Request, error) {
		_, err := c.ListDirectoryEmployeeExternalIdentities(ctx, testMachineToken, []int64{7, 8})
		return nil, err
	}},
	{"leave/users/{id}", func(_ *testing.T, c *Client, ctx context.Context) ([]*http.Request, error) {
		_, err := c.GetEmployeeLeave(ctx, testMachineToken, 7)
		return nil, err
	}},
	{"stores", func(_ *testing.T, c *Client, ctx context.Context) ([]*http.Request, error) {
		_, err := c.ListStores(ctx, testMachineToken, ListStoresParams{After: "opaque-cursor", Limit: 100, BrandID: 3, Status: StoreStatusOpen, Query: "上海"})
		return nil, err
	}},
	{"stores/{id}", func(_ *testing.T, c *Client, ctx context.Context) ([]*http.Request, error) {
		_, err := c.GetStore(ctx, testMachineToken, 101)
		return nil, err
	}},
	{"stores/{id}/receiving-address", func(_ *testing.T, c *Client, ctx context.Context) ([]*http.Request, error) {
		_, err := c.GetStoreReceivingAddress(ctx, testMachineToken, 101)
		return nil, err
	}},
	{"stores/{id}/employees", func(_ *testing.T, c *Client, ctx context.Context) ([]*http.Request, error) {
		_, err := c.GetStoreEmployees(ctx, testMachineToken, 101)
		return nil, err
	}},
	{"directory/users/{id}/stores", func(_ *testing.T, c *Client, ctx context.Context) ([]*http.Request, error) {
		_, err := c.GetEmployeeStores(ctx, testMachineToken, 7)
		return nil, err
	}},
	{"stores/external-identities/lookup", func(_ *testing.T, c *Client, ctx context.Context) ([]*http.Request, error) {
		_, err := c.LookupExternalStores(ctx, testMachineToken, []ExternalStoreKey{{Provider: "YOUZAN", TenantKey: "brand-a", Namespace: "STORE", ExternalID: "9"}})
		return nil, err
	}},
	{"iam/roles", func(_ *testing.T, c *Client, ctx context.Context) ([]*http.Request, error) {
		_, err := c.ListAppRoles(ctx, testMachineToken, PageParams{After: 4, Limit: 10})
		return nil, err
	}},
	{"iam/roles/create", func(_ *testing.T, c *Client, ctx context.Context) ([]*http.Request, error) {
		_, err := c.CreateAppRole(ctx, testMachineToken, RoleInput{Key: "reader", Name: "Reader", Description: "reads"})
		return nil, err
	}},
	{"iam/roles/delete", func(_ *testing.T, c *Client, ctx context.Context) ([]*http.Request, error) {
		_, err := c.DeleteAppRole(ctx, testMachineToken, 5)
		return nil, err
	}},
	{"iam/roles/{id}/permissions", func(_ *testing.T, c *Client, ctx context.Context) ([]*http.Request, error) {
		_, err := c.LinkRolePermission(ctx, testMachineToken, 5, 6)
		return nil, err
	}},
	{"iam/roles/{id}/permissions/{permission_id}", func(_ *testing.T, c *Client, ctx context.Context) ([]*http.Request, error) {
		_, err := c.UnlinkRolePermission(ctx, testMachineToken, 5, 6)
		return nil, err
	}},
	{"iam/permissions", func(_ *testing.T, c *Client, ctx context.Context) ([]*http.Request, error) {
		_, err := c.ListAppPermissions(ctx, testMachineToken, PageParams{Limit: 10})
		return nil, err
	}},
	{"iam/permissions/create", func(_ *testing.T, c *Client, ctx context.Context) ([]*http.Request, error) {
		_, err := c.CreateAppPermission(ctx, testMachineToken, PermissionInput{Key: "order.read", Name: "Read orders"})
		return nil, err
	}},
	{"iam/permissions/update", func(_ *testing.T, c *Client, ctx context.Context) ([]*http.Request, error) {
		_, err := c.UpdateAppPermission(ctx, testMachineToken, 6, PermissionInput{Key: "order.read", Name: "Renamed"})
		return nil, err
	}},
	{"iam/permissions/delete", func(_ *testing.T, c *Client, ctx context.Context) ([]*http.Request, error) {
		_, err := c.DeleteAppPermission(ctx, testMachineToken, 6)
		return nil, err
	}},
	{"iam/users/{id}/roles", func(_ *testing.T, c *Client, ctx context.Context) ([]*http.Request, error) {
		_, err := c.GrantUserRole(ctx, testMachineToken, 7, RoleGrant{RoleID: 5})
		return nil, err
	}},
	{"iam/users/{id}/roles/{role_id}", func(_ *testing.T, c *Client, ctx context.Context) ([]*http.Request, error) {
		_, err := c.RevokeUserRole(ctx, testMachineToken, 7, 5)
		return nil, err
	}},
	{"iam/groups/{id}/roles", func(_ *testing.T, c *Client, ctx context.Context) ([]*http.Request, error) {
		_, err := c.GrantGroupRole(ctx, testMachineToken, 8, RoleGrant{RoleID: 5})
		return nil, err
	}},
	{"iam/groups/{id}/roles/{role_id}", func(_ *testing.T, c *Client, ctx context.Context) ([]*http.Request, error) {
		_, err := c.RevokeGroupRole(ctx, testMachineToken, 8, 5)
		return nil, err
	}},
	{"iam/users/{id}/permissions", func(_ *testing.T, c *Client, ctx context.Context) ([]*http.Request, error) {
		_, err := c.GetUserPermissions(ctx, testMachineToken, 7)
		return nil, err
	}},
	{"events", func(_ *testing.T, c *Client, ctx context.Context) ([]*http.Request, error) {
		_, err := c.PullEvents(ctx, testMachineToken, PullEventsParams{
			After: 12, Limit: 10, Types: []EventType{EventUserUpdated, EventSessionRevoked, EventExternalIdentityChanged},
		})
		return nil, err
	}},
	{"audit/events", func(_ *testing.T, c *Client, ctx context.Context) ([]*http.Request, error) {
		_, err := c.ListAuditEvents(ctx, testMachineToken, ListAuditEventsParams{
			Before: 100, Limit: 10, Action: "app_role_save", Outcome: AuditOutcomeSuccess,
			TargetType: "role", TargetID: 5,
		})
		return nil, err
	}},
	{"audit/usage", func(_ *testing.T, c *Client, ctx context.Context) ([]*http.Request, error) {
		_, err := c.ReadAuditUsage(ctx, testMachineToken, 7)
		return nil, err
	}},
}

// excludedOperations are operations the SDK deliberately does not call, each
// with the reason it stays out of scope. A new server operation must be either
// exercised above or added here with a reason.
var excludedOperations = map[string]string{
	// The administrative surface is reachable only from an administrator's
	// browser session with CSRF protection, never with application credentials.
	"getOpenAPISettings":              "administrator browser session",
	"saveOpenAPISettings":             "administrator browser session",
	"listOpenAPICredentials":          "administrator browser session",
	"mintOpenAPICredential":           "administrator browser session",
	"retireOpenAPICredential":         "administrator browser session",
	"revokeOpenAPICredential":         "administrator browser session",
	"emergencyRevokeOpenAPI":          "administrator browser session",
	"listWebhookSubscriptions":        "administrator browser session",
	"createWebhookSubscription":       "administrator browser session",
	"deleteWebhookSubscription":       "administrator browser session",
	"rotateWebhookSubscriptionSecret": "administrator browser session",
	"setWebhookSubscriptionState":     "administrator browser session",
	"listWebhookDeliveries":           "administrator browser session",
	"replayWebhookDelivery":           "administrator browser session",
	"listAuthorizationSessions":       "administrator browser session",
	"revokeAuthorizationSession":      "administrator browser session",
	"revokeAllAuthorizationSessions":  "administrator browser session",
	// SAML is a browser protocol between the relying party's users and this
	// deployment, configured from the same administrator session.
	"samlSettingsGet":  "administrator browser session",
	"samlSettingsPost": "administrator browser session",
	"samlMetadata":     "SAML browser protocol",
	"samlSSOGet":       "SAML browser protocol",
	"samlSSOPost":      "SAML browser protocol",
	"samlContinue":     "SAML browser protocol",
	// Aliases the SDK deliberately does not use.
	"getOpenIDConfiguration": "equivalent alias of the standard discovery URL",
	"postUserInfo":           "equivalent alias of the GET userinfo read",
}

// contractResponses holds one valid answer per exercised path. The token
// endpoint answers per grant, because the two token kinds differ.
var contractResponses = map[string]string{
	"POST " + apiPath + "/directory/external-identities/lookup": `{"data":[{"identity":{"provider":"YOUZAN","tenant_id":"tenant-1","namespace":"SALESMAN","external_id":"staff-9"},"binding":null}],"request_id":"r"}`,
	"POST " + apiPath + "/directory/users/external-identities":  `{"data":[{"user_id":7,"enabled":false,"identities":[]}],"request_id":"r"}`,
	"GET " + apiPath + "/leave/users/7":                         `{"data":{"user_id":7,"on_leave":null,"synced_at":null,"records":[],"balances":[]},"request_id":"r"}`,
	"GET " + apiPath + "/stores":                                `{"data":{"items":[],"next":"","has_more":false},"request_id":"r"}`,
	"GET " + apiPath + "/stores/101":                            `{"data":{"id":101,"brand_id":3,"code":"SH001","name":"上海门店","status":"open","location":"上海","version":1},"request_id":"r"}`,
	"GET " + apiPath + "/stores/101/receiving-address":          `{"data":null,"request_id":"r"}`,
	"GET " + apiPath + "/stores/101/employees":                  `{"data":{"items":[],"evaluated_at":"2026-10-04T10:00:00Z","next_change_at":null},"request_id":"r"}`,
	"GET " + apiPath + "/directory/users/7/stores":              `{"data":{"user_id":7,"primary_store":null,"secondments":[],"other_relations":[],"evaluated_at":"2026-10-04T10:00:00Z","next_change_at":null},"request_id":"r"}`,
	"POST " + apiPath + "/stores/external-identities/lookup":    `{"data":[{"identity":{"provider":"YOUZAN","tenant_key":"brand-a","namespace":"STORE","external_id":"9"},"binding":null}],"request_id":"r"}`,

	"GET /.well-known/openid-configuration":               `{"issuer":"https://auth.example.com","authorization_endpoint":"https://auth.example.com/openapi/v1/oauth/authorize","token_endpoint":"https://auth.example.com/openapi/v1/oauth/token","userinfo_endpoint":"https://auth.example.com/openapi/v1/userinfo","end_session_endpoint":"https://auth.example.com/openapi/v1/oauth/logout","jwks_uri":"https://auth.example.com/openapi/v1/.well-known/jwks.json","scopes_supported":["profile:read"],"response_types_supported":["code"],"id_token_signing_alg_values_supported":["RS256"]}`,
	"GET " + apiPath + jwksPath:                           `{"keys":[{"kty":"RSA","use":"sig","alg":"RS256","kid":"k1","n":"AQAB","e":"AQAB"}]}`,
	"POST " + apiPath + "/oauth/revoke":                   ``,
	"POST " + apiPath + "/oauth/introspect":               `{"active":true,"exp":1893456000,"sub":"7","client_id":"42","aud":["42"],"username":"alice","scope":"profile:read","token_type":"Bearer","subject_kind":"user"}`,
	"GET " + apiPath + "/userinfo":                        `{"sub":"7","name":"Alice"}`,
	"GET " + apiPath + "/me":                              `{"data":{"id":7,"username":"alice","name":"Alice","avatar":"","hire_date":null,"hire_date_source":"","probation_months":null,"regularization_date":null},"request_id":"r"}`,
	"GET " + apiPath + "/me/permissions":                  `{"data":{"app_id":42,"user_id":7,"roles":[],"permissions":["order.read"],"evaluated_at":"2026-09-30T10:00:00Z","next_change_at":null},"request_id":"r"}`,
	"POST " + apiPath + "/me/permissions/check":           `{"data":{"allowed":true,"evaluated_at":"2026-09-30T10:00:00Z","next_change_at":null},"request_id":"r"}`,
	"POST " + apiPath + "/me/permissions/check-batch":     `{"data":{"results":[{"allowed":true,"evaluated_at":"2026-09-30T10:00:00Z","next_change_at":null}],"evaluated_at":"2026-09-30T10:00:00Z","next_change_at":null},"request_id":"r"}`,
	"GET " + apiPath + "/machine/me":                      `{"data":{"app_id":42,"subject":"machine","scopes":["directory:read"],"credential_id":3},"request_id":"r"}`,
	"GET " + apiPath + "/machine/me/permissions":          `{"data":{"app_id":42,"scopes":["directory:read"]},"request_id":"r"}`,
	"GET " + apiPath + "/directory/users":                 `{"data":{"items":[],"next":0},"request_id":"r"}`,
	"GET " + apiPath + "/directory/users/7":               `{"data":{"id":7,"username":"alice","name":"Alice","avatar":"","departments":[],"groups":[]},"request_id":"r"}`,
	"GET " + apiPath + "/directory/users/7/departments":   `{"data":[],"request_id":"r"}`,
	"GET " + apiPath + "/directory/users/7/groups":        `{"data":[],"request_id":"r"}`,
	"GET " + apiPath + "/directory/departments":           `{"data":[],"request_id":"r"}`,
	"GET " + apiPath + "/directory/departments/9/members": `{"data":{"items":[],"next":0},"request_id":"r"}`,
	"GET " + apiPath + "/directory/groups":                `{"data":[],"request_id":"r"}`,
	"GET " + apiPath + "/directory/groups/8/members":      `{"data":{"items":[],"next":0},"request_id":"r"}`,
	"GET " + apiPath + "/iam/roles":                       `{"data":{"items":[],"next":0},"request_id":"r"}`,
	"POST " + apiPath + "/iam/roles":                      `{"data":{"id":5},"request_id":"r"}`,
	"DELETE " + apiPath + "/iam/roles/5":                  `{"data":{"id":5},"request_id":"r"}`,
	"POST " + apiPath + "/iam/roles/5/permissions":        `{"data":{"id":5},"request_id":"r"}`,
	"DELETE " + apiPath + "/iam/roles/5/permissions/6":    `{"data":{"id":5},"request_id":"r"}`,
	"GET " + apiPath + "/iam/permissions":                 `{"data":{"items":[],"next":0},"request_id":"r"}`,
	"POST " + apiPath + "/iam/permissions":                `{"data":{"id":6},"request_id":"r"}`,
	"PATCH " + apiPath + "/iam/permissions/6":             `{"data":{"id":6},"request_id":"r"}`,
	"DELETE " + apiPath + "/iam/permissions/6":            `{"data":{"id":6},"request_id":"r"}`,
	"POST " + apiPath + "/iam/users/7/roles":              `{"data":{"id":7},"request_id":"r"}`,
	"DELETE " + apiPath + "/iam/users/7/roles/5":          `{"data":{"id":7},"request_id":"r"}`,
	"POST " + apiPath + "/iam/groups/8/roles":             `{"data":{"id":8},"request_id":"r"}`,
	"DELETE " + apiPath + "/iam/groups/8/roles/5":         `{"data":{"id":8},"request_id":"r"}`,
	"GET " + apiPath + "/iam/users/7/permissions":         `{"data":{"app_id":42,"user_id":7,"roles":[],"permissions":["order.read"],"sources":[],"evaluated_at":"2026-09-30T10:00:00Z","next_change_at":null},"request_id":"r"}`,
	"GET " + apiPath + "/events":                          `{"data":{"next":0,"events":[],"has_more":false},"request_id":"r"}`,
	"GET " + apiPath + "/audit/events":                    `{"data":{"items":[],"next":0},"request_id":"r"}`,
	"GET " + apiPath + "/audit/usage":                     `{"data":{"from":"2026-09-24T00:00:00Z","to":"2026-09-30T00:00:00Z","calls":0,"success":0,"failure":0,"buckets":[],"rate_limit":null,"latency":{"measured":0,"average_ms":0,"maximum_ms":0,"p95_upper_ms":0,"buckets":[]}},"request_id":"r"}`,
}

// contractResponse answers one mock request. The token endpoint is the one path
// whose answer depends on the grant that was requested.
func contractResponse(r *http.Request) (string, bool) {
	key := r.Method + " " + r.URL.Path
	if key != "POST "+apiPath+"/oauth/token" {
		body, ok := contractResponses[key]
		return body, ok
	}
	data, err := io.ReadAll(r.Body)
	if err != nil {
		return "", false
	}
	r.Body = io.NopCloser(bytes.NewReader(data))
	form, err := url.ParseQuery(string(data))
	if err != nil {
		return "", false
	}
	if form.Get("grant_type") == string(GrantClientCredentials) {
		return `{"access_token":"` + testMachineToken + `","token_type":"Bearer","expires_in":86400,"scope":"directory:read iam:read"}`, true
	}
	return `{"access_token":"` + testToken + `","token_type":"Bearer","expires_in":86400,"scope":"profile:read","refresh_token":"` + testRefreshToken + `"}`, true
}

func one(r *http.Request, err error) ([]*http.Request, error) {
	if err != nil {
		return nil, err
	}
	return []*http.Request{r}, nil
}

// synthetic turns an SDK-built URL or form into the request the browser or the
// caller would send, so it can be checked against the specification.
func synthetic(method, target string, form url.Values) (*http.Request, error) {
	var body io.Reader
	contentType := ""
	if form != nil {
		body = strings.NewReader(form.Encode())
		contentType = formContentType
	}
	r, err := http.NewRequest(method, target, body)
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	return r, nil
}
