package auth

import (
	"context"
	"net/http"
	"time"
	"unicode/utf8"
)

// checkPayload distinguishes a valid false decision and a missing evaluation
// instant from a malformed response.
type checkPayload struct {
	Allowed      *bool      `json:"allowed"`
	EvaluatedAt  *time.Time `json:"evaluated_at"`
	NextChangeAt *time.Time `json:"next_change_at"`
}

func (p checkPayload) check() (Check, error) {
	if p.Allowed == nil {
		return Check{}, invalidResponse("missing allowed decision")
	}
	if p.EvaluatedAt == nil {
		return Check{}, invalidResponse("missing evaluation instant")
	}
	return Check{Allowed: *p.Allowed, EvaluatedAt: *p.EvaluatedAt, NextChangeAt: p.NextChangeAt}, nil
}

func validPermissionKeyArgument(permission string) error {
	if !utf8.ValidString(permission) || utf8.RuneCountInString(permission) < 1 || utf8.RuneCountInString(permission) > 128 {
		return invalid("permission", "must contain 1–128 Unicode characters")
	}
	return nil
}

// GetCurrentUser reads the authorizing employee's minimal profile
// (profile:read). Only the fields of Profile are exposed: never the mobile
// number, the corporate mailbox or any other profile column.
func (c *Client) GetCurrentUser(ctx context.Context, accessToken string) (*ProfileResponse, error) {
	response, err := readResource[Profile](ctx, c, request{
		method: http.MethodGet, path: "/me", cred: credentialUserToken, token: accessToken,
	})
	if err != nil {
		return nil, err
	}
	if response.Data.ID <= 0 {
		return nil, invalidResponse("missing profile ID")
	}
	return response, nil
}

// GetCurrentPermissions reads the employee's effective roles and permissions in
// the token's application (permissions:read). Results are never cached by the
// SDK; the server re-checks the login admission rule on every call.
func (c *Client) GetCurrentPermissions(ctx context.Context, accessToken string) (*PermissionsResponse, error) {
	response, err := readResource[Permissions](ctx, c, request{
		method: http.MethodGet, path: "/me/permissions", cred: credentialUserToken, token: accessToken,
	})
	if err != nil {
		return nil, err
	}
	if response.Data.AppID <= 0 || response.Data.UserID <= 0 || response.Data.EvaluatedAt.IsZero() {
		return nil, invalidResponse("missing application, user or evaluation instant")
	}
	return response, nil
}

// CheckCurrentPermission answers whether the employee holds one permission
// (permissions:check). A well-formed key the employee does not hold returns
// Allowed false; the server remains authoritative for permission-key syntax and
// application boundaries.
func (c *Client) CheckCurrentPermission(ctx context.Context, accessToken, permission string) (*CheckResponse, error) {
	if err := validPermissionKeyArgument(permission); err != nil {
		return nil, err
	}
	body, err := jsonBody(struct {
		Permission string `json:"permission"`
	}{permission})
	if err != nil {
		return nil, err
	}
	response, err := readResource[checkPayload](ctx, c, request{
		method: http.MethodPost, path: "/me/permissions/check",
		contentType: jsonContentType, body: body,
		cred: credentialUserToken, token: accessToken,
	})
	if err != nil {
		return nil, err
	}
	check, err := response.Data.check()
	if err != nil {
		return nil, err
	}
	return &CheckResponse{Data: check, RequestID: response.RequestID}, nil
}

// CheckCurrentPermissions answers up to MaxBatchChecks permission questions
// against one authorization snapshot (permissions:check). Every requested key
// appears exactly once and in request order, and every answer describes the
// same database state.
func (c *Client) CheckCurrentPermissions(ctx context.Context, accessToken string, permissions ...string) (*BatchCheckResponse, error) {
	if len(permissions) == 0 || len(permissions) > MaxBatchChecks {
		return nil, invalid("permissions", "must contain one to 100 keys")
	}
	for _, permission := range permissions {
		if err := validPermissionKeyArgument(permission); err != nil {
			return nil, err
		}
	}
	body, err := jsonBody(struct {
		Permissions []string `json:"permissions"`
	}{permissions})
	if err != nil {
		return nil, err
	}
	response, err := readResource[struct {
		Results      []checkPayload `json:"results"`
		EvaluatedAt  *time.Time     `json:"evaluated_at"`
		NextChangeAt *time.Time     `json:"next_change_at"`
	}](ctx, c, request{
		method: http.MethodPost, path: "/me/permissions/check-batch",
		contentType: jsonContentType, body: body,
		cred: credentialUserToken, token: accessToken,
	})
	if err != nil {
		return nil, err
	}
	if response.Data.EvaluatedAt == nil {
		return nil, invalidResponse("missing evaluation instant")
	}
	results := make([]Check, 0, len(response.Data.Results))
	for _, payload := range response.Data.Results {
		check, err := payload.check()
		if err != nil {
			return nil, err
		}
		results = append(results, check)
	}
	batch := BatchCheck{Results: results, EvaluatedAt: *response.Data.EvaluatedAt, NextChangeAt: response.Data.NextChangeAt}
	return &BatchCheckResponse{Data: batch, RequestID: response.RequestID}, nil
}

// GetMachineIdentity reads the identity of the machine token's application. It
// needs no machine scope: a machine may always describe itself.
func (c *Client) GetMachineIdentity(ctx context.Context, machineToken string) (*MachineIdentityResponse, error) {
	response, err := readResource[MachineIdentity](ctx, c, request{
		method: http.MethodGet, path: "/machine/me", cred: credentialMachineToken, token: machineToken,
	})
	if err != nil {
		return nil, err
	}
	if response.Data.AppID <= 0 || response.Data.Scopes == nil {
		return nil, invalidResponse("missing machine application or scopes")
	}
	return response, nil
}

// GetMachineScopes reads the machine scopes the presented token currently
// carries. It needs no machine scope.
func (c *Client) GetMachineScopes(ctx context.Context, machineToken string) (*MachineScopesResponse, error) {
	response, err := readResource[MachineScopes](ctx, c, request{
		method: http.MethodGet, path: "/machine/me/permissions", cred: credentialMachineToken, token: machineToken,
	})
	if err != nil {
		return nil, err
	}
	if response.Data.AppID <= 0 || response.Data.Scopes == nil {
		return nil, invalidResponse("missing machine application or scopes")
	}
	return response, nil
}
