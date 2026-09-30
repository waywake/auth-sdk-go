package auth

import (
	"context"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	maxRoleKeyRunes     = 45
	maxNameRunes        = 128
	maxDescriptionRunes = 255
)

var permissionKeyExpr = regexp.MustCompile(`^[a-z][a-z0-9_.:-]{0,127}$`)

// RoleInput is one role owned by the calling application. The key is the
// immutable functional identifier; the name and description are free text.
type RoleInput struct {
	Key         string
	Name        string
	Description string
}

// PermissionInput is one permission point owned by the calling application. The
// key is immutable, so a rename cannot silently change what an already-issued
// credential refers to.
type PermissionInput struct {
	Key         string
	Name        string
	Description string
}

// RoleGrant authorizes one of the application's roles. ExpiresAt is optional: a
// nil value grants permanently, and a past instant is rejected by the server.
type RoleGrant struct {
	RoleID    int64
	ExpiresAt *time.Time
}

func validText(field, value string, maxRunes int) error {
	if !utf8.ValidString(value) || utf8.RuneCountInString(value) > maxRunes {
		return invalid(field, "must contain at most "+strconv.Itoa(maxRunes)+" characters")
	}
	return nil
}

func validateRoleInput(input RoleInput) error {
	key := strings.TrimSpace(input.Key)
	if key == "" || utf8.RuneCountInString(key) > maxRoleKeyRunes {
		return invalid("Key", "must contain 1–45 characters")
	}
	if err := validText("Name", input.Name, maxNameRunes); err != nil {
		return err
	}
	return validText("Description", input.Description, maxDescriptionRunes)
}

func validatePermissionInput(input PermissionInput) error {
	if !permissionKeyExpr.MatchString(input.Key) {
		return invalid("Key", "must start with a lowercase letter and contain at most 128 characters from a-z0-9_.:-")
	}
	if err := validText("Name", input.Name, maxNameRunes); err != nil {
		return err
	}
	return validText("Description", input.Description, maxDescriptionRunes)
}

// ListAppRoles lists the roles owned by the calling application (iam:read). The
// owning application always comes from the machine token; no request can name
// another one.
func (c *Client) ListAppRoles(ctx context.Context, machineToken string, params PageParams) (*AppRolePageResponse, error) {
	query, err := params.query()
	if err != nil {
		return nil, err
	}
	response, err := readResource[Page[AppRole]](ctx, c, request{
		method: http.MethodGet, path: "/iam/roles", query: query,
		cred: credentialMachineToken, token: machineToken,
	})
	if err != nil {
		return nil, err
	}
	if err := ensureNotNilItems(response.Data.Items); err != nil {
		return nil, err
	}
	return response, nil
}

// CreateAppRole creates a role owned by the calling application (iam:write).
func (c *Client) CreateAppRole(ctx context.Context, machineToken string, input RoleInput) (*IDResponse, error) {
	if err := validateRoleInput(input); err != nil {
		return nil, err
	}
	return c.iamWrite(ctx, machineToken, http.MethodPost, "/iam/roles", struct {
		Key         string `json:"key"`
		Name        string `json:"name"`
		Description string `json:"description"`
	}{input.Key, input.Name, input.Description})
}

// DeleteAppRole deletes one role owned by the calling application
// (iam:write). A role another application owns answers not_found: the caller
// cannot tell it apart from a role that does not exist.
func (c *Client) DeleteAppRole(ctx context.Context, machineToken string, roleID int64) (*IDResponse, error) {
	if err := validID("roleID", roleID); err != nil {
		return nil, err
	}
	return c.iamWrite(ctx, machineToken, http.MethodDelete, "/iam/roles/"+strconv.FormatInt(roleID, 10), nil)
}

// ListAppPermissions lists the permission points owned by the calling
// application (iam:read).
func (c *Client) ListAppPermissions(ctx context.Context, machineToken string, params PageParams) (*AppPermissionPageResponse, error) {
	query, err := params.query()
	if err != nil {
		return nil, err
	}
	response, err := readResource[Page[AppPermission]](ctx, c, request{
		method: http.MethodGet, path: "/iam/permissions", query: query,
		cred: credentialMachineToken, token: machineToken,
	})
	if err != nil {
		return nil, err
	}
	if err := ensureNotNilItems(response.Data.Items); err != nil {
		return nil, err
	}
	return response, nil
}

// CreateAppPermission creates a permission point owned by the calling
// application (iam:write).
func (c *Client) CreateAppPermission(ctx context.Context, machineToken string, input PermissionInput) (*IDResponse, error) {
	if err := validatePermissionInput(input); err != nil {
		return nil, err
	}
	return c.iamWrite(ctx, machineToken, http.MethodPost, "/iam/permissions", struct {
		Key         string `json:"key"`
		Name        string `json:"name"`
		Description string `json:"description"`
	}{input.Key, input.Name, input.Description})
}

// UpdateAppPermission renames one permission point owned by the calling
// application (iam:write).
func (c *Client) UpdateAppPermission(ctx context.Context, machineToken string, permissionID int64, input PermissionInput) (*IDResponse, error) {
	if err := validID("permissionID", permissionID); err != nil {
		return nil, err
	}
	if err := validatePermissionInput(input); err != nil {
		return nil, err
	}
	return c.iamWrite(ctx, machineToken, http.MethodPatch, "/iam/permissions/"+strconv.FormatInt(permissionID, 10), struct {
		Key         string `json:"key"`
		Name        string `json:"name"`
		Description string `json:"description"`
	}{input.Key, input.Name, input.Description})
}

// DeleteAppPermission deletes one permission point owned by the calling
// application (iam:write).
func (c *Client) DeleteAppPermission(ctx context.Context, machineToken string, permissionID int64) (*IDResponse, error) {
	if err := validID("permissionID", permissionID); err != nil {
		return nil, err
	}
	return c.iamWrite(ctx, machineToken, http.MethodDelete, "/iam/permissions/"+strconv.FormatInt(permissionID, 10), nil)
}

// LinkRolePermission attaches one of the application's permission points to one
// of its roles (iam:write).
func (c *Client) LinkRolePermission(ctx context.Context, machineToken string, roleID, permissionID int64) (*IDResponse, error) {
	if err := validID("roleID", roleID); err != nil {
		return nil, err
	}
	if err := validID("permissionID", permissionID); err != nil {
		return nil, err
	}
	return c.iamWrite(ctx, machineToken, http.MethodPost, "/iam/roles/"+strconv.FormatInt(roleID, 10)+"/permissions", struct {
		PermissionID int64 `json:"permission_id"`
	}{permissionID})
}

// UnlinkRolePermission detaches one permission point from one role
// (iam:write).
func (c *Client) UnlinkRolePermission(ctx context.Context, machineToken string, roleID, permissionID int64) (*IDResponse, error) {
	if err := validID("roleID", roleID); err != nil {
		return nil, err
	}
	if err := validID("permissionID", permissionID); err != nil {
		return nil, err
	}
	path := "/iam/roles/" + strconv.FormatInt(roleID, 10) + "/permissions/" + strconv.FormatInt(permissionID, 10)
	return c.iamWrite(ctx, machineToken, http.MethodDelete, path, nil)
}

// GrantUserRole authorizes one of the application's roles to one in-scope
// employee (iam:write). The employee must be inside the configured directory
// range, so an application can only authorize people the administrator already
// made visible to it.
func (c *Client) GrantUserRole(ctx context.Context, machineToken string, userID int64, grant RoleGrant) (*IDResponse, error) {
	if err := validID("userID", userID); err != nil {
		return nil, err
	}
	if err := validID("RoleID", grant.RoleID); err != nil {
		return nil, err
	}
	return c.iamWrite(ctx, machineToken, http.MethodPost, "/iam/users/"+strconv.FormatInt(userID, 10)+"/roles", grantBody(grant))
}

// RevokeUserRole removes one of the application's authorizations from one
// employee (iam:write). A revocation is allowed to clean up an employee who is
// no longer in range or is disabled, so a narrowing configuration never strands
// an authorization nobody can remove.
func (c *Client) RevokeUserRole(ctx context.Context, machineToken string, userID, roleID int64) (*IDResponse, error) {
	if err := validID("userID", userID); err != nil {
		return nil, err
	}
	if err := validID("roleID", roleID); err != nil {
		return nil, err
	}
	path := "/iam/users/" + strconv.FormatInt(userID, 10) + "/roles/" + strconv.FormatInt(roleID, 10)
	return c.iamWrite(ctx, machineToken, http.MethodDelete, path, nil)
}

// GrantGroupRole authorizes one of the application's roles to one approved user
// group (iam:write). The group must be inside the configured directory range:
// the range is the approval.
func (c *Client) GrantGroupRole(ctx context.Context, machineToken string, groupID int64, grant RoleGrant) (*IDResponse, error) {
	if err := validID("groupID", groupID); err != nil {
		return nil, err
	}
	if err := validID("RoleID", grant.RoleID); err != nil {
		return nil, err
	}
	return c.iamWrite(ctx, machineToken, http.MethodPost, "/iam/groups/"+strconv.FormatInt(groupID, 10)+"/roles", grantBody(grant))
}

// RevokeGroupRole removes one of the application's group authorizations
// (iam:write).
func (c *Client) RevokeGroupRole(ctx context.Context, machineToken string, groupID, roleID int64) (*IDResponse, error) {
	if err := validID("groupID", groupID); err != nil {
		return nil, err
	}
	if err := validID("roleID", roleID); err != nil {
		return nil, err
	}
	path := "/iam/groups/" + strconv.FormatInt(groupID, 10) + "/roles/" + strconv.FormatInt(roleID, 10)
	return c.iamWrite(ctx, machineToken, http.MethodDelete, path, nil)
}

// GetUserPermissions explains one in-scope employee's effective permissions in
// this application, including where each authorization came from (iam:read).
// An employee outside the range answers insufficient_scope.
func (c *Client) GetUserPermissions(ctx context.Context, machineToken string, userID int64) (*PermissionExplanationResponse, error) {
	if err := validID("userID", userID); err != nil {
		return nil, err
	}
	response, err := readResource[PermissionExplanation](ctx, c, request{
		method: http.MethodGet, path: "/iam/users/" + strconv.FormatInt(userID, 10) + "/permissions",
		cred: credentialMachineToken, token: machineToken,
	})
	if err != nil {
		return nil, err
	}
	explanation := response.Data
	if explanation.AppID <= 0 || explanation.UserID <= 0 || explanation.EvaluatedAt.IsZero() {
		return nil, invalidResponse("missing application, user or evaluation instant")
	}
	if explanation.Roles == nil || explanation.Permissions == nil || explanation.Sources == nil {
		return nil, invalidResponse("missing effective authorization lists")
	}
	return response, nil
}

func grantBody(grant RoleGrant) struct {
	RoleID    int64      `json:"role_id"`
	ExpiresAt *time.Time `json:"expires_at"`
} {
	return struct {
		RoleID    int64      `json:"role_id"`
		ExpiresAt *time.Time `json:"expires_at"`
	}{grant.RoleID, grant.ExpiresAt}
}

// iamWrite performs one machine IAM write and decodes the identifier it
// returns. The owning application always comes from the token.
func (c *Client) iamWrite(ctx context.Context, machineToken, method, path string, payload any) (*IDResponse, error) {
	req := request{method: method, path: path, cred: credentialMachineToken, token: machineToken}
	if payload != nil {
		body, err := jsonBody(payload)
		if err != nil {
			return nil, err
		}
		req.contentType, req.body = jsonContentType, body
	}
	response, err := readResource[ID](ctx, c, req)
	if err != nil {
		return nil, err
	}
	if response.Data.ID <= 0 {
		return nil, invalidResponse("missing object ID")
	}
	return response, nil
}
