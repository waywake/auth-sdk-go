package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"unicode/utf8"
)

// GetCurrentUser reads the authorized user's minimal profile (profile:read).
func (c *Client) GetCurrentUser(ctx context.Context, accessToken string) (*ProfileResponse, error) {
	response, err := readResource[Profile](ctx, c, http.MethodGet, "/me", "", "", accessToken)
	if err != nil {
		return nil, err
	}
	if response.Data.ID <= 0 {
		return nil, fmt.Errorf("%w: missing profile ID", ErrInvalidResponse)
	}
	return response, nil
}

// GetCurrentPermissions reads current roles and permissions in the token's
// application (permissions:read). Results are never cached by the SDK.
func (c *Client) GetCurrentPermissions(ctx context.Context, accessToken string) (*PermissionsResponse, error) {
	response, err := readResource[Permissions](ctx, c, http.MethodGet, "/me/permissions", "", "", accessToken)
	if err != nil {
		return nil, err
	}
	if response.Data.AppID <= 0 || response.Data.UserID <= 0 {
		return nil, fmt.Errorf("%w: missing application or user ID", ErrInvalidResponse)
	}
	return response, nil
}

// CheckCurrentPermission checks a live permission decision (permissions:check).
// A valid but nonexistent permission produces Allowed=false. The server remains
// authoritative for permission-key syntax and application boundaries.
func (c *Client) CheckCurrentPermission(ctx context.Context, accessToken, permission string) (*CheckResponse, error) {
	if !utf8.ValidString(permission) || utf8.RuneCountInString(permission) < 1 || utf8.RuneCountInString(permission) > 128 {
		return nil, invalid("permission", "must contain 1–128 Unicode characters")
	}
	input := struct {
		Permission string `json:"permission"`
	}{permission}
	body, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	// A pointer distinguishes a valid false decision from a malformed response.
	response, err := readResource[struct {
		Allowed *bool `json:"allowed"`
	}](ctx, c,
		http.MethodPost, "/me/permissions/check", "application/json", string(body), accessToken)
	if err != nil {
		return nil, err
	}
	if response.Data.Allowed == nil {
		return nil, fmt.Errorf("%w: missing allowed decision", ErrInvalidResponse)
	}
	return &CheckResponse{Data: Check{Allowed: *response.Data.Allowed}, RequestID: response.RequestID}, nil
}
