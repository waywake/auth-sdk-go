package auth

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"unicode/utf8"
)

// PageParams is the shared keyset cursor of every listing endpoint. After is
// the previous page's Next (zero starts from the beginning) and Limit is the
// page size, 1 to MaxPageSize; zero selects the server default.
type PageParams struct {
	After int64
	Limit int
}

func (p PageParams) query() (url.Values, error) { return pageQuery(p.After, p.Limit) }

// ListDirectoryUsersParams narrows the directory listing. DepartmentID and
// GroupID must name objects inside the application's configured directory
// range; a filter outside it is answered from the scope itself, so the caller
// learns nothing about whether such an object exists.
type ListDirectoryUsersParams struct {
	PageParams
	DepartmentID int64
	GroupID      int64
	// Search is a substring match on the account name or the display name, at
	// most 64 characters.
	Search string
}

// ListDirectoryUsers lists the employees inside the configured directory range
// (directory:read). An application that was never granted a directory scope
// reads nobody.
func (c *Client) ListDirectoryUsers(ctx context.Context, machineToken string, params ListDirectoryUsersParams) (*DirectoryUserPageResponse, error) {
	query, err := params.PageParams.query()
	if err != nil {
		return nil, err
	}
	if params.DepartmentID < 0 || params.GroupID < 0 {
		return nil, invalid("DepartmentID/GroupID", "must not be negative")
	}
	if params.DepartmentID > 0 {
		query.Set("department_id", strconv.FormatInt(params.DepartmentID, 10))
	}
	if params.GroupID > 0 {
		query.Set("group_id", strconv.FormatInt(params.GroupID, 10))
	}
	if params.Search != "" {
		if !utf8.ValidString(params.Search) || utf8.RuneCountInString(params.Search) > 64 {
			return nil, invalid("Search", "must contain at most 64 characters")
		}
		query.Set("search", params.Search)
	}
	response, err := readResource[Page[DirectoryUser]](ctx, c, request{
		method: http.MethodGet, path: "/directory/users", query: query,
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

// GetDirectoryUser reads one employee inside the configured directory range
// (directory:read). An employee outside the range answers not_found rather than
// an empty object, so the endpoint never confirms that an unreachable employee
// exists.
func (c *Client) GetDirectoryUser(ctx context.Context, machineToken string, userID int64) (*DirectoryUserResponse, error) {
	if err := validID("userID", userID); err != nil {
		return nil, err
	}
	response, err := readResource[DirectoryUser](ctx, c, request{
		method: http.MethodGet, path: "/directory/users/" + strconv.FormatInt(userID, 10),
		cred: credentialMachineToken, token: machineToken,
	})
	if err != nil {
		return nil, err
	}
	if response.Data.ID <= 0 {
		return nil, invalidResponse("missing employee ID")
	}
	return response, nil
}

// ListDirectoryUserDepartments lists one employee's in-scope department
// relations (directory:read). Relations outside the configured range are
// omitted rather than reported.
func (c *Client) ListDirectoryUserDepartments(ctx context.Context, machineToken string, userID int64) (*DepartmentRefListResponse, error) {
	if err := validID("userID", userID); err != nil {
		return nil, err
	}
	response, err := readResource[[]DepartmentRef](ctx, c, request{
		method: http.MethodGet, path: "/directory/users/" + strconv.FormatInt(userID, 10) + "/departments",
		cred: credentialMachineToken, token: machineToken,
	})
	if err != nil {
		return nil, err
	}
	if response.Data == nil {
		return nil, invalidResponse("missing department list")
	}
	return response, nil
}

// ListDirectoryUserGroups lists one employee's in-scope user-group relations
// (directory:read). Relations outside the configured range are omitted rather
// than reported.
func (c *Client) ListDirectoryUserGroups(ctx context.Context, machineToken string, userID int64) (*GroupRefListResponse, error) {
	if err := validID("userID", userID); err != nil {
		return nil, err
	}
	response, err := readResource[[]GroupRef](ctx, c, request{
		method: http.MethodGet, path: "/directory/users/" + strconv.FormatInt(userID, 10) + "/groups",
		cred: credentialMachineToken, token: machineToken,
	})
	if err != nil {
		return nil, err
	}
	if response.Data == nil {
		return nil, invalidResponse("missing group list")
	}
	return response, nil
}

// ListDirectoryDepartments lists the departments inside the configured range
// (directory:read). A configured department carries every descendant, and a
// parent outside the range is reported as a root, so the identifier of an
// unreadable department is never leaked.
func (c *Client) ListDirectoryDepartments(ctx context.Context, machineToken string) (*DepartmentListResponse, error) {
	response, err := readResource[[]Department](ctx, c, request{
		method: http.MethodGet, path: "/directory/departments",
		cred: credentialMachineToken, token: machineToken,
	})
	if err != nil {
		return nil, err
	}
	if response.Data == nil {
		return nil, invalidResponse("missing department list")
	}
	return response, nil
}

// ListDirectoryGroups lists the user groups inside the configured directory
// range (directory:read).
func (c *Client) ListDirectoryGroups(ctx context.Context, machineToken string, params PageParams) (*GroupListResponse, error) {
	query, err := params.query()
	if err != nil {
		return nil, err
	}
	response, err := readResource[[]Group](ctx, c, request{
		method: http.MethodGet, path: "/directory/groups", query: query,
		cred: credentialMachineToken, token: machineToken,
	})
	if err != nil {
		return nil, err
	}
	if response.Data == nil {
		return nil, invalidResponse("missing group list")
	}
	return response, nil
}

// ListDirectoryDepartmentMembers lists the employees of one in-scope
// department (directory:read). Only the department's own members are listed; a
// descendant's members belong to that descendant.
func (c *Client) ListDirectoryDepartmentMembers(ctx context.Context, machineToken string, departmentID int64, params PageParams) (*DirectoryUserPageResponse, error) {
	if err := validID("departmentID", departmentID); err != nil {
		return nil, err
	}
	query, err := params.query()
	if err != nil {
		return nil, err
	}
	response, err := readResource[Page[DirectoryUser]](ctx, c, request{
		method: http.MethodGet, path: "/directory/departments/" + strconv.FormatInt(departmentID, 10) + "/members",
		query: query, cred: credentialMachineToken, token: machineToken,
	})
	if err != nil {
		return nil, err
	}
	if err := ensureNotNilItems(response.Data.Items); err != nil {
		return nil, err
	}
	return response, nil
}

// ListDirectoryGroupMembers lists the employees of one in-scope user group
// (directory:read).
func (c *Client) ListDirectoryGroupMembers(ctx context.Context, machineToken string, groupID int64, params PageParams) (*DirectoryUserPageResponse, error) {
	if err := validID("groupID", groupID); err != nil {
		return nil, err
	}
	query, err := params.query()
	if err != nil {
		return nil, err
	}
	response, err := readResource[Page[DirectoryUser]](ctx, c, request{
		method: http.MethodGet, path: "/directory/groups/" + strconv.FormatInt(groupID, 10) + "/members",
		query: query, cred: credentialMachineToken, token: machineToken,
	})
	if err != nil {
		return nil, err
	}
	if err := ensureNotNilItems(response.Data.Items); err != nil {
		return nil, err
	}
	return response, nil
}
