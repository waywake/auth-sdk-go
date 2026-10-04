package auth

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestIAMWrites(t *testing.T) {
	cases := []struct {
		name   string
		method string
		path   string
		body   string
		call   func(*Client) (*IDResponse, error)
	}{
		{
			"create role", http.MethodPost, apiPath + "/iam/roles",
			`{"key":"reader","name":"Reader","description":"reads orders"}`,
			func(c *Client) (*IDResponse, error) {
				return c.CreateAppRole(context.Background(), testMachineToken, RoleInput{Key: "reader", Name: "Reader", Description: "reads orders"})
			},
		},
		{
			"delete role", http.MethodDelete, apiPath + "/iam/roles/5", "",
			func(c *Client) (*IDResponse, error) {
				return c.DeleteAppRole(context.Background(), testMachineToken, 5)
			},
		},
		{
			"create permission", http.MethodPost, apiPath + "/iam/permissions",
			`{"key":"order.read","name":"Read orders","description":""}`,
			func(c *Client) (*IDResponse, error) {
				return c.CreateAppPermission(context.Background(), testMachineToken, PermissionInput{Key: "order.read", Name: "Read orders"})
			},
		},
		{
			"update permission", http.MethodPatch, apiPath + "/iam/permissions/6",
			`{"key":"order.read","name":"Renamed","description":""}`,
			func(c *Client) (*IDResponse, error) {
				return c.UpdateAppPermission(context.Background(), testMachineToken, 6, PermissionInput{Key: "order.read", Name: "Renamed"})
			},
		},
		{
			"delete permission", http.MethodDelete, apiPath + "/iam/permissions/6", "",
			func(c *Client) (*IDResponse, error) {
				return c.DeleteAppPermission(context.Background(), testMachineToken, 6)
			},
		},
		{
			"link role permission", http.MethodPost, apiPath + "/iam/roles/5/permissions",
			`{"permission_id":6}`,
			func(c *Client) (*IDResponse, error) {
				return c.LinkRolePermission(context.Background(), testMachineToken, 5, 6)
			},
		},
		{
			"unlink role permission", http.MethodDelete, apiPath + "/iam/roles/5/permissions/6", "",
			func(c *Client) (*IDResponse, error) {
				return c.UnlinkRolePermission(context.Background(), testMachineToken, 5, 6)
			},
		},
		{
			"grant user role", http.MethodPost, apiPath + "/iam/users/7/roles",
			`{"role_id":5,"expires_at":null}`,
			func(c *Client) (*IDResponse, error) {
				return c.GrantUserRole(context.Background(), testMachineToken, 7, RoleGrant{RoleID: 5})
			},
		},
		{
			"grant user role with expiry", http.MethodPost, apiPath + "/iam/users/7/roles",
			`{"role_id":5,"expires_at":"2026-12-31T00:00:00Z"}`,
			func(c *Client) (*IDResponse, error) {
				expires := time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC)
				return c.GrantUserRole(context.Background(), testMachineToken, 7, RoleGrant{RoleID: 5, ExpiresAt: &expires})
			},
		},
		{
			"revoke user role", http.MethodDelete, apiPath + "/iam/users/7/roles/5", "",
			func(c *Client) (*IDResponse, error) {
				return c.RevokeUserRole(context.Background(), testMachineToken, 7, 5)
			},
		},
		{
			"grant group role", http.MethodPost, apiPath + "/iam/groups/8/roles",
			`{"role_id":5,"expires_at":null}`,
			func(c *Client) (*IDResponse, error) {
				return c.GrantGroupRole(context.Background(), testMachineToken, 8, RoleGrant{RoleID: 5})
			},
		},
		{
			"revoke group role", http.MethodDelete, apiPath + "/iam/groups/8/roles/5", "",
			func(c *Client) (*IDResponse, error) {
				return c.RevokeGroupRole(context.Background(), testMachineToken, 8, 5)
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, m := jsonMock(t, `{"data":{"id":5},"request_id":"r"}`)
			response, err := tc.call(c)
			if err != nil {
				t.Fatal(err)
			}
			request := m.only(t)
			if request.method != tc.method || request.path != tc.path || request.token != bearer(testMachineToken) {
				t.Fatalf("request=%+v", request)
			}
			if tc.body == "" {
				if request.body != "" {
					t.Fatalf("unexpected body %q", request.body)
				}
			} else {
				if request.ctype != jsonContentType || request.body != tc.body {
					t.Fatalf("body=%q content-type=%q", request.body, request.ctype)
				}
			}
			if response.Data.ID != 5 || response.RequestID != "r" {
				t.Fatalf("response=%+v", response)
			}
		})
	}
}

func TestIAMReads(t *testing.T) {
	c, m := jsonMock(t, `{"data":{"items":[{"id":5,"key":"reader","name":"Reader","description":""}],"next":6},"request_id":"r"}`)
	roles, err := c.ListAppRoles(context.Background(), testMachineToken, PageParams{After: 4, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	request := m.only(t)
	if request.path != apiPath+"/iam/roles" || request.query.Get("after") != "4" || request.query.Get("limit") != "10" {
		t.Fatalf("request=%+v", request)
	}
	if roles.Data.Next != 6 || len(roles.Data.Items) != 1 || roles.Data.Items[0].Key != "reader" {
		t.Fatalf("roles=%+v", roles)
	}

	c, m = jsonMock(t, `{"data":{"items":[{"id":6,"key":"order.read","name":"Read","description":""}],"next":0},"request_id":"r"}`)
	permissions, err := c.ListAppPermissions(context.Background(), testMachineToken, PageParams{})
	if err != nil {
		t.Fatal(err)
	}
	if request := m.only(t); request.path != apiPath+"/iam/permissions" || len(request.query) != 0 {
		t.Fatalf("request=%+v", request)
	}
	if len(permissions.Data.Items) != 1 || permissions.Data.Items[0].Key != "order.read" {
		t.Fatalf("permissions=%+v", permissions)
	}

	explanation := `{"data":{"app_id":42,"user_id":7,"roles":["reader"],"permissions":["order.read"],"sources":[{"role_id":5,"key":"reader","name":"Reader","origin":"group","group_id":8,"group_name":"Readers","expires_at":null}],"evaluated_at":"2026-09-30T10:00:00Z","next_change_at":null},"request_id":"r"}`
	c, m = jsonMock(t, explanation)
	effective, err := c.GetUserPermissions(context.Background(), testMachineToken, 7)
	if err != nil {
		t.Fatal(err)
	}
	if request := m.only(t); request.path != apiPath+"/iam/users/7/permissions" {
		t.Fatalf("request=%+v", request)
	}
	if effective.Data.AppID != 42 || effective.Data.UserID != 7 || len(effective.Data.Sources) != 1 ||
		effective.Data.Sources[0].Origin != GrantOriginGroup || effective.Data.Sources[0].GroupName != "Readers" {
		t.Fatalf("explanation=%+v", effective)
	}
}

func TestIAMInputValidation(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()
	for _, key := range []string{"", "   ", strings.Repeat("k", 46)} {
		if _, err := c.CreateAppRole(ctx, testMachineToken, RoleInput{Key: key}); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("accepted role key %q", key)
		}
	}
	for _, input := range []PermissionInput{
		{Key: ""},
		{Key: "Order.Read"},
		{Key: "_order"},
		{Key: strings.Repeat("k", 129)},
		{Key: "order.read", Name: strings.Repeat("n", 129)},
		{Key: "order.read", Description: strings.Repeat("d", 256)},
	} {
		if _, err := c.CreateAppPermission(ctx, testMachineToken, input); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("accepted %+v", input)
		}
		if _, err := c.UpdateAppPermission(ctx, testMachineToken, 6, input); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("accepted %+v", input)
		}
	}
	valid, _ := jsonMock(t, `{"data":{"id":6},"request_id":"r"}`)
	if _, err := valid.CreateAppPermission(ctx, testMachineToken, PermissionInput{Key: "order.read"}); err != nil {
		t.Fatal(err)
	}
	for _, call := range []func() error{
		func() error { _, err := c.DeleteAppRole(ctx, testMachineToken, 0); return err },
		func() error { _, err := c.DeleteAppPermission(ctx, testMachineToken, 0); return err },
		func() error { _, err := c.LinkRolePermission(ctx, testMachineToken, 0, 6); return err },
		func() error { _, err := c.LinkRolePermission(ctx, testMachineToken, 5, 0); return err },
		func() error { _, err := c.UnlinkRolePermission(ctx, testMachineToken, 0, 6); return err },
		func() error { _, err := c.GrantUserRole(ctx, testMachineToken, 0, RoleGrant{RoleID: 5}); return err },
		func() error { _, err := c.GrantUserRole(ctx, testMachineToken, 7, RoleGrant{}); return err },
		func() error { _, err := c.RevokeUserRole(ctx, testMachineToken, 7, 0); return err },
		func() error { _, err := c.GrantGroupRole(ctx, testMachineToken, 8, RoleGrant{}); return err },
		func() error { _, err := c.RevokeGroupRole(ctx, testMachineToken, 0, 5); return err },
		func() error { _, err := c.GetUserPermissions(ctx, testMachineToken, 0); return err },
		func() error { _, err := c.ListAppRoles(ctx, testMachineToken, PageParams{Limit: 201}); return err },
	} {
		if err := call(); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("err=%v", err)
		}
	}
}

func TestInvalidIAMResponses(t *testing.T) {
	c, _ := jsonMock(t, `{"data":{"id":0},"request_id":"r"}`)
	if _, err := c.DeleteAppRole(context.Background(), testMachineToken, 5); !errors.Is(err, ErrInvalidResponse) {
		t.Fatal("accepted a write without an identifier")
	}
	c, _ = jsonMock(t, `{"data":{"items":null,"next":0},"request_id":"r"}`)
	if _, err := c.ListAppRoles(context.Background(), testMachineToken, PageParams{}); !errors.Is(err, ErrInvalidResponse) {
		t.Fatal("accepted a page without items")
	}
	c, _ = jsonMock(t, `{"data":{"app_id":42,"user_id":7,"roles":[],"evaluated_at":"2026-09-30T10:00:00Z"},"request_id":"r"}`)
	if _, err := c.GetUserPermissions(context.Background(), testMachineToken, 7); !errors.Is(err, ErrInvalidResponse) {
		t.Fatal("accepted an explanation without permissions or sources")
	}
	// A conflict is the server's optimistic-lock answer for a stale reference.
	c, _ = errorMock(t, 409, ErrorConflict)
	_, err := c.DeleteAppRole(context.Background(), testMachineToken, 5)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != 409 || apiErr.Code != ErrorConflict {
		t.Fatalf("err=%v", err)
	}
	if !reflect.DeepEqual(MachineScopeVocabulary(), []Scope{ScopeDirectoryRead, ScopeLeaveRead, ScopeIAMRead, ScopeIAMWrite, ScopeEventsRead, ScopeAuditRead, ScopeStoresRead, ScopeStoresDeliveryRead, ScopeStoresMembersRead}) {
		t.Fatal("machine scope vocabulary")
	}
}
