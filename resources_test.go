package auth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const (
	profileBody     = `{"data":{"id":7,"username":"alice","name":"Alice","avatar":"https://img.example.com/a.png","hire_date":null,"hire_date_source":"","probation_months":null,"regularization_date":null},"request_id":"profile-1"}`
	permissionsBody = `{"data":{"app_id":42,"user_id":7,"roles":["reader"],"permissions":["order.read"],"evaluated_at":"2026-09-30T10:00:00Z","next_change_at":"2026-10-01T00:00:00Z"},"request_id":"permissions-1"}`
	checkBody       = `{"data":{"allowed":false,"evaluated_at":"2026-09-30T10:00:00Z","next_change_at":null},"request_id":"check-1"}`
)

func TestGetCurrentUserRequest(t *testing.T) {
	c, m := jsonMock(t, profileBody)
	profile, err := c.GetCurrentUser(context.Background(), testToken)
	if err != nil {
		t.Fatal(err)
	}
	request := m.only(t)
	if request.method != http.MethodGet || request.path != apiPath+"/me" || request.token != bearer(testToken) || request.body != "" {
		t.Fatalf("request=%+v", request)
	}
	if profile.RequestID != "profile-1" || profile.Data.ID != 7 || profile.Data.Username != "alice" || profile.Data.Name != "Alice" ||
		profile.Data.Avatar == "" || profile.Data.HireDate != nil || profile.Data.HireDateSource != "" ||
		profile.Data.ProbationMonths != nil || profile.Data.RegularizationDate != nil {
		t.Fatalf("profile=%+v", profile)
	}
}

func TestGetCurrentPermissionsRequest(t *testing.T) {
	c, m := jsonMock(t, permissionsBody)
	permissions, err := c.GetCurrentPermissions(context.Background(), testToken)
	if err != nil {
		t.Fatal(err)
	}
	if request := m.only(t); request.path != apiPath+"/me/permissions" || request.token != bearer(testToken) {
		t.Fatalf("request=%+v", request)
	}
	if permissions.Data.AppID != 42 || permissions.Data.UserID != 7 || permissions.Data.EvaluatedAt.IsZero() ||
		permissions.Data.NextChangeAt == nil || permissions.Data.NextChangeAt.IsZero() ||
		len(permissions.Data.Roles) != 1 || len(permissions.Data.Permissions) != 1 {
		t.Fatalf("permissions=%+v", permissions)
	}
}

func TestCheckCurrentPermissionRequest(t *testing.T) {
	c, m := jsonMock(t, checkBody)
	check, err := c.CheckCurrentPermission(context.Background(), testToken, "order.read")
	if err != nil {
		t.Fatal(err)
	}
	request := m.only(t)
	if request.method != http.MethodPost || request.path != apiPath+"/me/permissions/check" ||
		request.ctype != jsonContentType || request.body != `{"permission":"order.read"}` || request.token != bearer(testToken) {
		t.Fatalf("request=%+v", request)
	}
	if check.Data.Allowed || check.RequestID != "check-1" || check.Data.EvaluatedAt.IsZero() {
		t.Fatalf("check=%+v", check)
	}
}

func TestCheckCurrentPermissionsRequest(t *testing.T) {
	c, m := jsonMock(t, `{"data":{"results":[{"allowed":true,"evaluated_at":"2026-09-30T10:00:00Z","next_change_at":null},{"allowed":false,"evaluated_at":"2026-09-30T10:00:00Z","next_change_at":null}],"evaluated_at":"2026-09-30T10:00:00Z","next_change_at":null},"request_id":"batch-1"}`)
	batch, err := c.CheckCurrentPermissions(context.Background(), testToken, "order.read", "order.write")
	if err != nil {
		t.Fatal(err)
	}
	request := m.only(t)
	if request.path != apiPath+"/me/permissions/check-batch" || request.body != `{"permissions":["order.read","order.write"]}` {
		t.Fatalf("request=%+v", request)
	}
	if len(batch.Data.Results) != 2 || !batch.Data.Results[0].Allowed || batch.Data.Results[1].Allowed || batch.RequestID != "batch-1" {
		t.Fatalf("batch=%+v", batch)
	}
}

func TestMachineResources(t *testing.T) {
	c, m := jsonMock(t, `{"data":{"app_id":42,"subject":"machine","scopes":["directory:read","iam:read"],"credential_id":3},"request_id":"machine-1"}`)
	identity, err := c.GetMachineIdentity(context.Background(), testMachineToken)
	if err != nil {
		t.Fatal(err)
	}
	if request := m.only(t); request.path != apiPath+"/machine/me" || request.token != bearer(testMachineToken) {
		t.Fatalf("request=%+v", request)
	}
	if identity.Data.AppID != 42 || identity.Data.Subject != "machine" || identity.Data.CredentialID != 3 ||
		len(identity.Data.Scopes) != 2 || identity.RequestID != "machine-1" {
		t.Fatalf("identity=%+v", identity)
	}

	c, m = jsonMock(t, `{"data":{"app_id":42,"scopes":[]},"request_id":"scopes-1"}`)
	scopes, err := c.GetMachineScopes(context.Background(), testMachineToken)
	if err != nil {
		t.Fatal(err)
	}
	if request := m.only(t); request.path != apiPath+"/machine/me/permissions" {
		t.Fatalf("request=%+v", request)
	}
	if scopes.Data.Scopes == nil || len(scopes.Data.Scopes) != 0 {
		t.Fatalf("scopes=%+v", scopes)
	}
}

func TestResourceErrors(t *testing.T) {
	cases := []struct {
		status int
		code   ErrorCode
	}{
		{401, ErrorInvalidToken}, {403, ErrorInsufficientScope}, {403, ErrorIPNotAllowed},
		{403, ErrorLoginRequired}, {404, ErrorNotFound}, {409, ErrorConflict},
		{429, ErrorRateLimitExceeded}, {503, ErrorTemporarilyUnavailable},
	}
	for _, tc := range cases {
		t.Run(string(tc.code), func(t *testing.T) {
			c, _ := errorMock(t, tc.status, tc.code)
			_, err := c.GetCurrentUser(context.Background(), testToken)
			var apiErr *APIError
			if !errors.As(err, &apiErr) || apiErr.StatusCode != tc.status || apiErr.Code != tc.code {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestInvalidResourceResponses(t *testing.T) {
	cases := []struct {
		name string
		body string
		call func(*Client) error
	}{
		{"profile without ID", `{"data":{"username":"u"},"request_id":"r"}`, func(c *Client) error {
			_, err := c.GetCurrentUser(context.Background(), testToken)
			return err
		}},
		{"permissions without evaluation instant", `{"data":{"app_id":42,"user_id":7,"roles":[],"permissions":[]},"request_id":"r"}`, func(c *Client) error {
			_, err := c.GetCurrentPermissions(context.Background(), testToken)
			return err
		}},
		{"check without decision", `{"data":{"evaluated_at":"2026-09-30T10:00:00Z"},"request_id":"r"}`, func(c *Client) error {
			_, err := c.CheckCurrentPermission(context.Background(), testToken, "order.read")
			return err
		}},
		{"check without evaluation instant", `{"data":{"allowed":true},"request_id":"r"}`, func(c *Client) error {
			_, err := c.CheckCurrentPermission(context.Background(), testToken, "order.read")
			return err
		}},
		{"batch with an incomplete decision", `{"data":{"results":[{"allowed":true}],"evaluated_at":"2026-09-30T10:00:00Z"},"request_id":"r"}`, func(c *Client) error {
			_, err := c.CheckCurrentPermissions(context.Background(), testToken, "order.read")
			return err
		}},
		{"machine identity without scopes", `{"data":{"app_id":42,"subject":"machine"},"request_id":"r"}`, func(c *Client) error {
			_, err := c.GetMachineIdentity(context.Background(), testMachineToken)
			return err
		}},
		{"machine scopes without application", `{"data":{"scopes":[]},"request_id":"r"}`, func(c *Client) error {
			_, err := c.GetMachineScopes(context.Background(), testMachineToken)
			return err
		}},
		{"missing request id", `{"data":{"id":7}}`, func(c *Client) error {
			_, err := c.GetCurrentUser(context.Background(), testToken)
			return err
		}},
		{"null data", `{"data":null,"request_id":"r"}`, func(c *Client) error {
			_, err := c.GetCurrentUser(context.Background(), testToken)
			return err
		}},
		{"wrong decision type", `{"data":{"allowed":"true","evaluated_at":"2026-09-30T10:00:00Z"},"request_id":"r"}`, func(c *Client) error {
			_, err := c.CheckCurrentPermission(context.Background(), testToken, "order.read")
			return err
		}},
		{"trailing document", `{"data":{"id":7},"request_id":"r"} {}`, func(c *Client) error {
			_, err := c.GetCurrentUser(context.Background(), testToken)
			return err
		}},
		{"HTML body", `<html>secret</html>`, func(c *Client) error {
			_, err := c.GetCurrentUser(context.Background(), testToken)
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := newRawMock(t, tc.body)
			c := clientForServer(t, server)
			err := tc.call(c)
			if !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("err=%v", err)
			}
			if strings.Contains(err.Error(), "secret") {
				t.Fatal("response body leaked")
			}
		})
	}
}

// newRawMock answers every request with one body and the JSON media type, even
// when the body is not JSON at all.
func newRawMock(t *testing.T, body string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(server.Close)
	return server
}
