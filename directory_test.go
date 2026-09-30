package auth

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

const directoryUserBody = `{"data":{"id":7,"username":"alice","name":"Alice","avatar":"","departments":[{"id":9,"name":"Engineering"}],"groups":[{"id":8,"name":"Readers"}]},"request_id":"r"}`

func TestListDirectoryUsersRequest(t *testing.T) {
	c, m := jsonMock(t, `{"data":{"items":[{"id":7,"username":"alice","name":"Alice","avatar":"","departments":[],"groups":[]}],"next":9},"request_id":"r"}`)
	page, err := c.ListDirectoryUsers(context.Background(), testMachineToken, ListDirectoryUsersParams{
		PageParams: PageParams{After: 5, Limit: 10}, DepartmentID: 9, GroupID: 8, Search: "ali",
	})
	if err != nil {
		t.Fatal(err)
	}
	request := m.only(t)
	if request.method != http.MethodGet || request.path != apiPath+"/directory/users" || request.token != bearer(testMachineToken) {
		t.Fatalf("request=%+v", request)
	}
	want := map[string]string{"after": "5", "limit": "10", "department_id": "9", "group_id": "8", "search": "ali"}
	for key, value := range want {
		if got := request.query.Get(key); got != value {
			t.Errorf("%s=%q, want %q", key, got, value)
		}
	}
	if len(request.query) != len(want) {
		t.Fatalf("query=%v", request.query)
	}
	if page.Data.Next != 9 || len(page.Data.Items) != 1 || page.Data.Items[0].ID != 7 {
		t.Fatalf("page=%+v", page)
	}
}

func TestListDirectoryUsersOmitsEmptyFilters(t *testing.T) {
	c, m := jsonMock(t, `{"data":{"items":[],"next":0},"request_id":"r"}`)
	if _, err := c.ListDirectoryUsers(context.Background(), testMachineToken, ListDirectoryUsersParams{}); err != nil {
		t.Fatal(err)
	}
	if query := m.only(t).query; len(query) != 0 {
		t.Fatalf("query=%v", query)
	}
}

func TestDirectoryMemberRequests(t *testing.T) {
	c, m := jsonMock(t, `{"data":{"items":[],"next":0},"request_id":"r"}`)
	if _, err := c.ListDirectoryDepartmentMembers(context.Background(), testMachineToken, 9, PageParams{After: 3, Limit: 200}); err != nil {
		t.Fatal(err)
	}
	request := m.only(t)
	if request.path != apiPath+"/directory/departments/9/members" || request.query.Get("after") != "3" || request.query.Get("limit") != "200" {
		t.Fatalf("request=%+v", request)
	}

	c, m = jsonMock(t, `{"data":{"items":[],"next":0},"request_id":"r"}`)
	if _, err := c.ListDirectoryGroupMembers(context.Background(), testMachineToken, 8, PageParams{}); err != nil {
		t.Fatal(err)
	}
	if request := m.only(t); request.path != apiPath+"/directory/groups/8/members" || len(request.query) != 0 {
		t.Fatalf("request=%+v", request)
	}
}

func TestDirectoryListRequests(t *testing.T) {
	c, m := jsonMock(t, `{"data":[{"id":9,"parent_id":0,"name":"Engineering","order":1}],"request_id":"r"}`)
	departments, err := c.ListDirectoryDepartments(context.Background(), testMachineToken)
	if err != nil {
		t.Fatal(err)
	}
	if request := m.only(t); request.path != apiPath+"/directory/departments" || len(request.query) != 0 {
		t.Fatalf("request=%+v", request)
	}
	if len(departments.Data) != 1 || departments.Data[0].ParentID != 0 || departments.Data[0].Name != "Engineering" {
		t.Fatalf("departments=%+v", departments)
	}

	c, m = jsonMock(t, `{"data":[{"id":8,"name":"Readers","description":"readers"}],"request_id":"r"}`)
	groups, err := c.ListDirectoryGroups(context.Background(), testMachineToken, PageParams{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if request := m.only(t); request.path != apiPath+"/directory/groups" || request.query.Get("limit") != "50" {
		t.Fatalf("request=%+v", request)
	}
	if len(groups.Data) != 1 || groups.Data[0].Description != "readers" {
		t.Fatalf("groups=%+v", groups)
	}
}

func TestDirectoryUserRequests(t *testing.T) {
	c, m := jsonMock(t, directoryUserBody)
	user, err := c.GetDirectoryUser(context.Background(), testMachineToken, 7)
	if err != nil {
		t.Fatal(err)
	}
	if request := m.only(t); request.path != apiPath+"/directory/users/7" || request.token != bearer(testMachineToken) {
		t.Fatalf("request=%+v", request)
	}
	if user.Data.ID != 7 || !reflect.DeepEqual(user.Data.Departments, []DepartmentRef{{ID: 9, Name: "Engineering"}}) ||
		!reflect.DeepEqual(user.Data.Groups, []GroupRef{{ID: 8, Name: "Readers"}}) {
		t.Fatalf("user=%+v", user)
	}

	c, m = jsonMock(t, `{"data":[{"id":9,"name":"Engineering"}],"request_id":"r"}`)
	departments, err := c.ListDirectoryUserDepartments(context.Background(), testMachineToken, 7)
	if err != nil {
		t.Fatal(err)
	}
	if request := m.only(t); request.path != apiPath+"/directory/users/7/departments" {
		t.Fatalf("request=%+v", request)
	}
	if len(departments.Data) != 1 || departments.Data[0].ID != 9 {
		t.Fatalf("departments=%+v", departments)
	}

	c, m = jsonMock(t, `{"data":[],"request_id":"r"}`)
	groups, err := c.ListDirectoryUserGroups(context.Background(), testMachineToken, 7)
	if err != nil {
		t.Fatal(err)
	}
	if request := m.only(t); request.path != apiPath+"/directory/users/7/groups" {
		t.Fatalf("request=%+v", request)
	}
	if groups.Data == nil || len(groups.Data) != 0 {
		t.Fatalf("groups=%+v", groups)
	}
}

func TestDirectoryErrorCodes(t *testing.T) {
	c, _ := errorMock(t, 404, ErrorNotFound)
	_, err := c.GetDirectoryUser(context.Background(), testMachineToken, 99)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != 404 || apiErr.Code != ErrorNotFound {
		t.Fatalf("err=%v", err)
	}
	// The scope decision stays the server's: the SDK never invents a local
	// scope error, it reports the frozen code.
	c, _ = errorMock(t, 403, ErrorInsufficientScope)
	_, err = c.ListDirectoryUsers(context.Background(), testMachineToken, ListDirectoryUsersParams{})
	if !errors.As(err, &apiErr) || apiErr.StatusCode != 403 || apiErr.Code != ErrorInsufficientScope {
		t.Fatalf("err=%v", err)
	}
}

func TestDirectoryInputValidation(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()
	for _, id := range []int64{0, -1} {
		if _, err := c.GetDirectoryUser(ctx, testMachineToken, id); !errors.Is(err, ErrInvalidArgument) {
			t.Fatal("accepted an invalid employee identifier")
		}
		if _, err := c.ListDirectoryDepartmentMembers(ctx, testMachineToken, id, PageParams{}); !errors.Is(err, ErrInvalidArgument) {
			t.Fatal("accepted an invalid department identifier")
		}
		if _, err := c.ListDirectoryGroupMembers(ctx, testMachineToken, id, PageParams{}); !errors.Is(err, ErrInvalidArgument) {
			t.Fatal("accepted an invalid group identifier")
		}
		if _, err := c.ListDirectoryUserGroups(ctx, testMachineToken, id); !errors.Is(err, ErrInvalidArgument) {
			t.Fatal("accepted an invalid employee identifier")
		}
	}
	for _, params := range []PageParams{{Limit: -1}, {Limit: MaxPageSize + 1}, {After: -1}} {
		if _, err := c.ListDirectoryUsers(ctx, testMachineToken, ListDirectoryUsersParams{PageParams: params}); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("accepted %+v", params)
		}
		if _, err := c.ListDirectoryGroups(ctx, testMachineToken, params); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("accepted %+v", params)
		}
	}
	if _, err := c.ListDirectoryUsers(ctx, testMachineToken, ListDirectoryUsersParams{Search: strings.Repeat("s", 65)}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatal("accepted an oversized search")
	}
	if _, err := c.ListDirectoryUsers(ctx, testMachineToken, ListDirectoryUsersParams{DepartmentID: -1}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatal("accepted a negative department filter")
	}
}

func TestInvalidDirectoryResponses(t *testing.T) {
	for _, body := range []string{
		`{"data":{"next":0},"request_id":"r"}`,
		`{"data":{"items":null,"next":0},"request_id":"r"}`,
		`{"data":{"items":{},"next":0},"request_id":"r"}`,
	} {
		c, _ := jsonMock(t, body)
		if _, err := c.ListDirectoryUsers(context.Background(), testMachineToken, ListDirectoryUsersParams{}); !errors.Is(err, ErrInvalidResponse) {
			t.Fatalf("body %s: err=%v", body, err)
		}
	}
	for _, body := range []string{`{"data":null,"request_id":"r"}`, `{"data":{},"request_id":"r"}`} {
		c, _ := jsonMock(t, body)
		if _, err := c.ListDirectoryDepartments(context.Background(), testMachineToken); !errors.Is(err, ErrInvalidResponse) {
			t.Fatalf("body %s: err=%v", body, err)
		}
		if _, err := c.ListDirectoryUserDepartments(context.Background(), testMachineToken, 7); !errors.Is(err, ErrInvalidResponse) {
			t.Fatalf("body %s: err=%v", body, err)
		}
	}
	c, _ := jsonMock(t, `{"data":{"username":"alice"},"request_id":"r"}`)
	if _, err := c.GetDirectoryUser(context.Background(), testMachineToken, 7); !errors.Is(err, ErrInvalidResponse) {
		t.Fatal("accepted an employee without an identifier")
	}
}
