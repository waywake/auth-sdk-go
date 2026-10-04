package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

var testExternalIdentityKey = ExternalIdentityKey{Provider: "YOUZAN", TenantID: "TenantA", Namespace: "ADMIN_ID", ExternalID: "staff-9"}

const testExternalIdentityJSON = `{"provider":"YOUZAN","tenant_id":"TenantA","namespace":"ADMIN_ID","external_id":"staff-9"}`

func TestLookupDirectoryExternalIdentitiesRequest(t *testing.T) {
	c, mock := jsonMock(t, `{"data":[{"identity":`+testExternalIdentityJSON+`,"binding":{"user_id":7,"version":3,"enabled":false,"updated_at":"2026-10-04T08:00:00.123456789Z"}},{"identity":`+testExternalIdentityJSON+`,"binding":null}],"request_id":"lookup-r"}`)
	input := []ExternalIdentityKey{
		{Provider: " youzan ", TenantID: " TenantA ", Namespace: " admin_id ", ExternalID: " staff-9 "},
		testExternalIdentityKey,
	}
	response, err := c.LookupDirectoryExternalIdentities(context.Background(), testMachineToken, input)
	if err != nil {
		t.Fatal(err)
	}
	request := mock.only(t)
	if request.method != http.MethodPost || request.path != apiPath+"/directory/external-identities/lookup" || request.token != bearer(testMachineToken) || request.ctype != jsonContentType || len(request.query) != 0 {
		t.Fatalf("request=%+v", request)
	}
	var body struct {
		Identities []ExternalIdentityKey `json:"identities"`
	}
	if err := json.Unmarshal([]byte(request.body), &body); err != nil || !reflect.DeepEqual(body.Identities, input) {
		t.Fatalf("body=%s, err=%v", request.body, err)
	}
	if response.RequestID != "lookup-r" || len(response.Data) != 2 || response.Data[0].Identity != testExternalIdentityKey || response.Data[1].Identity != testExternalIdentityKey || response.Data[1].Binding != nil {
		t.Fatalf("response=%+v", response)
	}
	binding := response.Data[0].Binding
	if binding == nil || binding.UserID != 7 || binding.Version != 3 || binding.Enabled || binding.UpdatedAt != time.Date(2026, 10, 4, 8, 0, 0, 123456789, time.UTC) {
		t.Fatalf("binding=%+v", binding)
	}
}

func TestListDirectoryEmployeeExternalIdentitiesRequest(t *testing.T) {
	c, mock := jsonMock(t, `{"data":[{"user_id":7,"enabled":false,"identities":[{"identity":`+testExternalIdentityJSON+`,"version":3,"updated_at":"2026-10-04T08:00:00Z"}]},{"user_id":4294967295,"enabled":true,"identities":[]}],"request_id":"employees-r"}`)
	response, err := c.ListDirectoryEmployeeExternalIdentities(context.Background(), testMachineToken, []int64{7, 8, 7, 4294967295})
	if err != nil {
		t.Fatal(err)
	}
	request := mock.only(t)
	if request.method != http.MethodPost || request.path != apiPath+"/directory/users/external-identities" || request.token != bearer(testMachineToken) || request.ctype != jsonContentType || request.body != `{"user_ids":[7,8,7,4294967295]}` || len(request.query) != 0 {
		t.Fatalf("request=%+v", request)
	}
	if response.RequestID != "employees-r" || len(response.Data) != 2 || response.Data[0].UserID != 7 || response.Data[0].Enabled || len(response.Data[0].Identities) != 1 || response.Data[1].Identities == nil || len(response.Data[1].Identities) != 0 {
		t.Fatalf("response=%+v", response)
	}
	identity := response.Data[0].Identities[0]
	if identity.Identity != testExternalIdentityKey || identity.Version != 3 || identity.UpdatedAt.IsZero() {
		t.Fatalf("identity=%+v", identity)
	}

	c, _ = jsonMock(t, `{"data":[],"request_id":"r"}`)
	response, err = c.ListDirectoryEmployeeExternalIdentities(context.Background(), testMachineToken, []int64{8})
	if err != nil || response.Data == nil || len(response.Data) != 0 {
		t.Fatalf("empty response=%+v, err=%v", response, err)
	}
}

func TestDirectoryExternalIdentityInputValidation(t *testing.T) {
	c, mock := jsonMock(t, `{"data":[],"request_id":"r"}`)
	ctx := context.Background()
	for _, keys := range [][]ExternalIdentityKey{nil, {}, make([]ExternalIdentityKey, MaxExternalIdentityBatch+1)} {
		if _, err := c.LookupDirectoryExternalIdentities(ctx, testMachineToken, keys); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("accepted %d keys: %v", len(keys), err)
		}
	}
	for _, ids := range [][]int64{nil, {}, {0}, {-1}, {1 << 32}, make([]int64, MaxExternalIdentityBatch+1)} {
		if _, err := c.ListDirectoryEmployeeExternalIdentities(ctx, testMachineToken, ids); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("accepted IDs %v: %v", ids, err)
		}
	}
	for _, mutate := range []func(*ExternalIdentityKey){
		func(k *ExternalIdentityKey) { k.Provider = " " },
		func(k *ExternalIdentityKey) { k.Namespace = strings.Repeat("a", 33) },
		func(k *ExternalIdentityKey) { k.Provider = "有赞" },
		func(k *ExternalIdentityKey) { k.Namespace = "admin.id" },
		func(k *ExternalIdentityKey) { k.TenantID = " " },
		func(k *ExternalIdentityKey) { k.ExternalID = "" },
		func(k *ExternalIdentityKey) { k.TenantID = strings.Repeat("a", 129) },
		func(k *ExternalIdentityKey) { k.ExternalID = strings.Repeat("中", 43) },
		func(k *ExternalIdentityKey) { k.ExternalID = string([]byte{255}) },
		func(k *ExternalIdentityKey) { k.Provider = "\tyouzan" },
		func(k *ExternalIdentityKey) { k.TenantID = "tenant\n" },
		func(k *ExternalIdentityKey) { k.ExternalID = "staff\u0085" },
	} {
		key := testExternalIdentityKey
		mutate(&key)
		if _, err := c.LookupDirectoryExternalIdentities(ctx, testMachineToken, []ExternalIdentityKey{key}); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("accepted key %+v: %v", key, err)
		}
	}
	for _, token := range []string{"", testToken} {
		if _, err := c.LookupDirectoryExternalIdentities(ctx, token, []ExternalIdentityKey{testExternalIdentityKey}); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("accepted invalid machine token: %v", err)
		}
		if _, err := c.ListDirectoryEmployeeExternalIdentities(ctx, token, []int64{7}); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("accepted invalid machine token: %v", err)
		}
	}
	if requests := mock.requests(); len(requests) != 0 {
		t.Fatalf("invalid arguments sent %d requests", len(requests))
	}
}

func TestDirectoryExternalIdentityBatchLimits(t *testing.T) {
	keys := make([]ExternalIdentityKey, MaxExternalIdentityBatch)
	lookups := make([]ExternalIdentityLookup, len(keys))
	ids := make([]int64, MaxExternalIdentityBatch)
	for i := range keys {
		keys[i] = ExternalIdentityKey{Provider: strings.Repeat("A", 32), Namespace: strings.Repeat("N", 32), TenantID: strings.Repeat("中", 42) + "ab", ExternalID: strings.Repeat("x", 128)}
		lookups[i] = ExternalIdentityLookup{Identity: keys[i]}
		ids[i] = int64(i + 1)
	}
	encoded, err := json.Marshal(ExternalIdentityLookupResponse{Data: lookups, RequestID: "r"})
	if err != nil {
		t.Fatal(err)
	}
	c, _ := jsonMock(t, string(encoded))
	if _, err := c.LookupDirectoryExternalIdentities(context.Background(), testMachineToken, keys); err != nil {
		t.Fatalf("maximum valid batch: %v", err)
	}
	c, _ = jsonMock(t, `{"data":[],"request_id":"r"}`)
	if _, err := c.ListDirectoryEmployeeExternalIdentities(context.Background(), testMachineToken, ids); err != nil {
		t.Fatalf("maximum ID batch: %v", err)
	}
	for i := range keys {
		keys[i].ExternalID = strings.Repeat("&", 128)
	}
	c, mock := jsonMock(t, `{"data":[],"request_id":"r"}`)
	if _, err := c.LookupDirectoryExternalIdentities(context.Background(), testMachineToken, keys); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("oversized encoded body: %v", err)
	}
	if len(mock.requests()) != 0 {
		t.Fatal("oversized body reached the network")
	}
}

func TestDirectoryExternalIdentityInvalidResponses(t *testing.T) {
	for _, body := range []string{
		`{"data":null,"request_id":"r"}`,
		`{"data":[],"request_id":"r"}`,
		`{"data":[{}],"request_id":"r"}`,
		`{"data":[{"identity":` + testExternalIdentityJSON + `}],"request_id":"r"}`,
		`{"data":[{"identity":` + testExternalIdentityJSON + `,"binding":{}}],"request_id":"r"}`,
		`{"data":[{"identity":` + testExternalIdentityJSON + `,"binding":{"user_id":7,"version":1,"updated_at":"2026-10-04T00:00:00Z"}}],"request_id":"r"}`,
		`{"data":[{"identity":` + testExternalIdentityJSON + `,"binding":{"user_id":7,"version":1,"enabled":true,"updated_at":"bad"}}],"request_id":"r"}`,
		`{"data":[{"identity":` + testExternalIdentityJSON + `,"binding":{"user_id":7,"version":1,"enabled":true}}],"request_id":"r"}`,
	} {
		c, _ := jsonMock(t, body)
		if _, err := c.LookupDirectoryExternalIdentities(context.Background(), testMachineToken, []ExternalIdentityKey{testExternalIdentityKey}); !errors.Is(err, ErrInvalidResponse) {
			t.Fatalf("body=%s, err=%v", body, err)
		}
	}
	for _, body := range []string{
		`{"data":null,"request_id":"r"}`,
		`{"data":[{}],"request_id":"r"}`,
		`{"data":[{"user_id":7,"enabled":false}],"request_id":"r"}`,
		`{"data":[{"user_id":7,"identities":[]}],"request_id":"r"}`,
		`{"data":[{"user_id":7,"enabled":true,"identities":[{}]}],"request_id":"r"}`,
		`{"data":[{"user_id":7,"enabled":true,"identities":[{"identity":` + testExternalIdentityJSON + `,"version":1}]}],"request_id":"r"}`,
	} {
		c, _ := jsonMock(t, body)
		if _, err := c.ListDirectoryEmployeeExternalIdentities(context.Background(), testMachineToken, []int64{7}); !errors.Is(err, ErrInvalidResponse) {
			t.Fatalf("body=%s, err=%v", body, err)
		}
	}
}

func TestDirectoryExternalIdentityAPIErrors(t *testing.T) {
	for _, call := range []func(*Client) error{
		func(c *Client) error {
			_, err := c.LookupDirectoryExternalIdentities(context.Background(), testMachineToken, []ExternalIdentityKey{testExternalIdentityKey})
			return err
		},
		func(c *Client) error {
			_, err := c.ListDirectoryEmployeeExternalIdentities(context.Background(), testMachineToken, []int64{7})
			return err
		},
	} {
		c, _ := errorMock(t, http.StatusForbidden, ErrorInsufficientScope)
		var apiErr *APIError
		if err := call(c); !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusForbidden || apiErr.Code != ErrorInsufficientScope {
			t.Fatalf("err=%v", err)
		}
	}
}
