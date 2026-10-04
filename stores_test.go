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

const storeJSON = `{"id":21,"brand_id":3,"code":"SH-01","name":"上海一店","status":"open","location":"上海","version":4}`
const storeAssignmentJSON = `{"id":31,"store_id":21,"user_id":7,"kind":"employment","assignment_type":"primary","started_at":"2026-01-01T00:00:00Z","ended_at":null,"positions":[{"id":41,"position_code":"store_manager","started_at":"2026-01-01T00:00:00Z","ended_at":"2026-11-01T00:00:00Z"}],"employee_enabled":false}`
const externalStoreKeyJSON = `{"provider":"YOUZAN","tenant_key":"Tenant-A","namespace":"STORE","external_id":"Store-01"}`

func TestListStoresRequest(t *testing.T) {
	const cursor = "MjE6b3BhcXVlLWN1cnNvci0xMjM"
	c, m := jsonMock(t, `{"data":{"items":[`+storeJSON+`],"next":"`+cursor+`","has_more":true},"request_id":"r"}`)
	params := ListStoresParams{After: "opaque_previous-cursor", Limit: 100, BrandID: 3, Status: StoreStatusOpen, Query: "上海 & A+B"}
	page, err := c.ListStores(context.Background(), testMachineToken, params)
	if err != nil {
		t.Fatal(err)
	}
	r := m.only(t)
	if r.method != http.MethodGet || r.path != apiPath+"/stores" || r.token != bearer(testMachineToken) || r.body != "" {
		t.Fatalf("request=%+v", r)
	}
	want := map[string]string{"after": params.After, "limit": "100", "brand_id": "3", "status": "open", "q": params.Query}
	if len(r.query) != len(want) {
		t.Fatalf("query=%v", r.query)
	}
	for key, value := range want {
		if r.query.Get(key) != value {
			t.Errorf("%s=%q, want %q", key, r.query.Get(key), value)
		}
	}
	if page.RequestID != "r" || !page.Data.HasMore || page.Data.Next != cursor || len(page.Data.Items) != 1 || page.Data.Items[0].Status != StoreStatusOpen || page.Data.Items[0].BrandID != 3 {
		t.Fatalf("page=%+v", page)
	}
	params.After = page.Data.Next
	if _, err := c.ListStores(context.Background(), testMachineToken, params); err != nil {
		t.Fatal(err)
	}
	if after := m.requests()[1].query.Get("after"); after != cursor {
		t.Fatalf("cursor altered: %q", after)
	}
}

func TestListStoresEmptyPageAndFilters(t *testing.T) {
	c, m := jsonMock(t, `{"data":{"items":[],"next":"","has_more":false},"request_id":"r"}`)
	page, err := c.ListStores(context.Background(), testMachineToken, ListStoresParams{})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.only(t).query) != 0 || page.Data.Items == nil || page.Data.HasMore || page.Data.Next != "" {
		t.Fatalf("page=%+v", page)
	}
}

func TestGetStoreRequest(t *testing.T) {
	c, m := jsonMock(t, `{"data":`+storeJSON+`,"request_id":"r"}`)
	store, err := c.GetStore(context.Background(), testMachineToken, 21)
	if err != nil {
		t.Fatal(err)
	}
	r := m.only(t)
	if r.method != http.MethodGet || r.path != apiPath+"/stores/21" || r.token != bearer(testMachineToken) || len(r.query) != 0 {
		t.Fatalf("request=%+v", r)
	}
	if store.Data.ID != 21 || store.Data.Code != "SH-01" || store.Data.Name != "上海一店" || store.Data.Location != "上海" || store.Data.Version != 4 {
		t.Fatalf("store=%+v", store)
	}
}

func TestGetStoreReceivingAddress(t *testing.T) {
	t.Run("configured", func(t *testing.T) {
		c, m := jsonMock(t, `{"data":{"store_id":21,"region":"上海市","address":"示例路 1 号","contact_name":"Alice","contact_phone":"13800000000","delivery_time_requirement":"工作日 09:00–18:00","version":5},"request_id":"r"}`)
		address, err := c.GetStoreReceivingAddress(context.Background(), testMachineToken, 21)
		if err != nil {
			t.Fatal(err)
		}
		r := m.only(t)
		if r.method != http.MethodGet || r.path != apiPath+"/stores/21/receiving-address" || r.token != bearer(testMachineToken) || len(r.query) != 0 {
			t.Fatalf("request=%+v", r)
		}
		if address.RequestID != "r" || address.Data == nil || address.Data.StoreID != 21 || address.Data.DeliveryTimeRequirement != "工作日 09:00–18:00" || address.Data.ContactName != "Alice" || address.Data.Version != 5 {
			t.Fatalf("address=%+v", address)
		}
	})
	t.Run("unconfigured", func(t *testing.T) {
		c, _ := jsonMock(t, `{"data":null,"request_id":"r"}`)
		address, err := c.GetStoreReceivingAddress(context.Background(), testMachineToken, 21)
		if err != nil || address == nil || address.Data != nil || address.RequestID != "r" {
			t.Fatalf("address=%+v, err=%v", address, err)
		}
	})
}

func TestGetStoreEmployees(t *testing.T) {
	c, m := jsonMock(t, `{"data":{"items":[`+storeAssignmentJSON+`],"evaluated_at":"2026-10-04T00:00:00Z","next_change_at":"2026-11-01T00:00:00Z"},"request_id":"r"}`)
	response, err := c.GetStoreEmployees(context.Background(), testMachineToken, 21)
	if err != nil {
		t.Fatal(err)
	}
	r := m.only(t)
	if r.method != http.MethodGet || r.path != apiPath+"/stores/21/employees" || r.token != bearer(testMachineToken) || len(r.query) != 0 {
		t.Fatalf("request=%+v", r)
	}
	if len(response.Data.Items) != 1 || response.Data.EvaluatedAt.IsZero() || response.Data.NextChangeAt == nil {
		t.Fatalf("employees=%+v", response)
	}
	assignment := response.Data.Items[0]
	if assignment.EmployeeEnabled || assignment.EndedAt != nil || assignment.AssignmentType != "primary" || len(assignment.Positions) != 1 || assignment.Positions[0].PositionCode != "store_manager" || !assignment.Positions[0].EndedAt.Equal(*response.Data.NextChangeAt) {
		t.Fatalf("assignment=%+v", assignment)
	}
}

func TestGetEmployeeStores(t *testing.T) {
	placement := `{"store":` + storeJSON + `,"assignment":` + storeAssignmentJSON + `}`
	c, m := jsonMock(t, `{"data":{"user_id":7,"primary_store":`+placement+`,"secondments":[],"other_relations":[],"evaluated_at":"2026-10-04T00:00:00Z","next_change_at":null},"request_id":"r"}`)
	response, err := c.GetEmployeeStores(context.Background(), testMachineToken, 7)
	if err != nil {
		t.Fatal(err)
	}
	r := m.only(t)
	if r.method != http.MethodGet || r.path != apiPath+"/directory/users/7/stores" || r.token != bearer(testMachineToken) || len(r.query) != 0 {
		t.Fatalf("request=%+v", r)
	}
	if response.Data.PrimaryStore == nil || response.Data.PrimaryStore.Store.ID != 21 || response.Data.PrimaryStore.Assignment.UserID != 7 || response.Data.Secondments == nil || response.Data.OtherRelations == nil || response.Data.NextChangeAt != nil {
		t.Fatalf("stores=%+v", response)
	}
	c, _ = jsonMock(t, `{"data":{"user_id":7,"primary_store":null,"secondments":[],"other_relations":[],"evaluated_at":"2026-10-04T00:00:00Z","next_change_at":null},"request_id":"r"}`)
	response, err = c.GetEmployeeStores(context.Background(), testMachineToken, 7)
	if err != nil || response.Data.PrimaryStore != nil {
		t.Fatalf("empty stores=%+v, err=%v", response, err)
	}
}

func TestLookupExternalStores(t *testing.T) {
	key := ExternalStoreKey{Provider: " youzan ", TenantKey: "Tenant-A", Namespace: "store", ExternalID: "Store-01"}
	keys := []ExternalStoreKey{key, key}
	c, m := jsonMock(t, `{"data":[{"identity":`+externalStoreKeyJSON+`,"binding":{"store_id":21,"version":2}},{"identity":`+externalStoreKeyJSON+`,"binding":null}],"request_id":"r"}`)
	response, err := c.LookupExternalStores(context.Background(), testMachineToken, keys)
	if err != nil {
		t.Fatal(err)
	}
	r := m.only(t)
	if r.method != http.MethodPost || r.path != apiPath+"/stores/external-identities/lookup" || r.token != bearer(testMachineToken) || r.ctype != jsonContentType || len(r.query) != 0 {
		t.Fatalf("request=%+v", r)
	}
	var input struct {
		Identities []ExternalStoreKey `json:"identities"`
	}
	if err := json.Unmarshal([]byte(r.body), &input); err != nil || !reflect.DeepEqual(input.Identities, keys) {
		t.Fatalf("input=%+v, err=%v", input, err)
	}
	if len(response.Data) != 2 || response.Data[0].Identity.Provider != "YOUZAN" || response.Data[0].Identity.Namespace != "STORE" || response.Data[0].Binding == nil || response.Data[0].Binding.StoreID != 21 || response.Data[1].Binding != nil {
		t.Fatalf("lookup=%+v", response)
	}
}

func TestStoresInputValidation(t *testing.T) {
	c, m := jsonMock(t, `{}`)
	ctx := context.Background()
	for _, id := range []int64{0, -1, MaxStoreID + 1} {
		for _, call := range []func() error{
			func() error { _, err := c.GetStore(ctx, testMachineToken, id); return err },
			func() error { _, err := c.GetStoreReceivingAddress(ctx, testMachineToken, id); return err },
			func() error { _, err := c.GetStoreEmployees(ctx, testMachineToken, id); return err },
		} {
			if err := call(); !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("id %d: err=%v", id, err)
			}
		}
	}
	for _, id := range []int64{0, -1, 1 << 32} {
		if _, err := c.GetEmployeeStores(ctx, testMachineToken, id); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("user ID %d: err=%v", id, err)
		}
	}
	for _, params := range []ListStoresParams{
		{After: strings.Repeat("a", 257)}, {Limit: -1}, {Limit: MaxStorePageSize + 1},
		{BrandID: -1}, {BrandID: MaxStoreID + 1}, {Status: "unknown"},
		{Query: strings.Repeat("a", 257)}, {Query: strings.Repeat("店", 86)},
		{Query: "bad\nquery"}, {Query: "bad\u0085query"}, {Query: string([]byte{0xff})},
	} {
		if _, err := c.ListStores(ctx, testMachineToken, params); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("params=%+v: err=%v", params, err)
		}
	}
	for _, keys := range [][]ExternalStoreKey{nil, {}, make([]ExternalStoreKey, MaxStoreLookupKeys+1), {{}}} {
		if _, err := c.LookupExternalStores(ctx, testMachineToken, keys); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("keys=%+v: err=%v", keys, err)
		}
	}
	if len(m.requests()) != 0 {
		t.Fatal("invalid arguments reached the server")
	}
}

func TestExternalStoreKeyValidation(t *testing.T) {
	valid := ExternalStoreKey{Provider: "youzan", TenantKey: "Tenant-A", Namespace: "store", ExternalID: "Store-01"}
	for _, mutate := range []func(*ExternalStoreKey){
		func(k *ExternalStoreKey) { k.Provider = "" },
		func(k *ExternalStoreKey) { k.Provider = strings.Repeat("a", 33) },
		func(k *ExternalStoreKey) { k.Provider = "bad.code" },
		func(k *ExternalStoreKey) { k.Provider = "\tcode" },
		func(k *ExternalStoreKey) { k.Namespace = "门店" },
		func(k *ExternalStoreKey) { k.TenantKey = " leading" },
		func(k *ExternalStoreKey) { k.TenantKey = "" },
		func(k *ExternalStoreKey) { k.ExternalID = strings.Repeat("店", 43) },
		func(k *ExternalStoreKey) { k.ExternalID = "bad\x00key" },
		func(k *ExternalStoreKey) { k.ExternalID = string([]byte{0xff}) },
	} {
		key := valid
		mutate(&key)
		if err := validExternalStoreKey(key); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("accepted %+v: %v", key, err)
		}
	}
	valid.Provider = " code_1-2 "
	valid.ExternalID = strings.Repeat("x", 128)
	if err := validExternalStoreKey(valid); err != nil {
		t.Fatal(err)
	}
}

func TestStoresInvalidResponses(t *testing.T) {
	ctx := context.Background()
	key := ExternalStoreKey{Provider: "YOUZAN", TenantKey: "Tenant-A", Namespace: "STORE", ExternalID: "Store-01"}
	for _, tc := range []struct {
		name   string
		bodies []string
		call   func(*Client) error
	}{
		{"list", []string{`{"items":null,"next":"","has_more":false}`, `{"items":[]}`, `{"items":[],"next":1,"has_more":false}`, `{"items":[],"next":"cursor","has_more":true}`, `{"items":[],"next":"cursor","has_more":false}`}, func(c *Client) error { _, err := c.ListStores(ctx, testMachineToken, ListStoresParams{}); return err }},
		{"store", []string{`{}`, `{"id":22,"brand_id":3,"version":1}`}, func(c *Client) error { _, err := c.GetStore(ctx, testMachineToken, 21); return err }},
		{"address", []string{`{}`, `[]`, `{"store_id":22,"version":1}`}, func(c *Client) error { _, err := c.GetStoreReceivingAddress(ctx, testMachineToken, 21); return err }},
		{"employees", []string{`{"items":[]}`, `{"items":null,"evaluated_at":"2026-10-04T00:00:00Z"}`}, func(c *Client) error { _, err := c.GetStoreEmployees(ctx, testMachineToken, 21); return err }},
		{"employee stores", []string{`{"user_id":7,"secondments":[],"other_relations":[]}`, `{"user_id":8,"secondments":[],"other_relations":[],"evaluated_at":"2026-10-04T00:00:00Z"}`, `{"user_id":7,"secondments":null,"other_relations":[],"evaluated_at":"2026-10-04T00:00:00Z"}`}, func(c *Client) error { _, err := c.GetEmployeeStores(ctx, testMachineToken, 7); return err }},
		{"lookup", []string{`null`, `[]`, `{}`}, func(c *Client) error {
			_, err := c.LookupExternalStores(ctx, testMachineToken, []ExternalStoreKey{key})
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, data := range tc.bodies {
				c, _ := jsonMock(t, `{"data":`+data+`,"request_id":"r"}`)
				if err := tc.call(c); !errors.Is(err, ErrInvalidResponse) {
					t.Fatalf("data=%s: err=%v", data, err)
				}
			}
		})
	}
	for _, body := range []string{`{"request_id":"r"}`, `{"data":null}`, `null`} {
		c, _ := jsonMock(t, body)
		if _, err := c.GetStoreReceivingAddress(ctx, testMachineToken, 21); !errors.Is(err, ErrInvalidResponse) {
			t.Fatalf("body=%s: err=%v", body, err)
		}
	}
}

func TestStoresErrorCodes(t *testing.T) {
	for _, tc := range []struct {
		status int
		code   ErrorCode
	}{{404, ErrorNotFound}, {403, ErrorInsufficientScope}, {401, ErrorInvalidToken}, {400, ErrorInvalidRequest}} {
		c, _ := errorMock(t, tc.status, tc.code)
		_, err := c.GetStoreReceivingAddress(context.Background(), testMachineToken, 21)
		var apiErr *APIError
		if !errors.As(err, &apiErr) || apiErr.StatusCode != tc.status || apiErr.Code != tc.code {
			t.Fatalf("err=%v", err)
		}
	}
}

func TestStoresEmptyRelationships(t *testing.T) {
	c, _ := jsonMock(t, `{"data":{"items":[],"evaluated_at":"2026-10-04T00:00:00Z","next_change_at":null},"request_id":"r"}`)
	response, err := c.GetStoreEmployees(context.Background(), testMachineToken, 21)
	if err != nil || response.Data.Items == nil || len(response.Data.Items) != 0 || response.Data.NextChangeAt != nil || !response.Data.EvaluatedAt.Equal(time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("employees=%+v, err=%v", response, err)
	}
}
