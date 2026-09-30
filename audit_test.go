package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

const auditUsageBody = `{"data":{"from":"2026-09-24T00:00:00Z","to":"2026-09-30T00:00:00Z","calls":12,"success":10,"failure":2,"buckets":[{"day":"2026-09-30T00:00:00Z","action":"app_role_save","outcome":"success","calls":12}],"rate_limit":[{"purpose":"token","limit":60,"used":3,"window_seconds":60,"resets_in_seconds":10}],"latency":{"measured":12,"average_ms":7,"maximum_ms":40,"p95_upper_ms":50,"buckets":[{"upper_ms":50,"calls":12}]}},"request_id":"r"}`

func TestListAuditEventsRequest(t *testing.T) {
	c, m := jsonMock(t, `{"data":{"items":[{"id":100,"created_at":"2026-09-30T10:00:00Z","action":"app_role_save","outcome":"success","target_type":"role","target_id":5,"actor_id":0,"actor_app_id":42,"app_id":42,"user_id":0,"role_id":5,"request_id":"req-1","peer_ip":"203.0.113.10","status":200}],"next":99},"request_id":"r"}`)
	page, err := c.ListAuditEvents(context.Background(), testMachineToken, ListAuditEventsParams{
		Before: 100, Limit: 10, Action: "app_role_save", Outcome: AuditOutcomeSuccess, TargetType: "role", TargetID: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := m.only(t)
	if request.method != http.MethodGet || request.path != apiPath+"/audit/events" || request.token != bearer(testMachineToken) {
		t.Fatalf("request=%+v", request)
	}
	want := map[string]string{"before": "100", "limit": "10", "action": "app_role_save", "outcome": "success", "target_type": "role", "target_id": "5"}
	for key, value := range want {
		if got := request.query.Get(key); got != value {
			t.Errorf("%s=%q, want %q", key, got, value)
		}
	}
	if len(request.query) != len(want) {
		t.Fatalf("query=%v", request.query)
	}
	if page.Data.Next != 99 || len(page.Data.Items) != 1 {
		t.Fatalf("page=%+v", page)
	}
	event := page.Data.Items[0]
	if event.ID != 100 || event.ActorAppID != 42 || event.AppID != 42 || event.RoleID != 5 || event.Status != 200 ||
		event.Outcome != AuditOutcomeSuccess || event.CreatedAt.IsZero() || event.PeerIP == "" {
		t.Fatalf("event=%+v", event)
	}
}

func TestListAuditEventsValidation(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()
	for _, params := range []ListAuditEventsParams{
		{Before: -1}, {Limit: -1}, {Limit: MaxPageSize + 1}, {Outcome: "ok"},
		{Action: strings.Repeat("a", 129)}, {Action: "app\nrole"}, {TargetType: strings.Repeat("t", 129)},
		{TargetType: "role\x00"}, {TargetID: -1},
	} {
		if _, err := c.ListAuditEvents(ctx, testMachineToken, params); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("accepted %+v", params)
		}
	}
}

func TestReadAuditUsageRequest(t *testing.T) {
	c, m := jsonMock(t, auditUsageBody)
	usage, err := c.ReadAuditUsage(context.Background(), testMachineToken, 7)
	if err != nil {
		t.Fatal(err)
	}
	request := m.only(t)
	if request.path != apiPath+"/audit/usage" || request.query.Get("days") != "7" {
		t.Fatalf("request=%+v", request)
	}
	if usage.Data.Calls != 12 || usage.Data.Success != 10 || usage.Data.Failure != 2 || usage.Data.From.IsZero() || usage.Data.To.IsZero() {
		t.Fatalf("usage=%+v", usage)
	}
	if len(usage.Data.Buckets) != 1 || usage.Data.Buckets[0].Calls != 12 || usage.Data.Buckets[0].Day.IsZero() {
		t.Fatalf("buckets=%+v", usage.Data.Buckets)
	}
	if len(usage.Data.RateLimit) != 1 || usage.Data.RateLimit[0].Purpose != "token" || usage.Data.RateLimit[0].ResetsInSeconds != 10 {
		t.Fatalf("rate limit=%+v", usage.Data.RateLimit)
	}
	if usage.Data.Latency.Measured != 12 || usage.Data.Latency.P95UpperMillis != 50 || len(usage.Data.Latency.Buckets) != 1 {
		t.Fatalf("latency=%+v", usage.Data.Latency)
	}

	// The default window is the server's, and a null rate_limit is a real
	// answer: the counter store could not be read.
	c, m = jsonMock(t, `{"data":{"from":"2026-09-24T00:00:00Z","to":"2026-09-30T00:00:00Z","calls":0,"success":0,"failure":0,"buckets":[],"rate_limit":null,"latency":{"measured":0,"average_ms":0,"maximum_ms":0,"p95_upper_ms":0,"buckets":[]}},"request_id":"r"}`)
	usage, err = c.ReadAuditUsage(context.Background(), testMachineToken, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.only(t).query) != 0 {
		t.Fatal("the default window must not be sent")
	}
	if usage.Data.RateLimit != nil || usage.Data.Buckets == nil || usage.Data.Latency.Buckets == nil {
		t.Fatalf("usage=%+v", usage)
	}
}

func TestReadAuditUsageValidation(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()
	for _, days := range []int{-1, MaxAuditUsageDays + 1} {
		if _, err := c.ReadAuditUsage(ctx, testMachineToken, days); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("accepted %d days", days)
		}
	}
	valid, _ := jsonMock(t, auditUsageBody)
	if _, err := valid.ReadAuditUsage(ctx, testMachineToken, MaxAuditUsageDays); err != nil {
		t.Fatal(err)
	}
	c, _ = jsonMock(t, `{"data":{"calls":0},"request_id":"r"}`)
	if _, err := c.ReadAuditUsage(context.Background(), testMachineToken, 7); !errors.Is(err, ErrInvalidResponse) {
		t.Fatal("accepted a report without a window")
	}
}
