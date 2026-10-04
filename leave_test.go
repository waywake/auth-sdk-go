package auth

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

func TestGetEmployeeLeaveRequest(t *testing.T) {
	c, m := jsonMock(t, `{"data":{"user_id":7,"on_leave":true,"synced_at":"2026-10-04T10:00:00+08:00","records":[{"approval_id":"approval-1","item_id":"vacation-1","type_id":0,"type_name":"Annual leave","start_at":"2026-10-04T09:00:00+08:00","end_at":"2026-10-04T18:00:00+08:00","duration_seconds":28800,"unit":"hour","status":2}],"balances":[{"type_id":0,"type_name":"Annual leave","unit":"day","assigned_seconds":86400,"used_seconds":90000,"remaining_seconds":-3600}]},"request_id":"leave-request"}`)
	response, err := c.GetEmployeeLeave(context.Background(), testMachineToken, 7)
	if err != nil {
		t.Fatal(err)
	}
	request := m.only(t)
	if request.method != http.MethodGet || request.path != apiPath+"/leave/users/7" || request.token != bearer(testMachineToken) || len(request.query) != 0 || request.body != "" {
		t.Fatalf("request=%+v", request)
	}
	summary := response.Data
	wantSyncedAt := time.Date(2026, 10, 4, 2, 0, 0, 0, time.UTC)
	if response.RequestID != "leave-request" || summary.UserID != 7 || summary.OnLeave == nil || !*summary.OnLeave || summary.SyncedAt == nil || !summary.SyncedAt.Equal(wantSyncedAt) {
		t.Fatalf("response=%+v", response)
	}
	if len(summary.Records) != 1 || len(summary.Balances) != 1 {
		t.Fatalf("summary=%+v", summary)
	}
	record := summary.Records[0]
	if record.ApprovalID != "approval-1" || record.ItemID != "vacation-1" || record.TypeID != 0 || record.TypeName != "Annual leave" || record.DurationSeconds != 28800 || record.Unit != "hour" || record.Status != 2 || !record.EndAt.After(record.StartAt) {
		t.Fatalf("record=%+v", record)
	}
	balance := summary.Balances[0]
	if balance.TypeID != 0 || balance.TypeName != "Annual leave" || balance.Unit != "day" || balance.AssignedSeconds != 86400 || balance.UsedSeconds != 90000 || balance.RemainingSeconds != -3600 {
		t.Fatalf("balance=%+v", balance)
	}
}

func TestGetEmployeeLeavePreservesUnknownAndFalse(t *testing.T) {
	for _, tc := range []struct {
		name       string
		state      string
		wantSynced bool
	}{
		{"unsynchronized", `"on_leave":null,"synced_at":null`, false},
		{"synchronized empty", `"on_leave":false,"synced_at":"2026-10-04T02:00:00Z"`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := jsonMock(t, `{"data":{"user_id":7,`+tc.state+`,"records":[],"balances":[]},"request_id":"r"}`)
			response, err := c.GetEmployeeLeave(context.Background(), testMachineToken, 7)
			if err != nil {
				t.Fatal(err)
			}
			summary := response.Data
			if (summary.SyncedAt != nil) != tc.wantSynced || (summary.OnLeave != nil) != tc.wantSynced || (summary.OnLeave != nil && *summary.OnLeave) {
				t.Fatalf("summary=%+v", summary)
			}
			if summary.Records == nil || summary.Balances == nil || len(summary.Records) != 0 || len(summary.Balances) != 0 {
				t.Fatalf("summary=%+v", summary)
			}
		})
	}
}

func TestGetEmployeeLeaveInputValidation(t *testing.T) {
	c, m := jsonMock(t, `{"data":{"user_id":4294967295,"on_leave":null,"synced_at":null,"records":[],"balances":[]},"request_id":"r"}`)
	for _, id := range []int64{-1, 0, 1 << 32} {
		if _, err := c.GetEmployeeLeave(context.Background(), testMachineToken, id); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("userID=%d: err=%v", id, err)
		}
	}
	if got := m.requests(); len(got) != 0 {
		t.Fatalf("invalid input reached server: %+v", got)
	}
	if _, err := c.GetEmployeeLeave(context.Background(), testMachineToken, 1<<32-1); err != nil {
		t.Fatalf("maximum employee ID: %v", err)
	}
	if request := m.only(t); request.path != apiPath+"/leave/users/4294967295" {
		t.Fatalf("request=%+v", request)
	}
}

func TestGetEmployeeLeaveErrorCodes(t *testing.T) {
	for _, tc := range []struct {
		status int
		code   ErrorCode
	}{
		{http.StatusNotFound, ErrorNotFound},
		{http.StatusForbidden, ErrorInsufficientScope},
		{http.StatusServiceUnavailable, ErrorTemporarilyUnavailable},
	} {
		t.Run(string(tc.code), func(t *testing.T) {
			c, _ := errorMock(t, tc.status, tc.code)
			_, err := c.GetEmployeeLeave(context.Background(), testMachineToken, 7)
			var apiErr *APIError
			if !errors.As(err, &apiErr) || apiErr.StatusCode != tc.status || apiErr.Code != tc.code {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestInvalidEmployeeLeaveResponses(t *testing.T) {
	for _, data := range []string{
		`null`,
		`{}`,
		`{"user_id":8,"on_leave":null,"synced_at":null,"records":[],"balances":[]}`,
		`{"user_id":7,"on_leave":null,"synced_at":null,"records":null,"balances":[]}`,
		`{"user_id":7,"on_leave":null,"synced_at":null,"records":[],"balances":null}`,
		`{"user_id":7,"on_leave":false,"synced_at":null,"records":[],"balances":[]}`,
		`{"user_id":7,"on_leave":null,"synced_at":"2026-10-04T02:00:00Z","records":[],"balances":[]}`,
		`{"user_id":7,"on_leave":false,"synced_at":"0001-01-01T00:00:00Z","records":[],"balances":[]}`,
		`{"user_id":7,"on_leave":"false","synced_at":null,"records":[],"balances":[]}`,
		`{"user_id":7,"on_leave":false,"synced_at":"invalid","records":[],"balances":[]}`,
	} {
		c, _ := jsonMock(t, `{"data":`+data+`,"request_id":"r"}`)
		if _, err := c.GetEmployeeLeave(context.Background(), testMachineToken, 7); !errors.Is(err, ErrInvalidResponse) {
			t.Fatalf("data=%s: err=%v", data, err)
		}
	}
}
