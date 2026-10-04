package auth

import "time"

// LeaveSummary is an employee's synchronized leave snapshot. OnLeave and
// SyncedAt are nil until the first successful synchronization; an unknown
// snapshot must not be treated as a confirmed absence of leave. Check SyncedAt
// before relying on its freshness. Leave never determines login eligibility.
type LeaveSummary struct {
	UserID   int64          `json:"user_id"`
	OnLeave  *bool          `json:"on_leave"`
	SyncedAt *time.Time     `json:"synced_at"`
	Records  []LeaveRecord  `json:"records"`
	Balances []LeaveBalance `json:"balances"`
}

// LeaveRecord is one upstream approval item. Only Status 2 (approved) can
// contribute to OnLeave. The server exposes neither reasons nor attachments.
type LeaveRecord struct {
	ApprovalID      string    `json:"approval_id"`
	ItemID          string    `json:"item_id"`
	TypeID          int64     `json:"type_id"`
	TypeName        string    `json:"type_name"`
	StartAt         time.Time `json:"start_at"`
	EndAt           time.Time `json:"end_at"`
	DurationSeconds int64     `json:"duration_seconds"`
	// Unit preserves the upstream "day" or "hour" unit.
	Unit string `json:"unit"`
	// Status is the WeCom approval status: 1, 2, 3, 4, 6, 7 or 10.
	Status int `json:"status"`
}

// LeaveBalance retains the upstream allowance. A day is 86400 seconds and an
// hour is 3600 seconds; RemainingSeconds may be negative under the upstream
// quota policy and must not be derived from AssignedSeconds and UsedSeconds.
type LeaveBalance struct {
	TypeID           int64  `json:"type_id"`
	TypeName         string `json:"type_name"`
	Unit             string `json:"unit"`
	AssignedSeconds  int64  `json:"assigned_seconds"`
	UsedSeconds      int64  `json:"used_seconds"`
	RemainingSeconds int64  `json:"remaining_seconds"`
}

// LeaveSummaryResponse wraps the employee's leave snapshot and request ID.
type LeaveSummaryResponse = Response[LeaveSummary]
