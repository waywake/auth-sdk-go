package auth

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"
)

// ListAuditEventsParams narrows the application's own audit history. Before is
// the previous page's Next and walks towards older rows: the page is ordered by
// descending identifier. Every filter is optional.
type ListAuditEventsParams struct {
	Before int64
	Limit  int
	// Action restricts the page to one recorded action name.
	Action string
	// Outcome restricts the page to one recorded outcome.
	Outcome AuditOutcome
	// TargetType restricts the page to one recorded target kind.
	TargetType string
	// TargetID restricts the page to one recorded target identifier.
	TargetID int64
}

// ListAuditEvents reads this application's own audit history (audit:read). The
// page is scoped to the calling application: it holds the rows the application
// acted in, which carry actor_app_id, and the rows recorded about it, which
// carry app_id. A Next of zero means the history ends there.
func (c *Client) ListAuditEvents(ctx context.Context, machineToken string, params ListAuditEventsParams) (*AuditEventPageResponse, error) {
	if params.Before < 0 || params.Limit < 0 || params.Limit > MaxPageSize {
		return nil, invalid("Before/Limit", "must not be negative, and Limit must be at most 200")
	}
	query := url.Values{}
	if params.Before > 0 {
		query.Set("before", strconv.FormatInt(params.Before, 10))
	}
	if params.Limit > 0 {
		query.Set("limit", strconv.Itoa(params.Limit))
	}
	if params.Action != "" {
		if !validFilter("Action", params.Action) {
			return nil, invalid("Action", "must contain at most 128 characters and no control characters")
		}
		query.Set("action", params.Action)
	}
	switch params.Outcome {
	case "":
	case AuditOutcomeSuccess, AuditOutcomeFailure, AuditOutcomeUnknown:
		query.Set("outcome", string(params.Outcome))
	default:
		return nil, invalid("Outcome", "must be success, failure or unknown")
	}
	if params.TargetType != "" {
		if !validFilter("TargetType", params.TargetType) {
			return nil, invalid("TargetType", "must contain at most 128 characters and no control characters")
		}
		query.Set("target_type", params.TargetType)
	}
	if params.TargetID < 0 {
		return nil, invalid("TargetID", "must not be negative")
	}
	if params.TargetID > 0 {
		query.Set("target_id", strconv.FormatInt(params.TargetID, 10))
	}
	response, err := readResource[Page[AuditEvent]](ctx, c, request{
		method: http.MethodGet, path: "/audit/events", query: query,
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

// ReadAuditUsage reads the application's recorded call statistics over a window
// of calendar days ending today (audit:read). A window boundary is a calendar
// day in the deployment's time zone, not a rolling 24 hours. Zero selects the
// server default of DefaultAuditUsageDays; the maximum is MaxAuditUsageDays. An
// application with no recorded activity receives totals of zero rather than an
// error.
func (c *Client) ReadAuditUsage(ctx context.Context, machineToken string, days int) (*AuditUsageResponse, error) {
	if days < 0 || days > MaxAuditUsageDays {
		return nil, invalid("days", "must be between 1 and 30")
	}
	var query url.Values
	if days > 0 {
		query = url.Values{"days": {strconv.Itoa(days)}}
	}
	response, err := readResource[AuditUsage](ctx, c, request{
		method: http.MethodGet, path: "/audit/usage", query: query,
		cred: credentialMachineToken, token: machineToken,
	})
	if err != nil {
		return nil, err
	}
	if response.Data.From.IsZero() || response.Data.To.IsZero() {
		return nil, invalidResponse("missing usage window")
	}
	if response.Data.Buckets == nil || response.Data.Latency.Buckets == nil {
		return nil, invalidResponse("missing usage buckets")
	}
	return response, nil
}

func validFilter(field, value string) bool {
	if !utf8.ValidString(value) || utf8.RuneCountInString(value) > 128 {
		return false
	}
	return !strings.ContainsFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f })
}
