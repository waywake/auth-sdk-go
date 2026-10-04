package auth

import (
	"context"
	"net/http"
	"strconv"
)

// GetEmployeeLeave reads an employee's leave records and balances (leave:read).
// This requires a machine token with the independent leave scope; directory:read
// alone does not authorize this data. The server rechecks the current directory
// range on every call and answers not_found for hidden or departed employees.
// An unconfigured leave source answers temporarily_unavailable.
func (c *Client) GetEmployeeLeave(ctx context.Context, machineToken string, userID int64) (*LeaveSummaryResponse, error) {
	if userID <= 0 || userID > 1<<32-1 {
		return nil, invalid("userID", "must be between 1 and 4294967295")
	}
	response, err := readResource[LeaveSummary](ctx, c, request{
		method: http.MethodGet, path: "/leave/users/" + strconv.FormatInt(userID, 10),
		cred: credentialMachineToken, token: machineToken,
	})
	if err != nil {
		return nil, err
	}
	summary := response.Data
	if summary.UserID != userID {
		return nil, invalidResponse("missing or mismatched employee ID")
	}
	if summary.Records == nil || summary.Balances == nil {
		return nil, invalidResponse("missing leave records or balances")
	}
	if (summary.OnLeave == nil) != (summary.SyncedAt == nil) {
		return nil, invalidResponse("inconsistent leave synchronization state")
	}
	if summary.SyncedAt != nil && summary.SyncedAt.IsZero() {
		return nil, invalidResponse("missing leave synchronization instant")
	}
	return response, nil
}
