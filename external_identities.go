package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// LookupDirectoryExternalIdentities resolves one to MaxExternalIdentityBatch
// external keys inside the application's directory range (directory:read).
// Results preserve request order, including duplicates. Absent, unbound,
// departed and out-of-range identities all have a nil Binding.
func (c *Client) LookupDirectoryExternalIdentities(ctx context.Context, machineToken string, identities []ExternalIdentityKey) (*ExternalIdentityLookupResponse, error) {
	if len(identities) == 0 || len(identities) > MaxExternalIdentityBatch {
		return nil, invalid("identities", "must contain one to 100 keys")
	}
	canonical := make([]ExternalIdentityKey, len(identities))
	for i, key := range identities {
		var err error
		canonical[i], err = normalizeExternalIdentityKey(key)
		if err != nil {
			return nil, err
		}
	}
	body, err := jsonBody(struct {
		Identities []ExternalIdentityKey `json:"identities"`
	}{identities})
	if err != nil {
		return nil, err
	}
	response, err := readResource[[]struct {
		Identity ExternalIdentityKey `json:"identity"`
		Binding  json.RawMessage     `json:"binding"`
	}](ctx, c, request{
		method: http.MethodPost, path: "/directory/external-identities/lookup",
		contentType: jsonContentType, body: body,
		cred: credentialMachineToken, token: machineToken,
	})
	if err != nil {
		return nil, err
	}
	if len(response.Data) != len(identities) {
		return nil, invalidResponse("external identity lookup count differs from request")
	}
	items := make([]ExternalIdentityLookup, len(response.Data))
	for i, item := range response.Data {
		if item.Identity != canonical[i] || len(item.Binding) == 0 {
			return nil, invalidResponse("missing or mismatched external identity lookup")
		}
		var binding *struct {
			UserID    int64      `json:"user_id"`
			Version   int64      `json:"version"`
			Enabled   *bool      `json:"enabled"`
			UpdatedAt *time.Time `json:"updated_at"`
		}
		if err := json.Unmarshal(item.Binding, &binding); err != nil {
			return nil, invalidResponse("malformed external identity binding")
		}
		items[i].Identity = item.Identity
		if binding != nil {
			if binding.UserID <= 0 || binding.UserID > 1<<32-1 || binding.Version <= 0 || binding.Enabled == nil || binding.UpdatedAt == nil {
				return nil, invalidResponse("missing or invalid external identity binding fields")
			}
			items[i].Binding = &ExternalIdentityBinding{
				UserID: binding.UserID, Version: binding.Version,
				Enabled: *binding.Enabled, UpdatedAt: *binding.UpdatedAt,
			}
		}
	}
	return &ExternalIdentityLookupResponse{Data: items, RequestID: response.RequestID}, nil
}

// ListDirectoryEmployeeExternalIdentities reads confirmed identities for one
// to MaxExternalIdentityBatch employee IDs (directory:read). The server
// deduplicates IDs in input order and omits out-of-range or departed employees.
// Readable employees without confirmed identities have an empty identity list.
func (c *Client) ListDirectoryEmployeeExternalIdentities(ctx context.Context, machineToken string, userIDs []int64) (*EmployeeExternalIdentitiesResponse, error) {
	if len(userIDs) == 0 || len(userIDs) > MaxExternalIdentityBatch {
		return nil, invalid("userIDs", "must contain one to 100 identifiers")
	}
	for _, id := range userIDs {
		if id <= 0 || id > 1<<32-1 {
			return nil, invalid("userIDs", "must be between 1 and 4294967295")
		}
	}
	body, err := jsonBody(struct {
		UserIDs []int64 `json:"user_ids"`
	}{userIDs})
	if err != nil {
		return nil, err
	}
	response, err := readResource[[]struct {
		UserID     int64                      `json:"user_id"`
		Enabled    *bool                      `json:"enabled"`
		Identities []EmployeeExternalIdentity `json:"identities"`
	}](ctx, c, request{
		method: http.MethodPost, path: "/directory/users/external-identities",
		contentType: jsonContentType, body: body,
		cred: credentialMachineToken, token: machineToken,
	})
	if err != nil {
		return nil, err
	}
	items := make([]EmployeeExternalIdentities, 0, len(response.Data))
	for _, item := range response.Data {
		if item.UserID <= 0 || item.UserID > 1<<32-1 || item.Enabled == nil || item.Identities == nil {
			return nil, invalidResponse("missing or invalid employee external identities")
		}
		for _, identity := range item.Identities {
			if _, err := normalizeExternalIdentityKey(identity.Identity); err != nil || identity.Version <= 0 || identity.UpdatedAt.IsZero() {
				return nil, invalidResponse("missing or invalid employee external identity fields")
			}
		}
		items = append(items, EmployeeExternalIdentities{UserID: item.UserID, Enabled: *item.Enabled, Identities: item.Identities})
	}
	return &EmployeeExternalIdentitiesResponse{Data: items, RequestID: response.RequestID}, nil
}

// normalizeExternalIdentityKey follows the owning directory service's key
// rules. In particular, controls are rejected before trimming, and opaque IDs
// are bounded in UTF-8 bytes rather than runes.
func normalizeExternalIdentityKey(key ExternalIdentityKey) (ExternalIdentityKey, error) {
	for _, value := range []string{key.Provider, key.TenantID, key.Namespace, key.ExternalID} {
		if !utf8.ValidString(value) {
			return ExternalIdentityKey{}, invalid("identity", "must contain valid UTF-8")
		}
		for _, r := range value {
			if unicode.IsControl(r) {
				return ExternalIdentityKey{}, invalid("identity", "must not contain control characters")
			}
		}
	}
	key.Provider = strings.ToUpper(strings.TrimSpace(key.Provider))
	key.Namespace = strings.ToUpper(strings.TrimSpace(key.Namespace))
	key.TenantID = strings.TrimSpace(key.TenantID)
	key.ExternalID = strings.TrimSpace(key.ExternalID)
	for _, value := range []string{key.Provider, key.Namespace} {
		if len(value) == 0 || len(value) > 32 {
			return ExternalIdentityKey{}, invalid("identity provider/namespace", "must contain 1–32 ASCII letters, digits, underscores or hyphens")
		}
		for _, r := range value {
			if !((r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-') {
				return ExternalIdentityKey{}, invalid("identity provider/namespace", "must contain only ASCII letters, digits, underscores or hyphens")
			}
		}
	}
	for _, value := range []string{key.TenantID, key.ExternalID} {
		if len(value) == 0 || len(value) > 128 {
			return ExternalIdentityKey{}, invalid("identity tenant/external ID", "must contain 1–128 UTF-8 bytes")
		}
	}
	return key, nil
}
