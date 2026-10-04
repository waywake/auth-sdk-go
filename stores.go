package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ListStoresParams narrows the stores inside the configured brand/store range.
// After is the previous StorePage.Next cursor. Limit is 1 to MaxStorePageSize;
// zero selects the server default of 50. Query searches store names/codes and
// accepts at most 256 UTF-8 bytes without control characters.
type ListStoresParams struct {
	After   string
	Limit   int
	BrandID int64
	Status  StoreStatus
	Query   string
}

func (p ListStoresParams) query() (url.Values, error) {
	if len(p.After) > 256 {
		return nil, invalid("After", "must contain at most 256 bytes")
	}
	if p.Limit < 0 || p.Limit > MaxStorePageSize {
		return nil, invalid("Limit", "must be between 1 and 100")
	}
	if p.BrandID < 0 || p.BrandID > MaxStoreID {
		return nil, invalid("BrandID", "must be between 1 and 9007199254740991")
	}
	if !utf8.ValidString(p.Query) || len(p.Query) > 256 || strings.IndexFunc(p.Query, unicode.IsControl) >= 0 {
		return nil, invalid("Query", "must contain at most 256 UTF-8 bytes without control characters")
	}
	switch p.Status {
	case "", StoreStatusPreparing, StoreStatusOpen, StoreStatusSuspended, StoreStatusClosed:
	default:
		return nil, invalid("Status", "must be preparing, open, suspended or closed")
	}
	query := url.Values{}
	if p.After != "" {
		query.Set("after", p.After)
	}
	if p.Limit != 0 {
		query.Set("limit", strconv.Itoa(p.Limit))
	}
	if p.BrandID != 0 {
		query.Set("brand_id", strconv.FormatInt(p.BrandID, 10))
	}
	if p.Status != "" {
		query.Set("status", string(p.Status))
	}
	if p.Query != "" {
		query.Set("q", p.Query)
	}
	return query, nil
}

func validStoreID(field string, id int64) error {
	if id <= 0 || id > MaxStoreID {
		return invalid(field, "must be between 1 and 9007199254740991")
	}
	return nil
}

// ListStores reads the stores inside the application's current brand/store
// range (stores:read). Pagination cursors are bound to the application, filters
// and authorization policy; pass them unchanged and restart if policy changes.
func (c *Client) ListStores(ctx context.Context, machineToken string, params ListStoresParams) (*StorePageResponse, error) {
	query, err := params.query()
	if err != nil {
		return nil, err
	}
	response, err := readResource[struct {
		Items   []Store `json:"items"`
		Next    *string `json:"next"`
		HasMore *bool   `json:"has_more"`
	}](ctx, c, request{
		method: http.MethodGet, path: "/stores", query: query,
		cred: credentialMachineToken, token: machineToken,
	})
	if err != nil {
		return nil, err
	}
	if err := ensureNotNilItems(response.Data.Items); err != nil {
		return nil, err
	}
	if response.Data.Next == nil || response.Data.HasMore == nil {
		return nil, invalidResponse("missing store pagination fields")
	}
	page := StorePage{Items: response.Data.Items, Next: *response.Data.Next, HasMore: *response.Data.HasMore}
	if page.HasMore != (page.Next != "") || page.HasMore && len(page.Items) == 0 {
		return nil, invalidResponse("inconsistent store pagination")
	}
	return &StorePageResponse{Data: page, RequestID: response.RequestID}, nil
}

// GetStore reads one visible store (stores:read). Missing and hidden stores
// both return not_found.
func (c *Client) GetStore(ctx context.Context, machineToken string, storeID int64) (*StoreResponse, error) {
	if err := validStoreID("storeID", storeID); err != nil {
		return nil, err
	}
	response, err := readResource[Store](ctx, c, request{
		method: http.MethodGet, path: "/stores/" + strconv.FormatInt(storeID, 10),
		cred: credentialMachineToken, token: machineToken,
	})
	if err != nil {
		return nil, err
	}
	if response.Data.ID != storeID || response.Data.BrandID <= 0 || response.Data.Version <= 0 {
		return nil, invalidResponse("missing or inconsistent store identity")
	}
	return response, nil
}

// GetStoreReceivingAddress reads delivery details (stores:read and
// stores:delivery:read). Data is nil when no address is configured; a hidden or
// missing store returns not_found instead.
func (c *Client) GetStoreReceivingAddress(ctx context.Context, machineToken string, storeID int64) (*StoreReceivingAddressResponse, error) {
	if err := validStoreID("storeID", storeID); err != nil {
		return nil, err
	}
	// Unlike other resource envelopes, this endpoint deliberately returns null
	// data. RawMessage distinguishes that valid result from an absent member.
	var envelope struct {
		Data      json.RawMessage `json:"data"`
		RequestID *string         `json:"request_id"`
	}
	if err := c.do(ctx, request{
		method: http.MethodGet, path: "/stores/" + strconv.FormatInt(storeID, 10) + "/receiving-address",
		cred: credentialMachineToken, token: machineToken,
	}, &envelope); err != nil {
		return nil, err
	}
	if len(envelope.Data) == 0 || envelope.RequestID == nil {
		return nil, invalidResponse("missing data or request_id")
	}
	var address *StoreReceivingAddress
	if err := json.Unmarshal(envelope.Data, &address); err != nil {
		return nil, invalidResponse("malformed receiving address")
	}
	if address != nil && (address.StoreID != storeID || address.Version <= 0) {
		return nil, invalidResponse("missing or inconsistent receiving address identity")
	}
	return &StoreReceivingAddressResponse{Data: address, RequestID: *envelope.RequestID}, nil
}

// GetStoreEmployees reads active, visible relationships in a store
// (stores:read, stores:members:read and directory:read). Both the live store
// range and directory range apply. The result has no employee profile fields.
func (c *Client) GetStoreEmployees(ctx context.Context, machineToken string, storeID int64) (*StoreEmployeesResponse, error) {
	if err := validStoreID("storeID", storeID); err != nil {
		return nil, err
	}
	response, err := readResource[StoreEmployees](ctx, c, request{
		method: http.MethodGet, path: "/stores/" + strconv.FormatInt(storeID, 10) + "/employees",
		cred: credentialMachineToken, token: machineToken,
	})
	if err != nil {
		return nil, err
	}
	if err := ensureNotNilItems(response.Data.Items); err != nil {
		return nil, err
	}
	if response.Data.EvaluatedAt.IsZero() {
		return nil, invalidResponse("missing store employees evaluation instant")
	}
	return response, nil
}

// GetEmployeeStores reads an employee's visible primary store, secondments and
// other relationships (stores:read, stores:members:read and directory:read).
// Missing employees and employees outside the directory range return not_found.
func (c *Client) GetEmployeeStores(ctx context.Context, machineToken string, userID int64) (*EmployeeStoresResponse, error) {
	if userID <= 0 || userID > 1<<32-1 {
		return nil, invalid("userID", "must be between 1 and 4294967295")
	}
	response, err := readResource[EmployeeStores](ctx, c, request{
		method: http.MethodGet, path: "/directory/users/" + strconv.FormatInt(userID, 10) + "/stores",
		cred: credentialMachineToken, token: machineToken,
	})
	if err != nil {
		return nil, err
	}
	if response.Data.UserID != userID || response.Data.Secondments == nil || response.Data.OtherRelations == nil || response.Data.EvaluatedAt.IsZero() {
		return nil, invalidResponse("missing or inconsistent employee store relationships")
	}
	return response, nil
}

func validExternalStoreKey(key ExternalStoreKey) error {
	for _, field := range []struct{ name, value string }{{"Provider", key.Provider}, {"Namespace", key.Namespace}} {
		if strings.IndexFunc(field.value, unicode.IsControl) >= 0 {
			return invalid(field.name, "must not contain control characters")
		}
		value := strings.ToUpper(strings.TrimSpace(field.value))
		if len(value) == 0 || len(value) > 32 {
			return invalid(field.name, "must contain 1–32 code characters after normalization")
		}
		for _, char := range value {
			if !(char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '_' || char == '-') {
				return invalid(field.name, "must contain only letters, digits, underscores or hyphens")
			}
		}
	}
	for _, field := range []struct{ name, value string }{{"TenantKey", key.TenantKey}, {"ExternalID", key.ExternalID}} {
		if field.value == "" || len(field.value) > 128 || !utf8.ValidString(field.value) || field.value != strings.TrimSpace(field.value) || strings.IndexFunc(field.value, unicode.IsControl) >= 0 {
			return invalid(field.name, "must contain 1–128 UTF-8 bytes without control characters or surrounding whitespace")
		}
	}
	return nil
}

// LookupExternalStores resolves one to MaxStoreLookupKeys external identities
// (stores:read). Results preserve request order, including duplicate keys.
// A nil binding covers missing, unbound and out-of-scope stores equally.
func (c *Client) LookupExternalStores(ctx context.Context, machineToken string, identities []ExternalStoreKey) (*ExternalStoreLookupResponse, error) {
	if len(identities) == 0 || len(identities) > MaxStoreLookupKeys {
		return nil, invalid("identities", "must contain one to 100 keys")
	}
	for _, key := range identities {
		if err := validExternalStoreKey(key); err != nil {
			return nil, err
		}
	}
	body, err := jsonBody(struct {
		Identities []ExternalStoreKey `json:"identities"`
	}{identities})
	if err != nil {
		return nil, err
	}
	response, err := readResource[[]ExternalStoreLookup](ctx, c, request{
		method: http.MethodPost, path: "/stores/external-identities/lookup",
		contentType: jsonContentType, body: body,
		cred: credentialMachineToken, token: machineToken,
	})
	if err != nil {
		return nil, err
	}
	if len(response.Data) != len(identities) {
		return nil, invalidResponse("external store lookup count does not match request")
	}
	return response, nil
}
