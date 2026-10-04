package auth

import "time"

const (
	// MaxStorePageSize is the maximum number of stores returned in one page.
	MaxStorePageSize = 100
	// MaxStoreLookupKeys is the maximum number of external identities per lookup.
	MaxStoreLookupKeys = 100
	// MaxStoreID is the largest supported store or brand identifier.
	MaxStoreID int64 = 1<<53 - 1
)

// StoreStatus is the operational state of a store.
type StoreStatus string

const (
	StoreStatusPreparing StoreStatus = "preparing"
	StoreStatusOpen      StoreStatus = "open"
	StoreStatusSuspended StoreStatus = "suspended"
	StoreStatusClosed    StoreStatus = "closed"
)

// Store describes a store inside the application's current brand/store range.
type Store struct {
	ID       int64       `json:"id"`
	BrandID  int64       `json:"brand_id"`
	Code     string      `json:"code"`
	Name     string      `json:"name"`
	Status   StoreStatus `json:"status"`
	Location string      `json:"location"`
	Version  int64       `json:"version"`
}

// StorePage uses an opaque cursor rather than Page's numeric keyset cursor.
// When HasMore is true, pass Next unchanged as ListStoresParams.After with the
// same filters. A changed authorization policy requires restarting pagination.
type StorePage struct {
	Items   []Store `json:"items"`
	Next    string  `json:"next"`
	HasMore bool    `json:"has_more"`
}

// StoreReceivingAddress contains the store's configured delivery details.
type StoreReceivingAddress struct {
	StoreID                 int64  `json:"store_id"`
	Region                  string `json:"region"`
	Address                 string `json:"address"`
	ContactName             string `json:"contact_name"`
	ContactPhone            string `json:"contact_phone"`
	DeliveryTimeRequirement string `json:"delivery_time_requirement"`
	Version                 int64  `json:"version"`
}

// StorePosition is an employee's active position within a store assignment.
// PositionCode is store_manager or sales_associate. Periods include StartedAt
// and exclude EndedAt; a nil EndedAt has no scheduled end.
type StorePosition struct {
	ID           int64      `json:"id"`
	PositionCode string     `json:"position_code"`
	StartedAt    time.Time  `json:"started_at"`
	EndedAt      *time.Time `json:"ended_at"`
}

// StoreAssignment is a visible employee relationship at EvaluatedAt. Kind is
// employment or receiving_contact; AssignmentType is primary or secondment for
// employment and empty for receiving_contact. Disabled employees can remain in
// the result, while departed employees are omitted. Positions is always an
// array and is empty for receiving contacts.
type StoreAssignment struct {
	ID              int64           `json:"id"`
	StoreID         int64           `json:"store_id"`
	UserID          int64           `json:"user_id"`
	Kind            string          `json:"kind"`
	AssignmentType  string          `json:"assignment_type"`
	StartedAt       time.Time       `json:"started_at"`
	EndedAt         *time.Time      `json:"ended_at"`
	Positions       []StorePosition `json:"positions"`
	EmployeeEnabled bool            `json:"employee_enabled"`
}

// StoreEmployees contains the currently visible relationships for one store.
// NextChangeAt is the next known change among visible relationships and
// positions; the server evaluates the entire result at EvaluatedAt.
type StoreEmployees struct {
	Items        []StoreAssignment `json:"items"`
	EvaluatedAt  time.Time         `json:"evaluated_at"`
	NextChangeAt *time.Time        `json:"next_change_at"`
}

// StorePlacement combines a store with the employee's active relationship.
type StorePlacement struct {
	Store      Store           `json:"store"`
	Assignment StoreAssignment `json:"assignment"`
}

// EmployeeStores groups an employee's visible relationships at EvaluatedAt.
// A nil PrimaryStore means no visible primary store; it does not disclose
// whether an out-of-scope primary store exists.
type EmployeeStores struct {
	UserID         int64            `json:"user_id"`
	PrimaryStore   *StorePlacement  `json:"primary_store"`
	Secondments    []StorePlacement `json:"secondments"`
	OtherRelations []StorePlacement `json:"other_relations"`
	EvaluatedAt    time.Time        `json:"evaluated_at"`
	NextChangeAt   *time.Time       `json:"next_change_at"`
}

// ExternalStoreKey identifies a store in an external system. The server trims
// and uppercases Provider and Namespace. TenantKey and ExternalID are opaque,
// case-sensitive values and cannot contain surrounding whitespace.
type ExternalStoreKey struct {
	Provider   string `json:"provider"`
	TenantKey  string `json:"tenant_key"`
	Namespace  string `json:"namespace"`
	ExternalID string `json:"external_id"`
}

// ExternalStoreBinding identifies a visible store and the binding's version.
type ExternalStoreBinding struct {
	StoreID int64 `json:"store_id"`
	Version int64 `json:"version"`
}

// ExternalStoreLookup preserves request order and echoes the normalized
// identity. Binding is nil when the identity is unbound, missing or hidden.
type ExternalStoreLookup struct {
	Identity ExternalStoreKey      `json:"identity"`
	Binding  *ExternalStoreBinding `json:"binding"`
}

type (
	StoreResponse     = Response[Store]
	StorePageResponse = Response[StorePage]
	// StoreReceivingAddressResponse has nil Data when no address is configured.
	StoreReceivingAddressResponse = Response[*StoreReceivingAddress]
	StoreEmployeesResponse        = Response[StoreEmployees]
	EmployeeStoresResponse        = Response[EmployeeStores]
	ExternalStoreLookupResponse   = Response[[]ExternalStoreLookup]
)
