package auth

import "time"

// MaxExternalIdentityBatch is the largest batch accepted by the directory's
// external-identity lookup and employee-identity listing endpoints.
const MaxExternalIdentityBatch = 100

// ExternalIdentityKey identifies an external account within a provider tenant
// and namespace. Provider and Namespace are trimmed and uppercased by the
// server; TenantID and ExternalID are trimmed but remain case-sensitive.
type ExternalIdentityKey struct {
	Provider   string `json:"provider"`
	TenantID   string `json:"tenant_id"`
	Namespace  string `json:"namespace"`
	ExternalID string `json:"external_id"`
}

// ExternalIdentityBinding is a confirmed employee mapping. Disabled employees
// retain their mappings with Enabled false; a binding alone never proves login
// eligibility or authorization.
type ExternalIdentityBinding struct {
	UserID    int64     `json:"user_id"`
	Version   int64     `json:"version"`
	Enabled   bool      `json:"enabled"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ExternalIdentityLookup answers one requested key. Binding is nil for an
// absent, unbound, departed or out-of-range identity.
type ExternalIdentityLookup struct {
	Identity ExternalIdentityKey      `json:"identity"`
	Binding  *ExternalIdentityBinding `json:"binding"`
}

// EmployeeExternalIdentity is one confirmed identity of a readable employee.
type EmployeeExternalIdentity struct {
	Identity  ExternalIdentityKey `json:"identity"`
	Version   int64               `json:"version"`
	UpdatedAt time.Time           `json:"updated_at"`
}

// EmployeeExternalIdentities contains the confirmed identities of one readable
// employee. Identities is empty when that employee has no confirmed mapping.
type EmployeeExternalIdentities struct {
	UserID     int64                      `json:"user_id"`
	Enabled    bool                       `json:"enabled"`
	Identities []EmployeeExternalIdentity `json:"identities"`
}

type ExternalIdentityLookupResponse = Response[[]ExternalIdentityLookup]
type EmployeeExternalIdentitiesResponse = Response[[]EmployeeExternalIdentities]
