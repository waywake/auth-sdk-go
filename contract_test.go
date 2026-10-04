package auth

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

// Contract checks use a checked-in snapshot by default. Point AUTH_OPENAPI_SPEC
// to auth-server/docs/openapi-v1.json to detect changes against a live checkout.
func TestOpenAPIContract(t *testing.T) {
	path := os.Getenv("AUTH_OPENAPI_SPEC")
	if path == "" {
		path = "docs/openapi-v1.json"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Paths      map[string]map[string]contractOperation `json:"paths"`
		Components struct {
			Schemas map[string]contractSchema `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(data, &spec); err != nil {
		t.Fatal(err)
	}
	t.Run("vocabularies", func(t *testing.T) { checkContractVocabularies(t, spec.Components.Schemas) })
	// Each path item mixes methods with non-operation members, so only the
	// method keys become operations and each one learns its own pattern.
	operations := make(map[string]contractOperation)
	for pattern, methods := range spec.Paths {
		for method, operation := range methods {
			if !isMethod(method) {
				continue
			}
			operation.method = strings.ToUpper(method)
			operation.pattern = pattern
			operation.schemas = spec.Components.Schemas
			operations[operation.OperationID] = operation
		}
	}

	requests := make([]*http.Request, 0, 64)
	c := newTestClient(t)
	c.httpClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		requests = append(requests, r)
		body, ok := contractResponse(r)
		if !ok {
			t.Errorf("contract mock has no response for %s %s", r.Method, r.URL.Path)
		}
		return &http.Response{
			StatusCode: 200,
			Header:     http.Header{"Content-Type": {"application/json; charset=utf-8"}},
			Body:       io.NopCloser(strings.NewReader(body)),
		}, nil
	})
	ctx := context.Background()
	exercised := make(map[string]bool)
	for _, call := range contractCalls {
		t.Run(call.name, func(t *testing.T) {
			before := len(requests)
			synthetic, err := call.invoke(t, c, ctx)
			if err != nil {
				t.Fatalf("%s: %v", call.name, err)
			}
			requests = append(requests, synthetic...)
			if len(requests) == before {
				t.Fatal("call issued no request")
			}
			for _, r := range requests[before:] {
				operation, ok := operationOf(operations, r)
				if !ok {
					t.Fatalf("SDK request absent from specification: %s %s", r.Method, r.URL.Path)
				}
				checkContractRequest(t, operation, r)
				exercised[operation.OperationID] = true
			}
		})
	}

	for id := range operations {
		if exercised[id] {
			continue
		}
		if _, ok := excludedOperations[id]; ok {
			continue
		}
		t.Errorf("SDK does not exercise operation %s", id)
	}
	for id := range excludedOperations {
		if _, ok := operations[id]; !ok {
			t.Errorf("excluded operation %s no longer exists in the specification", id)
		}
		if exercised[id] {
			t.Errorf("operation %s is both exercised and excluded", id)
		}
	}
}

// contractOperation is one operation of the specification, resolved against the
// component schemas it references.
type contractOperation struct {
	OperationID string `json:"operationId"`
	Parameters  []struct {
		Name     string         `json:"name"`
		In       string         `json:"in"`
		Required bool           `json:"required"`
		Schema   contractSchema `json:"schema"`
	} `json:"parameters"`
	RequestBody struct {
		Content map[string]struct {
			Schema contractSchema `json:"schema"`
		} `json:"content"`
	} `json:"requestBody"`

	method  string
	pattern string
	schemas map[string]contractSchema
}

// pathParameter matches one path template placeholder after QuoteMeta escaped
// its braces.
var pathParameter = regexp.MustCompile(`\\\{[^}]*\\\}`)

func isMethod(value string) bool {
	switch value {
	case "get", "post", "put", "patch", "delete", "head", "options":
		return true
	default:
		return false
	}
}

// operationOf resolves one concrete request onto the specification's path
// templates, so a call to /directory/users/7 still checks against
// /directory/users/{id}.
func operationOf(operations map[string]contractOperation, r *http.Request) (contractOperation, bool) {
	for _, operation := range operations {
		if operation.method != r.Method {
			continue
		}
		expression := "^" + pathParameter.ReplaceAllString(regexp.QuoteMeta(operation.pattern), "[^/]+") + "$"
		if regexp.MustCompile(expression).MatchString(r.URL.Path) {
			return operation, true
		}
	}
	return contractOperation{}, false
}

// checkContractRequest verifies one request against its operation: the declared
// parameters, no undeclared query key, and a body matching the declared media
// type and schema.
func checkContractRequest(t *testing.T, operation contractOperation, r *http.Request) {
	t.Helper()
	query := r.URL.Query()
	allowedQuery := make(map[string]bool)
	for _, p := range operation.Parameters {
		if p.In == "path" {
			// Path parameters are already bound by the template the request
			// matched; their values are the concrete identifiers the SDK sent.
			continue
		}
		allowedQuery[p.Name] = true
		if p.Required && len(query[p.Name]) != 1 {
			t.Fatalf("%s: missing/duplicate %s", operation.OperationID, p.Name)
		}
		if !p.Schema.array() && len(query[p.Name]) > 1 {
			t.Fatalf("%s: repeated %s", operation.OperationID, p.Name)
		}
		for _, value := range query[p.Name] {
			checkContractValue(t, p.Name, value, p.Schema)
		}
	}
	for key := range query {
		if !allowedQuery[key] {
			t.Fatalf("%s: unexpected query parameter %s", operation.OperationID, key)
		}
	}
	if len(operation.RequestBody.Content) == 0 {
		return
	}
	content, ok := operation.RequestBody.Content[r.Header.Get("Content-Type")]
	if !ok {
		t.Fatalf("%s: unsupported Content-Type %q", operation.OperationID, r.Header.Get("Content-Type"))
	}
	schema := content.Schema
	if schema.Ref != "" {
		schema = operation.schemas[strings.TrimPrefix(schema.Ref, "#/components/schemas/")]
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	values := make(map[string]json.RawMessage)
	if r.Header.Get("Content-Type") == jsonContentType {
		if err := json.Unmarshal(body, &values); err != nil {
			t.Fatal(err)
		}
	} else {
		form, err := url.ParseQuery(string(body))
		if err != nil {
			t.Fatal(err)
		}
		for key, entries := range form {
			if len(entries) != 1 {
				t.Fatalf("%s: duplicate form field %s", operation.OperationID, key)
			}
			values[key] = json.RawMessage(strconv.Quote(entries[0]))
		}
	}
	for _, key := range schema.Required {
		if _, ok := values[key]; !ok {
			t.Fatalf("%s: missing body field %s", operation.OperationID, key)
		}
	}
	for key, raw := range values {
		field, ok := schema.Properties[key]
		if !ok {
			t.Fatalf("%s: unknown body field %s", operation.OperationID, key)
		}
		if field.array() {
			var items []json.RawMessage
			if err := json.Unmarshal(raw, &items); err != nil {
				t.Fatalf("%s: %s is not an array", operation.OperationID, key)
			}
			if field.Items == nil {
				continue
			}
			for _, item := range items {
				checkContractValue(t, key, rawString(item), *field.Items)
			}
			continue
		}
		checkContractValue(t, key, rawString(raw), field)
	}
}

// rawString reads one JSON scalar as the string the constraint checks compare.
func rawString(raw json.RawMessage) string {
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return ""
	}
	return value
}

// Only the string constraints used in this API's requests are needed here.
type contractSchema struct {
	Ref        string                    `json:"$ref"`
	Enum       []json.RawMessage         `json:"enum"`
	Type       json.RawMessage           `json:"type"`
	Const      json.RawMessage           `json:"const"`
	Pattern    string                    `json:"pattern"`
	MinLength  int                       `json:"minLength"`
	MaxLength  int                       `json:"maxLength"`
	Required   []string                  `json:"required"`
	Properties map[string]contractSchema `json:"properties"`
	Items      *contractSchema           `json:"items"`
}

// array reports whether the schema is a JSON array, whose scalar string
// constraints do not apply.
func (s contractSchema) array() bool { return strings.Contains(string(s.Type), "array") }

func checkContractValue(t *testing.T, field, value string, schema contractSchema) {
	t.Helper()
	if schema.array() {
		return
	}
	if len(schema.Const) != 0 {
		var expected string
		if err := json.Unmarshal(schema.Const, &expected); err != nil {
			t.Fatal(err)
		}
		if value != expected {
			t.Errorf("%s violates const", field)
		}
	}
	if schema.Pattern != "" && !regexp.MustCompile(schema.Pattern).MatchString(value) {
		t.Errorf("%s violates pattern", field)
	}
	length := utf8.RuneCountInString(value)
	if length < schema.MinLength || (schema.MaxLength > 0 && length > schema.MaxLength) {
		t.Errorf("%s violates length", field)
	}
}

// The closed vocabularies affect local validation as well as documentation.
// Check their complete membership so a new server scope/event cannot silently
// remain rejected by the client after refreshing the contract snapshot.
func checkContractVocabularies(t *testing.T, schemas map[string]contractSchema) {
	t.Helper()
	machine := make([]string, 0, len(MachineScopeVocabulary()))
	for _, scope := range MachineScopeVocabulary() {
		machine = append(machine, string(scope))
	}
	user := make([]string, 0, len(UserScopeVocabulary()))
	for _, scope := range UserScopeVocabulary() {
		user = append(user, string(scope))
	}
	for _, tc := range []struct {
		name string
		got  []string
	}{
		{"machine_scopes", machine}, {"user_scopes", user},
	} {
		field := schemas["Settings"].Properties[tc.name]
		if field.Items == nil || !reflect.DeepEqual(tc.got, field.Items.stringEnum()) {
			t.Errorf("%s differs from the server vocabulary", tc.name)
		}
	}
	events := make([]string, 0, len(EventTypes()))
	for _, event := range EventTypes() {
		events = append(events, string(event))
	}
	if !reflect.DeepEqual(events, schemas["Event"].Properties["type"].stringEnum()) {
		t.Error("event types differ from the server vocabulary")
	}
}

func (s contractSchema) stringEnum() []string {
	values := make([]string, 0, len(s.Enum))
	for _, value := range s.Enum {
		values = append(values, rawString(value))
	}
	return values
}
