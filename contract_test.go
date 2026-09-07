package auth

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
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
		Paths map[string]map[string]struct {
			OperationID string `json:"operationId"`
			Parameters  []struct {
				Name     string         `json:"name"`
				Required bool           `json:"required"`
				Schema   contractSchema `json:"schema"`
			} `json:"parameters"`
			RequestBody struct {
				Content map[string]struct {
					Schema contractSchema `json:"schema"`
				} `json:"content"`
			} `json:"requestBody"`
		} `json:"paths"`
		Components struct {
			Schemas map[string]contractSchema `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(data, &spec); err != nil {
		t.Fatal(err)
	}
	responses := map[string]string{
		"/openapi/v1/oauth/token":          `{"access_token":"` + testToken + `","token_type":"Bearer","expires_in":900,"scope":"profile:read"}`,
		"/openapi/v1/oauth/revoke":         "",
		"/openapi/v1/me":                   `{"data":{"id":1,"username":"u","name":"n","avatar":""},"request_id":"r"}`,
		"/openapi/v1/me/permissions":       `{"data":{"app_id":42,"user_id":1,"roles":[],"permissions":[]},"request_id":"r"}`,
		"/openapi/v1/me/permissions/check": `{"data":{"allowed":false},"request_id":"r"}`,
	}
	var requests []*http.Request
	c := newTestClient(t)
	c.httpClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		requests = append(requests, r)
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(responses[r.URL.Path]))}, nil
	})
	a, err := c.NewAuthorization(testRedirect, ScopeProfileRead, ScopePermissionsRead, ScopePermissionsCheck)
	if err != nil {
		t.Fatal(err)
	}
	authorize, err := http.NewRequest("GET", a.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	requests = append(requests, authorize)
	ctx := context.Background()
	if _, err := c.ExchangeCode(ctx, ExchangeCodeParams{Code: testCode, RedirectURI: testRedirect, CodeVerifier: testVerifier}); err != nil {
		t.Fatal(err)
	}
	if err := c.RevokeToken(ctx, RevokeTokenParams{Token: "unknown", TokenTypeHint: "access_token"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetCurrentUser(ctx, testToken); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetCurrentPermissions(ctx, testToken); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CheckCurrentPermission(ctx, testToken, "order.read"); err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]bool)
	for _, r := range requests {
		operation, ok := spec.Paths[r.URL.Path][strings.ToLower(r.Method)]
		if !ok {
			t.Fatalf("SDK operation absent from specification: %s %s", r.Method, r.URL.Path)
		}
		seen[operation.OperationID] = true
		query := r.URL.Query()
		allowedQuery := make(map[string]bool)
		for _, p := range operation.Parameters {
			allowedQuery[p.Name] = true
			if p.Required && len(query[p.Name]) != 1 {
				t.Fatalf("%s: missing/duplicate %s", operation.OperationID, p.Name)
			}
			checkContractValue(t, p.Name, query.Get(p.Name), p.Schema)
		}
		for key := range query {
			if !allowedQuery[key] {
				t.Fatalf("unexpected query parameter: %s", key)
			}
		}
		if len(operation.RequestBody.Content) == 0 {
			continue
		}
		content, ok := operation.RequestBody.Content[r.Header.Get("Content-Type")]
		if !ok {
			t.Fatalf("%s: unsupported Content-Type", operation.OperationID)
		}
		schema := content.Schema
		if schema.Ref != "" {
			schema = spec.Components.Schemas[strings.TrimPrefix(schema.Ref, "#/components/schemas/")]
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		values := make(map[string]string)
		if r.Header.Get("Content-Type") == "application/json" {
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
					t.Fatalf("duplicate form field %s", key)
				}
				values[key] = entries[0]
			}
		}
		for _, key := range schema.Required {
			if _, ok := values[key]; !ok {
				t.Fatalf("%s: missing body field %s", operation.OperationID, key)
			}
		}
		for key, value := range values {
			field, ok := schema.Properties[key]
			if !ok {
				t.Fatalf("%s: unknown body field %s", operation.OperationID, key)
			}
			checkContractValue(t, key, value, field)
		}
	}
	for _, methods := range spec.Paths {
		for _, operation := range methods {
			if !seen[operation.OperationID] {
				t.Errorf("SDK is missing operation %s", operation.OperationID)
			}
		}
	}
}

// Only the string constraints used in this API's requests are needed here.
type contractSchema struct {
	Ref        string                    `json:"$ref"`
	Const      json.RawMessage           `json:"const"`
	Pattern    string                    `json:"pattern"`
	MinLength  int                       `json:"minLength"`
	MaxLength  int                       `json:"maxLength"`
	Required   []string                  `json:"required"`
	Properties map[string]contractSchema `json:"properties"`
}

func checkContractValue(t *testing.T, field, value string, schema contractSchema) {
	t.Helper()
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
