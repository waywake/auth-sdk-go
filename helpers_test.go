package auth

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
)

// mockRequest records what one mock endpoint received.
type mockRequest struct {
	method string
	path   string
	query  url.Values
	token  string
	ctype  string
	body   string
}

// mockServer answers every request with one canned response and records what it
// received, so a test can assert both halves of a call.
type mockServer struct {
	*httptest.Server
	mu     sync.Mutex
	seen   []mockRequest
	answer func(mockRequest) (int, string)
}

// newMock starts a mock endpoint and returns a client aimed at it.
func newMock(t *testing.T, answer func(mockRequest) (int, string)) (*Client, *mockServer) {
	t.Helper()
	m := &mockServer{answer: answer}
	m.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		entry := mockRequest{
			method: r.Method, path: r.URL.Path, query: r.URL.Query(),
			token: r.Header.Get("Authorization"), ctype: r.Header.Get("Content-Type"), body: string(data),
		}
		m.mu.Lock()
		m.seen = append(m.seen, entry)
		m.mu.Unlock()
		status, body := 200, ""
		if m.answer != nil {
			status, body = m.answer(entry)
		}
		if body != "" {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(m.Close)
	return clientForServer(t, m.Server), m
}

// jsonMock answers every request with one JSON document.
func jsonMock(t *testing.T, body string) (*Client, *mockServer) {
	t.Helper()
	return newMock(t, func(mockRequest) (int, string) { return 200, body })
}

// errorMock answers every request with one error envelope.
func errorMock(t *testing.T, status int, code ErrorCode) (*Client, *mockServer) {
	t.Helper()
	return newMock(t, func(mockRequest) (int, string) {
		return status, `{"error":"` + string(code) + `","request_id":"r"}`
	})
}

// requests returns a copy of what the mock has received so far.
func (m *mockServer) requests() []mockRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]mockRequest(nil), m.seen...)
}

// only returns the single request the mock received, failing the test on any
// other count.
func (m *mockServer) only(t *testing.T) mockRequest {
	t.Helper()
	seen := m.requests()
	if len(seen) != 1 {
		t.Fatalf("expected exactly one request, got %d: %+v", len(seen), seen)
	}
	return seen[0]
}

// bearer returns the expected Authorization header of one employee or machine
// call.
func bearer(token string) string { return "Bearer " + token }
