// Package testutil provides testing utilities and mocks for the Eos project
package testutil

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/httpclient"
)

// TestRuntimeContext creates a properly initialized RuntimeContext for testing
func TestRuntimeContext(t *testing.T) *eos_io.RuntimeContext {
	t.Helper()
	ctx := context.Background()
	return eos_io.NewContext(ctx, "test")
}

// TestRuntimeContextWithTimeout creates a test context with a specific timeout
func TestRuntimeContextWithTimeout(t *testing.T, timeout time.Duration) (*eos_io.RuntimeContext, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	rc := eos_io.NewContext(ctx, "test")
	return rc, cancel
}

// TestRuntimeContextWithCancel creates a test context that can be cancelled
func TestRuntimeContextWithCancel(t *testing.T) (*eos_io.RuntimeContext, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	rc := eos_io.NewContext(ctx, "test")
	return rc, cancel
}

// MockHTTPTransport provides a customizable HTTP transport for testing
type MockHTTPTransport struct {
	// ResponseMap maps URL paths to response data
	ResponseMap map[string]MockResponse
	// DefaultResponse is used when no specific response is found
	DefaultResponse MockResponse
}

// MockResponse defines a mock HTTP response
type MockResponse struct {
	StatusCode int
	Body       any // Will be JSON-encoded
	Headers    map[string]string
}

// RoundTrip implements http.RoundTripper interface
func (m *MockHTTPTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	response := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Request:    req,
	}

	// Look for specific response for this path
	mockResp, exists := m.ResponseMap[req.URL.Path]
	if !exists {
		mockResp = m.DefaultResponse
	}

	// Set status code
	if mockResp.StatusCode != 0 {
		response.StatusCode = mockResp.StatusCode
	}

	// Set headers
	response.Header.Set("Content-Type", "application/json")
	for key, value := range mockResp.Headers {
		response.Header.Set(key, value)
	}

	// Set body
	var bodyData []byte
	if mockResp.Body != nil {
		var err error
		bodyData, err = json.Marshal(mockResp.Body)
		if err != nil {
			response.StatusCode = 500
			bodyData = []byte(`{"error": "failed to marshal mock response"}`)
		}
	}

	response.Body = &mockResponseBody{data: bodyData}
	response.ContentLength = int64(len(bodyData))

	return response, nil
}

// mockResponseBody implements io.ReadCloser for mock response bodies
type mockResponseBody struct {
	data []byte
	pos  int
}

func (m *mockResponseBody) Read(p []byte) (n int, err error) {
	if m.pos >= len(m.data) {
		return 0, io.EOF
	}

	n = copy(p, m.data[m.pos:])
	m.pos += n
	if m.pos >= len(m.data) {
		err = io.EOF
	}
	return n, err
}

func (m *mockResponseBody) Close() error {
	return nil
}

// WithMockHTTPClient replaces the default HTTP client for the duration of the test
func WithMockHTTPClient(t *testing.T, transport *MockHTTPTransport) func() {
	t.Helper()

	originalClient := httpclient.DefaultClient()
	mockClient := &http.Client{Transport: transport}
	httpclient.SetDefaultClient(mockClient)

	return func() {
		httpclient.SetDefaultClient(originalClient)
	}
}

// WazuhMockTransport creates a mock transport for Wazuh API calls
func WazuhMockTransport() *MockHTTPTransport {
	return &MockHTTPTransport{
		ResponseMap: map[string]MockResponse{
			"/security/users": {
				StatusCode: 200,
				Body: map[string]any{
					"data": []map[string]any{
						{"id": "user-123", "username": "alice"},
						{"id": "user-456", "username": "bob"},
						{"id": "user-789", "username": "charlie"},
					},
				},
			},
			"/security/roles": {
				StatusCode: 200,
				Body: map[string]any{
					"data": []map[string]any{
						{"id": "role-123", "name": "role_alice"},
						{"id": "role-456", "name": "role_bob"},
						{"id": "role-789", "name": "admin"},
					},
				},
			},
			"/security/policies": {
				StatusCode: 200,
				Body: map[string]any{
					"data": []map[string]any{
						{"id": "policy-123", "name": "policy_alice"},
						{"id": "policy-456", "name": "policy_bob"},
						{"id": "policy-789", "name": "read_only"},
					},
				},
			},
			"/groups": {
				StatusCode: 201,
				Body: map[string]any{
					"data": map[string]any{
						"group_id": "group_test",
						"message":  "Group created successfully",
					},
				},
			},
		},
		DefaultResponse: MockResponse{
			StatusCode: 404,
			Body:       map[string]any{"error": "not found"},
		},
	}
}

// VaultMockTransport creates a mock transport for HashiCorp Vault API calls
func VaultMockTransport() *MockHTTPTransport {
	return &MockHTTPTransport{
		ResponseMap: map[string]MockResponse{
			"/v1/sys/health": {
				StatusCode: 200,
				Body: map[string]any{
					"initialized": true,
					"sealed":      false,
					"standby":     false,
				},
			},
			"/v1/auth/userpass/users": {
				StatusCode: 200,
				Body: map[string]any{
					"data": map[string]any{
						"users": []string{"alice", "bob"},
					},
				},
			},
		},
		DefaultResponse: MockResponse{
			StatusCode: 404,
			Body:       map[string]any{"errors": []string{"path not found"}},
		},
	}
}

// DockerMockTransport creates a mock transport for Docker API calls
func DockerMockTransport() *MockHTTPTransport {
	return &MockHTTPTransport{
		ResponseMap: map[string]MockResponse{
			"/containers/json": {
				StatusCode: 200,
				Body: []map[string]any{
					{
						"Id":    "container123",
						"Names": []string{"/test-container"},
						"State": "running",
					},
				},
			},
			"/images/json": {
				StatusCode: 200,
				Body: []map[string]any{
					{
						"Id":       "image123",
						"RepoTags": []string{"nginx:latest"},
					},
				},
			},
		},
		DefaultResponse: MockResponse{
			StatusCode: 404,
			Body:       map[string]any{"message": "not found"},
		},
	}
}

// AssertNoError is a helper that fails the test if err is not nil
func AssertNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

// AssertError is a helper that fails the test if err is nil
func AssertError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
}

// AssertErrorContains checks that an error contains a specific substring
func AssertErrorContains(t *testing.T, err error, substring string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error containing '%s', got nil", substring)
	}
	if !strings.Contains(err.Error(), substring) {
		t.Fatalf("expected error to contain '%s', got: %s", substring, err.Error())
	}
}

// AssertEqual is a generic equality assertion helper
func AssertEqual[T comparable](t *testing.T, expected, actual T) {
	t.Helper()
	if expected != actual {
		t.Fatalf("expected %v, got %v", expected, actual)
	}
}

// AssertNotEqual is a generic inequality assertion helper
func AssertNotEqual[T comparable](t *testing.T, notExpected, actual T) {
	t.Helper()
	if notExpected == actual {
		t.Fatalf("expected value to not equal %v, but it did", notExpected)
	}
}

// TableTest represents a table-driven test case
type TableTest[T any] struct {
	Name     string
	Input    T
	Expected any
	Error    string
	Setup    func() // Optional setup function
	Cleanup  func() // Optional cleanup function
}

// RunTableTests runs table-driven tests with the provided test function
func RunTableTests[T any](t *testing.T, tests []TableTest[T], testFunc func(t *testing.T, input T) (any, error)) {
	t.Helper()

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			if tt.Setup != nil {
				tt.Setup()
			}
			if tt.Cleanup != nil {
				defer tt.Cleanup()
			}

			result, err := testFunc(t, tt.Input)

			if tt.Error != "" {
				AssertErrorContains(t, err, tt.Error)
			} else {
				AssertNoError(t, err)
				if tt.Expected != nil {
					AssertEqual(t, tt.Expected, result)
				}
			}
		})
	}
}

// Contains checks if a string contains a substring (helper for integration tests)
func Contains(s, substr string) bool {
	return strings.Contains(s, substr)
}

// AssertContains checks that a string contains a specific substring
func AssertContains(t *testing.T, str, substring string) {
	t.Helper()
	if !strings.Contains(str, substring) {
		t.Fatalf("expected string to contain '%s', got: %s", substring, str)
	}
}

// Timeout creates a timeout channel for testing slow operations
func Timeout(t *testing.T, duration string) <-chan time.Time {
	t.Helper()
	d, err := time.ParseDuration(duration)
	if err != nil {
		t.Fatalf("invalid duration '%s': %v", duration, err)
	}
	return time.After(d)
}
