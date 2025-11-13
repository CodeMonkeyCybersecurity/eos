package wazuh

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/httpclient"
)

// MockHTTPClient implements http.Client interface for testing
type MockHTTPClient struct {
	DoFunc func(req *http.Request) (*http.Response, error)
}

func (m *MockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	return m.DoFunc(req)
}

// newTestRuntimeContext creates a properly initialized RuntimeContext for testing
func newTestRuntimeContext() *eos_io.RuntimeContext {
	ctx := context.Background()
	return eos_io.NewContext(ctx, "test")
}

// createMockHTTPClient creates an HTTP client that mocks Wazuh API responses
func createMockHTTPClient() *http.Client {
	return &http.Client{
		Transport: &mockRoundTripper{},
	}
}

// mockRoundTripper implements http.RoundTripper for mocking HTTP requests
type mockRoundTripper struct{}

func (m *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	response := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Body:       nil,
	}
	response.Header.Set("Content-Type", "application/json")

	var responseData map[string]any

	switch req.URL.Path {
	case "/security/users":
		responseData = map[string]any{
			"data": []map[string]any{
				{"id": "user-123", "username": "alice"},
				{"id": "user-456", "username": "bob"},
			},
		}
	case "/security/roles":
		responseData = map[string]any{
			"data": []map[string]any{
				{"id": "role-123", "name": "role_alice"},
				{"id": "role-456", "name": "role_bob"},
			},
		}
	case "/security/policies":
		responseData = map[string]any{
			"data": []map[string]any{
				{"id": "policy-123", "name": "policy_alice"},
				{"id": "policy-456", "name": "policy_bob"},
			},
		}
	default:
		response.StatusCode = 404
		return response, nil
	}

	// Convert response data to JSON
	jsonData, err := json.Marshal(responseData)
	if err != nil {
		response.StatusCode = 500
		return response, nil
	}

	response.Body = http.NoBody
	response.ContentLength = int64(len(jsonData))
	response.Body = &mockResponseBody{data: jsonData}

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

func TestResolveWazuhUserID(t *testing.T) {
	// Store original client and restore after test
	originalClient := httpclient.DefaultClient()
	err := httpclient.SetDefaultHTTPClient(createMockHTTPClient())
	if err != nil {
		t.Fatalf("failed to set mock client: %v", err)
	}
	defer httpclient.SetDefaultClient(originalClient)

	// Create test context
	rc := newTestRuntimeContext()

	// Test existing user
	id, err := ResolveWazuhUserID(rc, "alice")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if id != "user-123" {
		t.Fatalf("expected 'user-123', got: %s", id)
	}

	// Test non-existing user
	_, err = ResolveWazuhUserID(rc, "nonexistent")
	if err == nil {
		t.Fatal("expected error for non-existent user")
	}
	expectedErr := "user not found: nonexistent"
	if err.Error() != expectedErr {
		t.Fatalf("expected error '%s', got: %s", expectedErr, err.Error())
	}
}

func TestResolveWazuhRoleID(t *testing.T) {
	// Store original client and restore after test
	originalClient := httpclient.DefaultClient()
	err := httpclient.SetDefaultHTTPClient(createMockHTTPClient())
	if err != nil {
		t.Fatalf("failed to set mock client: %v", err)
	}
	defer httpclient.SetDefaultClient(originalClient)

	// Create test context
	rc := newTestRuntimeContext()

	// Test existing role
	id, err := ResolveWazuhRoleID(rc, "role_alice")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if id != "role-123" {
		t.Fatalf("expected 'role-123', got: %s", id)
	}

	// Test non-existing role
	_, err = ResolveWazuhRoleID(rc, "nonexistent")
	if err == nil {
		t.Fatal("expected error for non-existent role")
	}
	expectedErr := "role not found: nonexistent"
	if err.Error() != expectedErr {
		t.Fatalf("expected error '%s', got: %s", expectedErr, err.Error())
	}
}

func TestResolveWazuhPolicyID(t *testing.T) {
	// Store original client and restore after test
	originalClient := httpclient.DefaultClient()
	err := httpclient.SetDefaultHTTPClient(createMockHTTPClient())
	if err != nil {
		t.Fatalf("failed to set mock client: %v", err)
	}
	defer httpclient.SetDefaultClient(originalClient)

	// Create test context
	rc := newTestRuntimeContext()

	// Test existing policy
	id, err := ResolveWazuhPolicyID(rc, "policy_alice")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if id != "policy-123" {
		t.Fatalf("expected 'policy-123', got: %s", id)
	}

	// Test non-existing policy
	_, err = ResolveWazuhPolicyID(rc, "nonexistent")
	if err == nil {
		t.Fatal("expected error for non-existent policy")
	}
	expectedErr := "policy not found: nonexistent"
	if err.Error() != expectedErr {
		t.Fatalf("expected error '%s', got: %s", expectedErr, err.Error())
	}
}

// Test table-driven approach for multiple scenarios
func TestResolveWazuhUserID_TableDriven(t *testing.T) {
	tests := []struct {
		name          string
		username      string
		expectedID    string
		expectedError string
	}{
		{
			name:       "existing user alice",
			username:   "alice",
			expectedID: "user-123",
		},
		{
			name:       "existing user bob",
			username:   "bob",
			expectedID: "user-456",
		},
		{
			name:          "non-existent user",
			username:      "charlie",
			expectedError: "user not found: charlie",
		},
	}

	// Store original client and restore after test
	originalClient := httpclient.DefaultClient()
	err := httpclient.SetDefaultHTTPClient(createMockHTTPClient())
	if err != nil {
		t.Fatalf("failed to set mock client: %v", err)
	}
	defer httpclient.SetDefaultClient(originalClient)

	rc := newTestRuntimeContext()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := ResolveWazuhUserID(rc, tt.username)

			if tt.expectedError != "" {
				if err == nil {
					t.Fatalf("expected error '%s', got nil", tt.expectedError)
				}
				if err.Error() != tt.expectedError {
					t.Fatalf("expected error '%s', got: %s", tt.expectedError, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("expected no error, got: %v", err)
				}
				if id != tt.expectedID {
					t.Fatalf("expected ID '%s', got: %s", tt.expectedID, id)
				}
			}
		})
	}
}
