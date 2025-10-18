package wazuh

import (
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/testutil"
)

// Example of how to use the new testing framework
func TestResolveWazuhUserID_WithFramework(t *testing.T) {
	// Create test context using the framework
	rc := testutil.TestRuntimeContext(t)

	// Setup mock HTTP client that restores automatically
	cleanup := testutil.WithMockHTTPClient(t, testutil.WazuhMockTransport())
	defer cleanup()

	// Test existing user
	id, err := ResolveWazuhUserID(rc, "alice")
	testutil.AssertNoError(t, err)
	testutil.AssertEqual(t, "user-123", id)

	// Test non-existing user
	_, err = ResolveWazuhUserID(rc, "nonexistent")
	testutil.AssertErrorContains(t, err, "user not found")
}

// Example of table-driven testing with the framework
func TestResolveWazuhUserID_TableDriven_WithFramework(t *testing.T) {
	rc := testutil.TestRuntimeContext(t)
	cleanup := testutil.WithMockHTTPClient(t, testutil.WazuhMockTransport())
	defer cleanup()

	tests := []testutil.TableTest[string]{
		{
			Name:     "existing user alice",
			Input:    "alice",
			Expected: "user-123",
		},
		{
			Name:     "existing user bob",
			Input:    "bob",
			Expected: "user-456",
		},
		{
			Name:     "existing user charlie",
			Input:    "charlie",
			Expected: "user-789",
		},
		{
			Name:  "non-existent user",
			Input: "nonexistent",
			Error: "user not found",
		},
	}

	testutil.RunTableTests(t, tests, func(t *testing.T, username string) (any, error) {
		return ResolveWazuhUserID(rc, username)
	})
}

// Example test for a function that creates resources
func TestEnsureWazuhGroup_WithFramework(t *testing.T) {
	rc := testutil.TestRuntimeContext(t)
	cleanup := testutil.WithMockHTTPClient(t, testutil.WazuhMockTransport())
	defer cleanup()

	spec := TenantSpec{
		Name:    "test-tenant",
		User:    "alice",
		GroupID: "group_test",
	}

	err := EnsureWazuhGroup(rc, spec)
	testutil.AssertNoError(t, err)
}

// Example test with custom mock responses
func TestResolveWazuhUserID_CustomMockResponse(t *testing.T) {
	rc := testutil.TestRuntimeContext(t)

	// Create custom mock transport for this specific test
	mockTransport := &testutil.MockHTTPTransport{
		ResponseMap: map[string]testutil.MockResponse{
			"/security/users": {
				StatusCode: 200,
				Body: map[string]any{
					"data": []map[string]any{
						{"id": "custom-user-123", "username": "test-user"},
					},
				},
			},
		},
		DefaultResponse: testutil.MockResponse{
			StatusCode: 404,
			Body:       map[string]any{"error": "not found"},
		},
	}

	cleanup := testutil.WithMockHTTPClient(t, mockTransport)
	defer cleanup()

	// Test with custom response
	id, err := ResolveWazuhUserID(rc, "test-user")
	testutil.AssertNoError(t, err)
	testutil.AssertEqual(t, "custom-user-123", id)
}

// Example test demonstrating error scenarios
func TestResolveWazuhUserID_ErrorScenarios(t *testing.T) {
	tests := []struct {
		name         string
		mockResponse testutil.MockResponse
		username     string
		expectedErr  string
	}{
		{
			name: "server error with valid JSON but no data field",
			mockResponse: testutil.MockResponse{
				StatusCode: 500,
				Body:       map[string]any{"error": "internal server error"},
			},
			username:    "alice",
			expectedErr: "user not found", // Function still looks for user even on 500
		},
		{
			name: "invalid json response",
			mockResponse: testutil.MockResponse{
				StatusCode: 200,
				Body:       "invalid json",
			},
			username:    "alice",
			expectedErr: "failed to decode users",
		},
		{
			name: "empty user list",
			mockResponse: testutil.MockResponse{
				StatusCode: 200,
				Body: map[string]any{
					"data": []map[string]any{},
				},
			},
			username:    "alice",
			expectedErr: "user not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rc := testutil.TestRuntimeContext(t)

			mockTransport := &testutil.MockHTTPTransport{
				ResponseMap: map[string]testutil.MockResponse{
					"/security/users": tt.mockResponse,
				},
			}

			cleanup := testutil.WithMockHTTPClient(t, mockTransport)
			defer cleanup()

			_, err := ResolveWazuhUserID(rc, tt.username)
			testutil.AssertErrorContains(t, err, tt.expectedErr)
		})
	}
}
