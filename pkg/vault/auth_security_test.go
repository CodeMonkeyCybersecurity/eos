package vault

import (
	"strings"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/testutil"
)

func TestAuthenticationErrorCategorization(t *testing.T) {
	tests := []struct {
		name            string
		error           string
		expectedCategory string
	}{
		{
			name:            "permission_denied",
			error:           "Permission denied accessing vault",
			expectedCategory: "permission_denied",
		},
		{
			name:            "file_not_found",
			error:           "no such file or directory: /etc/vault-token",
			expectedCategory: "resource_not_found",
		},
		{
			name:            "network_timeout", 
			error:           "network timeout connecting to vault",
			expectedCategory: "timeout",
		},
		{
			name:            "connection_refused",
			error:           "connection refused",
			expectedCategory: "network_error",
		},
		{
			name:            "invalid_token_format",
			error:           "invalid token format provided",
			expectedCategory: "invalid_format",
		},
		{
			name:            "generic_error",
			error:           "something went wrong with the system",
			expectedCategory: "general_error",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := &testError{message: tt.error}
			category := categorizeAuthError(err)
			testutil.AssertEqual(t, tt.expectedCategory, category)
		})
	}
}

// testError implements error interface for testing
type testError struct {
	message string
}

func (e *testError) Error() string {
	return e.message
}

func TestAuthenticationSessionLogging(t *testing.T) {
	rc := testutil.TestRuntimeContext(t)
	
	t.Run("successful_authentication_session", func(t *testing.T) {
		session := &AuthenticationSession{
			StartTime: time.Now().Add(-5 * time.Second),
			EndTime:   time.Now(),
			Attempts: []AuthenticationAttempt{
				{
					Method:    "vault-agent-token",
					StartTime: time.Now().Add(-4 * time.Second),
					EndTime:   time.Now().Add(-3 * time.Second),
					Success:   false,
					ErrorType: "resource_not_found",
					Sensitive: true,
				},
				{
					Method:    "approle-auth", 
					StartTime: time.Now().Add(-2 * time.Second),
					EndTime:   time.Now(),
					Success:   true,
					ErrorType: "",
					Sensitive: true,
				},
			},
			SuccessMethod:  "approle-auth",
			TotalDuration: 5 * time.Second,
		}
		
		// This should not panic and should log appropriately
		logAuthenticationSession(rc, session)
		
		// Verify the session data is correctly structured
		testutil.AssertEqual(t, "approle-auth", session.SuccessMethod)
		testutil.AssertEqual(t, 2, len(session.Attempts))
	})
	
	t.Run("multiple_failures_session", func(t *testing.T) {
		session := &AuthenticationSession{
			StartTime: time.Now().Add(-10 * time.Second),
			EndTime:   time.Now(),
			Attempts: []AuthenticationAttempt{
				{Method: "vault-agent-token", Success: false, ErrorType: "resource_not_found"},
				{Method: "approle-auth", Success: false, ErrorType: "permission_denied"},
				{Method: "interactive-userpass", Success: false, ErrorType: "timeout"},
				{Method: "emergency-root-token", Success: false, ErrorType: "resource_not_found"},
			},
			SuccessMethod:  "",
			TotalDuration: 10 * time.Second,
		}
		
		// Should log warnings for multiple failures and long duration
		logAuthenticationSession(rc, session)
		
		testutil.AssertEqual(t, "", session.SuccessMethod)
		testutil.AssertEqual(t, 4, len(session.Attempts))
	})
}

func TestGetAuthenticationStatus(t *testing.T) {
	rc := testutil.TestRuntimeContext(t)
	
	t.Run("no_client", func(t *testing.T) {
		status := GetAuthenticationStatus(rc, nil)
		
		testutil.AssertEqual(t, false, status["authenticated"])
		testutil.AssertEqual(t, false, status["token_present"])
		testutil.AssertEqual(t, false, status["token_valid"])
		
		// Should have timestamp
		_, hasTimestamp := status["timestamp"]
		testutil.AssertEqual(t, true, hasTimestamp)
	})
	
	// Note: Testing with actual Vault client would require more complex mocking
	// For now, we test the basic structure and nil handling
}

func TestSecureAuthenticationOrchestrator(t *testing.T) {
	rc := testutil.TestRuntimeContext(t)
	
	t.Run("all_methods_fail", func(t *testing.T) {
		// Mock HTTP client that returns 401 for all requests
		mockTransport := &testutil.MockHTTPTransport{
			ResponseMap: map[string]testutil.MockResponse{
				"/v1/auth/token/lookup-self": {
					StatusCode: 401,
					Body:       map[string]any{"errors": []string{"permission denied"}},
				},
				"/v1/auth/approle/login": {
					StatusCode: 401,
					Body:       map[string]any{"errors": []string{"invalid credentials"}},
				},
			},
			DefaultResponse: testutil.MockResponse{
				StatusCode: 404,
				Body:       map[string]any{"errors": []string{"not found"}},
			},
		}
		
		cleanup := testutil.WithMockHTTPClient(t, mockTransport)
		defer cleanup()
		
		client, err := NewClient(rc)
		testutil.AssertNoError(t, err)
		
		// Should fail gracefully without exposing sensitive information
		err = SecureAuthenticationOrchestrator(rc, client)
		testutil.AssertError(t, err)
		
		// Error message should be generic
		testutil.AssertErrorContains(t, err, "authentication failed")
		
		// Should not contain sensitive file paths or detailed error info
		errorMsg := err.Error()
		sensitiveTerms := []string{
			"/etc/vault-agent",
			"/var/lib/eos",
			"permission denied",
			"not found",
			"root token",
		}
		
		for _, term := range sensitiveTerms {
			if strings.Contains(errorMsg, term) {
				t.Errorf("Error message contains sensitive information: %s", term)
			}
		}
	})
}

func TestEnhancedTokenVerification(t *testing.T) {
	rc := testutil.TestRuntimeContext(t)
	
	tests := []struct {
		name     string
		token    string
		expected bool
	}{
		{
			name:     "empty_token",
			token:    "",
			expected: false,
		},
		{
			name:     "invalid_format_token",
			token:    "invalid-token-format",
			expected: false,
		},
		{
			name:     "valid_format_hvs_token",
			token:    "hvs.AAAAAQKLwI_VgPyvmn_dV7wR8xOz",
			expected: false, // Will be false because we're not mocking the actual verification
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// For empty/invalid format tokens, should return false immediately
			// For valid format tokens, would call actual VerifyToken which would fail in test
			result := EnhancedTokenVerification(rc, nil, tt.token)
			testutil.AssertEqual(t, tt.expected, result)
		})
	}
}

func TestSecureRootTokenFallback(t *testing.T) {
	rc := testutil.TestRuntimeContext(t)
	
	t.Run("emergency_root_token_logging", func(t *testing.T) {
		// This test mainly verifies that the function handles the emergency case
		// and logs appropriate warnings
		
		// Mock client that will fail root token attempts
		cleanup := testutil.WithMockHTTPClient(t, testutil.VaultMockTransport())
		defer cleanup()
		
		client, err := NewClient(rc)
		testutil.AssertNoError(t, err)
		
		// Should fail because we don't have actual root token files in test environment
		err = SecureRootTokenFallback(rc, client)
		testutil.AssertError(t, err)
		
		// But should handle the failure gracefully with appropriate error categorization
		testutil.AssertErrorContains(t, err, "emergency root token")
	})
}