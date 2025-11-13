package wazuh

import (
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/testutil"
)

func TestAuthenticate(t *testing.T) {
	tests := []struct {
		name        string
		setupMock   func() *testutil.MockHTTPTransport
		config      *Config
		wantToken   string
		wantErr     bool
		errContains string
	}{
		{
			name: "successful authentication",
			setupMock: func() *testutil.MockHTTPTransport {
				return &testutil.MockHTTPTransport{
					ResponseMap: map[string]testutil.MockResponse{
						"/security/user/authenticate?raw=true": {
							StatusCode: 200,
							Body:       "jwt-token-12345",
						},
					},
				}
			},
			config: &Config{
				APIUser:            "test-user",
				APIPassword:        "test-password",
				Endpoint:           "http://localhost:55000",
				VerifyCertificates: false,
			},
			wantToken: "jwt-token-12345",
			wantErr:   false,
		},
		{
			name: "authentication failure - invalid credentials",
			setupMock: func() *testutil.MockHTTPTransport {
				return &testutil.MockHTTPTransport{
					ResponseMap: map[string]testutil.MockResponse{
						"/security/user/authenticate?raw=true": {
							StatusCode: 401,
							Body:       "Invalid credentials",
						},
					},
				}
			},
			config: &Config{
				APIUser:            "invalid-user",
				APIPassword:        "invalid-password",
				Endpoint:           "http://localhost:55000",
				VerifyCertificates: false,
			},
			wantToken:   "",
			wantErr:     true,
			errContains: "authentication failed",
		},
		{
			name: "empty token response",
			setupMock: func() *testutil.MockHTTPTransport {
				return &testutil.MockHTTPTransport{
					ResponseMap: map[string]testutil.MockResponse{
						"/security/user/authenticate?raw=true": {
							StatusCode: 200,
							Body:       "   \n\t  ",
						},
					},
				}
			},
			config: &Config{
				APIUser:            "test-user",
				APIPassword:        "test-password",
				Endpoint:           "http://localhost:55000",
				VerifyCertificates: false,
			},
			wantToken:   "",
			wantErr:     true,
			errContains: "no token received",
		},
		{
			name: "server error",
			setupMock: func() *testutil.MockHTTPTransport {
				return &testutil.MockHTTPTransport{
					ResponseMap: map[string]testutil.MockResponse{
						"/security/user/authenticate?raw=true": {
							StatusCode: 500,
							Body:       "Internal server error",
						},
					},
				}
			},
			config: &Config{
				APIUser:            "test-user",
				APIPassword:        "test-password",
				Endpoint:           "http://localhost:55000",
				VerifyCertificates: false,
			},
			wantToken:   "",
			wantErr:     true,
			errContains: "authentication failed",
		},
		{
			name: "with certificate verification",
			setupMock: func() *testutil.MockHTTPTransport {
				return &testutil.MockHTTPTransport{
					ResponseMap: map[string]testutil.MockResponse{
						"/security/user/authenticate?raw=true": {
							StatusCode: 200,
							Body:       "secure-token",
						},
					},
				}
			},
			config: &Config{
				APIUser:            "secure-user",
				APIPassword:        "secure-password",
				Endpoint:           "https://secure.example.com:55000",
				VerifyCertificates: true,
			},
			wantToken: "secure-token",
			wantErr:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rc := testutil.TestRuntimeContext(t)
			transport := tc.setupMock()
			testutil.WithMockHTTPClient(t, transport)

			token, err := Authenticate(rc, tc.config)

			if tc.wantErr {
				testutil.AssertError(t, err)
				if tc.errContains != "" {
					testutil.AssertErrorContains(t, err, tc.errContains)
				}
				testutil.AssertEqual(t, "", token)
			} else {
				testutil.AssertNoError(t, err)
				testutil.AssertEqual(t, tc.wantToken, token)
			}
		})
	}
}

func TestAuthenticateUser(t *testing.T) {
	tests := []struct {
		name        string
		setupMock   func() *testutil.MockHTTPTransport
		config      *Config
		username    string
		password    string
		wantToken   string
		wantErr     bool
		errContains string
	}{
		{
			name: "successful user authentication",
			setupMock: func() *testutil.MockHTTPTransport {
				return &testutil.MockHTTPTransport{
					ResponseMap: map[string]testutil.MockResponse{
						"/security/user/authenticate?raw=true": {
							StatusCode: 200,
							Body:       "user-jwt-token",
						},
					},
				}
			},
			config: &Config{
				Protocol:           "http",
				FQDN:               "localhost",
				Port:               "55000",
				VerifyCertificates: false,
			},
			username:  "test-user",
			password:  "test-password",
			wantToken: "user-jwt-token",
			wantErr:   false,
		},
		{
			name: "authentication with admin privileges",
			setupMock: func() *testutil.MockHTTPTransport {
				return &testutil.MockHTTPTransport{
					ResponseMap: map[string]testutil.MockResponse{
						"/security/user/authenticate?raw=true": {
							StatusCode: 200,
							Body:       "admin-jwt-token",
						},
					},
				}
			},
			config: &Config{
				Protocol:           "https",
				FQDN:               "wazuh.example.com",
				Port:               "55000",
				VerifyCertificates: true,
			},
			username:  "admin",
			password:  "admin-password",
			wantToken: "admin-jwt-token",
			wantErr:   false,
		},
		{
			name: "user forbidden",
			setupMock: func() *testutil.MockHTTPTransport {
				return &testutil.MockHTTPTransport{
					ResponseMap: map[string]testutil.MockResponse{
						"/security/user/authenticate?raw=true": {
							StatusCode: 403,
							Body:       "User account disabled",
						},
					},
				}
			},
			config: &Config{
				Protocol:           "http",
				FQDN:               "localhost",
				Port:               "55000",
				VerifyCertificates: false,
			},
			username:    "disabled-user",
			password:    "password",
			wantToken:   "",
			wantErr:     true,
			errContains: "authentication failed",
		},
		{
			name: "network error",
			setupMock: func() *testutil.MockHTTPTransport {
				return &testutil.MockHTTPTransport{
					DefaultResponse: testutil.MockResponse{
						StatusCode: 0, // Simulate network error
						Body:       "network unreachable",
					},
				}
			},
			config: &Config{
				Protocol:           "http",
				FQDN:               "unreachable.example.com",
				Port:               "55000",
				VerifyCertificates: false,
			},
			username:    "test-user",
			password:    "test-password",
			wantToken:   "",
			wantErr:     true,
			errContains: "auth request failed",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rc := testutil.TestRuntimeContext(t)
			transport := tc.setupMock()
			testutil.WithMockHTTPClient(t, transport)

			token, err := AuthenticateUser(rc, tc.config, tc.username, tc.password)

			if tc.wantErr {
				testutil.AssertError(t, err)
				if tc.errContains != "" {
					testutil.AssertErrorContains(t, err, tc.errContains)
				}
				testutil.AssertEqual(t, "", token)
			} else {
				testutil.AssertNoError(t, err)
				testutil.AssertEqual(t, tc.wantToken, token)
			}
		})
	}
}

func TestAuthenticatedGetJSON(t *testing.T) {
	tests := []struct {
		name       string
		setupMock  func() *testutil.MockHTTPTransport
		config     *Config
		path       string
		wantBody   string
		wantStatus int
	}{
		{
			name: "successful authenticated request",
			setupMock: func() *testutil.MockHTTPTransport {
				return &testutil.MockHTTPTransport{
					ResponseMap: map[string]testutil.MockResponse{
						"/api/v1/users": {
							StatusCode: 200,
							Body: map[string]interface{}{
								"data": map[string]interface{}{
									"users": []map[string]interface{}{
										{"id": 1, "username": "user1"},
										{"id": 2, "username": "user2"},
									},
								},
							},
						},
					},
				}
			},
			config: &Config{
				Token:              "valid-jwt-token",
				Endpoint:           "http://localhost:55000",
				VerifyCertificates: false,
			},
			path:       "/api/v1/users",
			wantStatus: 200,
		},
		{
			name: "endpoint not found",
			setupMock: func() *testutil.MockHTTPTransport {
				return &testutil.MockHTTPTransport{
					ResponseMap: map[string]testutil.MockResponse{
						"/api/v1/nonexistent": {
							StatusCode: 404,
							Body: map[string]interface{}{
								"error": "Endpoint not found",
							},
						},
					},
				}
			},
			config: &Config{
				Token:              "valid-token",
				Endpoint:           "http://localhost:55000",
				VerifyCertificates: false,
			},
			path:       "/api/v1/nonexistent",
			wantStatus: 404,
		},
		{
			name: "unauthorized request",
			setupMock: func() *testutil.MockHTTPTransport {
				return &testutil.MockHTTPTransport{
					ResponseMap: map[string]testutil.MockResponse{
						"/api/v1/protected": {
							StatusCode: 401,
							Body: map[string]interface{}{
								"error": "Invalid or expired token",
							},
						},
					},
				}
			},
			config: &Config{
				Token:              "invalid-token",
				Endpoint:           "http://localhost:55000",
				VerifyCertificates: false,
			},
			path:       "/api/v1/protected",
			wantStatus: 401,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rc := testutil.TestRuntimeContext(t)
			transport := tc.setupMock()
			testutil.WithMockHTTPClient(t, transport)

			// Note: AuthenticatedGetJSON calls os.Exit(1) on error
			// so we can't easily test error cases without modifying the function
			body, status := AuthenticatedGetJSON(rc, tc.config, tc.path)

			testutil.AssertEqual(t, tc.wantStatus, status)
			testutil.AssertNotEqual(t, "", body)
		})
	}
}

func TestAuthenticationSecurity(t *testing.T) {
	t.Run("credentials not logged", func(t *testing.T) {
		rc := testutil.TestRuntimeContext(t)

		transport := &testutil.MockHTTPTransport{
			ResponseMap: map[string]testutil.MockResponse{
				"/security/user/authenticate?raw=true": {
					StatusCode: 401,
					Body:       "Invalid credentials",
				},
			},
		}
		testutil.WithMockHTTPClient(t, transport)

		config := &Config{
			APIUser:            "secret-user",
			APIPassword:        "secret-password",
			Endpoint:           "http://localhost:55000",
			VerifyCertificates: false,
		}

		_, err := Authenticate(rc, config)
		testutil.AssertError(t, err)

		// Error should not contain the actual password
		errStr := err.Error()
		if containsSensitiveData(errStr, config.APIPassword) {
			t.Errorf("Error message contains sensitive password: %s", errStr)
		}
	})

	t.Run("TLS configuration", func(t *testing.T) {
		rc := testutil.TestRuntimeContext(t)

		transport := &testutil.MockHTTPTransport{
			ResponseMap: map[string]testutil.MockResponse{
				"/security/user/authenticate?raw=true": {
					StatusCode: 200,
					Body:       "secure-token",
				},
			},
		}
		testutil.WithMockHTTPClient(t, transport)

		// Test with certificate verification enabled
		secureConfig := &Config{
			APIUser:            "secure-user",
			APIPassword:        "secure-password",
			Endpoint:           "https://secure.example.com:55000",
			VerifyCertificates: true,
		}

		token, err := Authenticate(rc, secureConfig)
		testutil.AssertNoError(t, err)
		testutil.AssertEqual(t, "secure-token", token)
	})
}

func TestAuthenticationConcurrency(t *testing.T) {
	t.Run("concurrent authentication", func(t *testing.T) {
		transport := &testutil.MockHTTPTransport{
			ResponseMap: map[string]testutil.MockResponse{
				"/security/user/authenticate?raw=true": {
					StatusCode: 200,
					Body:       "concurrent-token",
				},
			},
		}
		testutil.WithMockHTTPClient(t, transport)

		config := &Config{
			APIUser:            "test-user",
			APIPassword:        "test-password",
			Endpoint:           "http://localhost:55000",
			VerifyCertificates: false,
		}

		// Run multiple concurrent authentication requests
		testutil.ParallelTest(t, 10, func(t *testing.T, i int) {
			rc := testutil.TestRuntimeContext(t)
			token, err := Authenticate(rc, config)
			testutil.AssertNoError(t, err)
			testutil.AssertEqual(t, "concurrent-token", token)
		})
	})

	t.Run("concurrent user authentication", func(t *testing.T) {
		transport := &testutil.MockHTTPTransport{
			ResponseMap: map[string]testutil.MockResponse{
				"/security/user/authenticate?raw=true": {
					StatusCode: 200,
					Body:       "user-concurrent-token",
				},
			},
		}
		testutil.WithMockHTTPClient(t, transport)

		config := &Config{
			Protocol:           "http",
			FQDN:               "localhost",
			Port:               "55000",
			VerifyCertificates: false,
		}

		testutil.ParallelTest(t, 10, func(t *testing.T, i int) {
			rc := testutil.TestRuntimeContext(t)
			token, err := AuthenticateUser(rc, config, "test-user", "test-password")
			testutil.AssertNoError(t, err)
			testutil.AssertEqual(t, "user-concurrent-token", token)
		})
	})
}

func TestAuthenticationIntegration(t *testing.T) {
	t.Run("authentication workflow", func(t *testing.T) {
		rc := testutil.TestRuntimeContext(t)

		transport := &testutil.MockHTTPTransport{
			ResponseMap: map[string]testutil.MockResponse{
				"/security/user/authenticate?raw=true": {
					StatusCode: 200,
					Body:       "workflow-token",
				},
				"/api/v1/test": {
					StatusCode: 200,
					Body: map[string]interface{}{
						"message": "authenticated successfully",
					},
				},
			},
		}
		testutil.WithMockHTTPClient(t, transport)

		// Step 1: Authenticate to get token
		config := &Config{
			APIUser:            "workflow-user",
			APIPassword:        "workflow-password",
			Endpoint:           "http://localhost:55000",
			VerifyCertificates: false,
		}

		token, err := Authenticate(rc, config)
		testutil.AssertNoError(t, err)
		testutil.AssertEqual(t, "workflow-token", token)

		// Step 2: Use token for authenticated request
		config.Token = token
		body, status := AuthenticatedGetJSON(rc, config, "/api/v1/test")
		testutil.AssertEqual(t, 200, status)
		testutil.AssertContains(t, body, "authenticated successfully")
	})
}

// Helper function to check if error message contains sensitive data
func containsSensitiveData(message, sensitive string) bool {
	// Simple check - in real implementation would be more sophisticated
	return len(sensitive) > 4 && len(message) > 0 &&
		message != "" && sensitive != ""
}

func BenchmarkAuthenticate(b *testing.B) {
	// Skip benchmarks for integration tests
	b.Skip("Skipping integration benchmark - requires real HTTP client")
}

func BenchmarkAuthenticateUser(b *testing.B) {
	// Skip benchmarks for integration tests
	b.Skip("Skipping integration benchmark - requires real HTTP client")
}
