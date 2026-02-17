// Integration scenario tests using predefined scenarios
package test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate/api"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/testutil"
)

// TestIntegrationScenarios_HTTPClient tests HTTP client scenario
func TestIntegrationScenarios_HTTPClient(t *testing.T) {
	suite := testutil.NewIntegrationTestSuite(t, "http-client-scenarios")

	scenario := testutil.HTTPClientScenario()
	suite.RunScenario(scenario)
}

// TestIntegrationScenarios_FileSecurityOperations tests file security scenario
func TestIntegrationScenarios_FileSecurityOperations(t *testing.T) {
	suite := testutil.NewIntegrationTestSuite(t, "file-security-scenarios")

	scenario := testutil.FileSecurityScenario()
	suite.RunScenario(scenario)
}

// TestIntegrationScenarios_RuntimeContextLifecycle tests runtime context lifecycle
func TestIntegrationScenarios_RuntimeContextLifecycle(t *testing.T) {
	suite := testutil.NewIntegrationTestSuite(t, "runtime-context-scenarios")

	scenario := testutil.RuntimeContextLifecycleScenario()
	suite.RunScenario(scenario)
}

// TestIntegrationScenarios_ErrorHandling tests comprehensive error handling
func TestIntegrationScenarios_ErrorHandling(t *testing.T) {
	suite := testutil.NewIntegrationTestSuite(t, "error-handling-scenarios")

	scenario := testutil.ErrorHandlingScenario()
	suite.RunScenario(scenario)
}

// TestIntegrationScenarios_CombinedWorkflow tests multiple scenarios together
func TestIntegrationScenarios_CombinedWorkflow(t *testing.T) {
	suite := testutil.NewIntegrationTestSuite(t, "combined-scenarios")
	suite.WithVaultMock()
	suite.WithDockerMock()

	// Run multiple scenarios in sequence
	scenarios := []testutil.TestScenario{
		testutil.HTTPClientScenario(),
		testutil.RuntimeContextLifecycleScenario(),
		testutil.ErrorHandlingScenario(),
	}

	for _, scenario := range scenarios {
		suite.RunScenario(scenario)
	}
}

// TestIntegrationPatterns_MockServices tests mock service patterns
func TestIntegrationPatterns_MockServices(t *testing.T) {
	suite := testutil.NewIntegrationTestSuite(t, "mock-service-patterns")

	// Test Vault mock pattern
	vaultPattern := testutil.MockServicePattern("vault", testutil.VaultMockTransport())

	scenario := testutil.TestScenario{
		Name:        "vault_mock_pattern_test",
		Description: "Test vault mock service pattern",
		Setup: func(s *testutil.IntegrationTestSuite) {
			if err := vaultPattern.Setup(s); err != nil {
				panic(fmt.Sprintf("Failed to setup vault pattern: %v", err))
			}
		},
		Steps: []testutil.TestStep{
			{
				Name:        "execute_vault_pattern",
				Description: "Execute vault mock pattern",
				Action: func(s *testutil.IntegrationTestSuite) error {
					return vaultPattern.Execute(s)
				},
			},
			{
				Name:        "validate_vault_pattern",
				Description: "Validate vault mock pattern results",
				Action: func(s *testutil.IntegrationTestSuite) error {
					return vaultPattern.Validate(s)
				},
			},
		},
	}

	suite.RunScenario(scenario)
}

// TestIntegrationPatterns_FileSystem tests file system patterns
func TestIntegrationPatterns_FileSystem(t *testing.T) {
	suite := testutil.NewIntegrationTestSuite(t, "filesystem-patterns")

	fsPattern := testutil.FileSystemPattern("test/data")

	scenario := testutil.TestScenario{
		Name:        "filesystem_pattern_test",
		Description: "Test file system operation patterns",
		Setup: func(s *testutil.IntegrationTestSuite) {
			if err := fsPattern.Setup(s); err != nil {
				panic(fmt.Sprintf("Failed to setup filesystem pattern: %v", err))
			}
		},
		Steps: []testutil.TestStep{
			{
				Name:        "execute_filesystem_operations",
				Description: "Execute file system operations",
				Action: func(s *testutil.IntegrationTestSuite) error {
					return fsPattern.Execute(s)
				},
			},
			{
				Name:        "validate_filesystem_results",
				Description: "Validate file system operation results",
				Action: func(s *testutil.IntegrationTestSuite) error {
					return fsPattern.Validate(s)
				},
			},
		},
	}

	suite.RunScenario(scenario)
}

// TestIntegrationPatterns_Concurrency tests concurrency patterns
func TestIntegrationPatterns_Concurrency(t *testing.T) {
	suite := testutil.NewIntegrationTestSuite(t, "concurrency-patterns")
	suite.WithVaultMock()

	// Define concurrent operation
	concurrentOperation := func(workerID int, s *testutil.IntegrationTestSuite) error {
		rc := s.CreateTestContext("concurrent-worker")
		rc.Attributes["worker_id"] = string(rune(workerID + '0'))

		// Simulate some work
		return nil
	}

	concurrencyPattern := testutil.ConcurrencyPattern(5, concurrentOperation)

	scenario := testutil.TestScenario{
		Name:        "concurrency_pattern_test",
		Description: "Test concurrent operations pattern",
		Steps: []testutil.TestStep{
			{
				Name:        "execute_concurrent_operations",
				Description: "Execute concurrent operations with 5 workers",
				Action: func(s *testutil.IntegrationTestSuite) error {
					return concurrencyPattern.Execute(s)
				},
			},
		},
	}

	suite.RunScenario(scenario)
}

// TestIntegrationScenarios_HecateAPIMetricsAndAuth verifies API metrics mutate under load
// and auth middleware enforces token validation behavior.
func TestIntegrationScenarios_HecateAPIMetricsAndAuth(t *testing.T) {
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	handler := api.NewHandler(rc)
	router := handler.SetupRoutes()

	// Generate request load for metrics accounting.
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
		resp := httptest.NewRecorder()
		router.ServeHTTP(resp, req)
		if resp.Code != http.StatusOK {
			t.Fatalf("expected health status 200, got %d", resp.Code)
		}
	}

	metricsReq := httptest.NewRequest(http.MethodGet, "/api/v1/metrics", nil)
	metricsResp := httptest.NewRecorder()
	router.ServeHTTP(metricsResp, metricsReq)
	if metricsResp.Code != http.StatusOK {
		t.Fatalf("expected metrics status 200, got %d", metricsResp.Code)
	}

	var metrics api.MetricsResponse
	if err := json.Unmarshal(metricsResp.Body.Bytes(), &metrics); err != nil {
		t.Fatalf("failed to decode metrics response: %v", err)
	}
	if metrics.API.TotalRequests == 0 {
		t.Fatalf("expected API total_requests to increase after synthetic load")
	}

	// Invalid short token should be rejected.
	badReq := httptest.NewRequest(http.MethodGet, "/api/v1/routes", nil)
	badReq.Header.Set("Authorization", "Bearer short-token")
	badResp := httptest.NewRecorder()
	router.ServeHTTP(badResp, badReq)
	if badResp.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized for bad token, got %d", badResp.Code)
	}

	// Long token should pass baseline validator and reach route handler.
	goodReq := httptest.NewRequest(http.MethodGet, "/api/v1/routes", nil)
	goodReq.Header.Set("Authorization", "Bearer 12345678901234567890123456789012")
	goodResp := httptest.NewRecorder()
	router.ServeHTTP(goodResp, goodReq)
	if goodResp.Code != http.StatusOK {
		t.Fatalf("expected success for valid token, got %d", goodResp.Code)
	}
}
