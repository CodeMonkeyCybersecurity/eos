package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	hecatemon "github.com/CodeMonkeyCybersecurity/eos/pkg/hecate/monitoring"
	"github.com/stretchr/testify/require"
)

type mockTokenValidator struct {
	validateFn func(token string) (*TokenValidationResult, error)
}

func (m *mockTokenValidator) ValidateToken(_ context.Context, token string) (*TokenValidationResult, error) {
	return m.validateFn(token)
}

type mockMetricsCollector struct {
	snapshot *hecatemon.MetricsSnapshot
	err      error
}

func (m *mockMetricsCollector) CollectMetrics() (*hecatemon.MetricsSnapshot, error) {
	return m.snapshot, m.err
}

func testHandler(t *testing.T) *Handler {
	t.Helper()

	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	h := NewHandler(rc)
	h.metricsCollector = &mockMetricsCollector{
		snapshot: &hecatemon.MetricsSnapshot{
			Timestamp: time.Now(),
			Routes: map[string]hecatemon.RouteMetrics{
				"app.example.com": {
					Domain:         "app.example.com",
					RequestCount:   10,
					ResponseTime:   20 * time.Millisecond,
					ErrorRate:      0.1,
					BytesIn:        1234,
					BytesOut:       5678,
					ActiveRequests: 1,
				},
			},
			System: hecatemon.SystemMetrics{
				TotalRoutes:         1,
				HealthyRoutes:       1,
				UnhealthyRoutes:     0,
				TotalRequests:       10,
				AverageResponseTime: 20 * time.Millisecond,
				SystemLoad:          0.5,
				MemoryUsage:         0.3,
			},
		},
	}
	h.tokenValidator = &mockTokenValidator{
		validateFn: func(token string) (*TokenValidationResult, error) {
			if token == "good-token" {
				return &TokenValidationResult{Valid: true, Subject: "unit-test"}, nil
			}
			return &TokenValidationResult{Valid: false}, nil
		},
	}
	h.prometheusCollector = func(_ *eos_io.RuntimeContext) (string, error) {
		return "# HELP test Test metric\n# TYPE test counter\ntest 1\n", nil
	}

	return h
}

func TestMetricsEndpointIncludesAPIMetrics(t *testing.T) {
	h := testHandler(t)
	router := h.SetupRoutes()

	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
		resp := httptest.NewRecorder()
		router.ServeHTTP(resp, req)
		require.Equal(t, http.StatusOK, resp.Code)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics", nil)
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	require.Equal(t, http.StatusOK, resp.Code)

	var body MetricsResponse
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &body))
	require.GreaterOrEqual(t, body.API.TotalRequests, int64(1))
	require.NotZero(t, body.API.StatusCodeCount[http.StatusOK])
	require.NotZero(t, body.System.TotalRequests)
}

func TestAuthMiddlewareRejectsAndAcceptsToken(t *testing.T) {
	h := testHandler(t)
	router := h.SetupRoutes()

	unauthorizedReq := httptest.NewRequest(http.MethodGet, "/api/v1/routes", nil)
	unauthorizedReq.Header.Set("Authorization", "Bearer bad-token")
	unauthorizedResp := httptest.NewRecorder()
	router.ServeHTTP(unauthorizedResp, unauthorizedReq)
	require.Equal(t, http.StatusUnauthorized, unauthorizedResp.Code)

	authorizedReq := httptest.NewRequest(http.MethodGet, "/api/v1/routes", nil)
	authorizedReq.Header.Set("Authorization", "Bearer good-token")
	authorizedResp := httptest.NewRecorder()
	router.ServeHTTP(authorizedResp, authorizedReq)
	require.Equal(t, http.StatusOK, authorizedResp.Code)
}
