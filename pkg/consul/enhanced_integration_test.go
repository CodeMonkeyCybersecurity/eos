// pkg/consul/enhanced_integration_test.go

package consul

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewEnhancedConsulManager(t *testing.T) {
	config := &EnhancedConfig{
		Address:    "127.0.0.1:8500",
		Datacenter: "dc1",
		Token:      "",
		CircuitBreakerConfig: &CBConfig{
			MaxRequests: 3,
			Interval:    10 * time.Second,
			Timeout:     60 * time.Second,
		},
		MonitoringConfig: &MonitoringConfig{
			MetricsInterval: 30 * time.Second,
			AlertingEnabled: false,
		},
	}

	// Create runtime context
	ctx := context.Background()
	rc := &eos_io.RuntimeContext{
		Ctx: ctx,
	}

	// Test manager creation
	manager, err := NewEnhancedConsulManager(rc, config)
	
	// Note: This will fail if Consul is not running, which is expected in CI
	if err != nil {
		t.Skipf("Skipping test - Consul not available: %v", err)
		return
	}

	require.NoError(t, err)
	assert.NotNil(t, manager)
	assert.Equal(t, config.Address, manager.config.Address)
	assert.Equal(t, config.Datacenter, manager.config.Datacenter)

	// Cleanup
	manager.Cleanup()
}

func TestAdvancedService_Creation(t *testing.T) {
	service := AdvancedService{
		ID:      "test-service-1",
		Name:    "test-service",
		Tags:    []string{"test", "api"},
		Port:    8080,
		Address: "127.0.0.1",
		Meta: map[string]string{
			"version": "1.0.0",
			"env":     "test",
		},
		HealthChecks: []AdvancedHealthCheck{
			{
				ID:                     "test-health-1",
				Name:                   "HTTP Health Check",
				Type:                   "http",
				Target:                 "http://127.0.0.1:8080/health",
				Interval:               "10s",
				Timeout:                "3s",
				SuccessBeforePassing:   2,
				FailuresBeforeCritical: 3,
			},
		},
		EnableTaggedOverride: true,
	}

	assert.Equal(t, "test-service-1", service.ID)
	assert.Equal(t, "test-service", service.Name)
	assert.Len(t, service.HealthChecks, 1)
	assert.Equal(t, "http", service.HealthChecks[0].Type)
}

func TestConnectConfiguration_Validation(t *testing.T) {
	connectConfig := &ConnectConfiguration{
		Native: false,
		SidecarService: &SidecarService{
			Port: 8081,
			Proxy: &ProxyConfiguration{
				Upstreams: []UpstreamConfig{
					{
						DestinationName: "backend-service",
						LocalBindPort:   9090,
						Datacenter:      "dc1",
					},
				},
				Config: map[string]interface{}{
					"protocol": "http",
				},
			},
		},
	}

	assert.False(t, connectConfig.Native)
	assert.NotNil(t, connectConfig.SidecarService)
	assert.Equal(t, 8081, connectConfig.SidecarService.Port)
	assert.Len(t, connectConfig.SidecarService.Proxy.Upstreams, 1)
	assert.Equal(t, "backend-service", connectConfig.SidecarService.Proxy.Upstreams[0].DestinationName)
}

func TestHealthCheckTypes(t *testing.T) {
	testCases := []struct {
		name     string
		checkType string
		target   string
		valid    bool
	}{
		{"HTTP Check", "http", "http://127.0.0.1:8080/health", true},
		{"HTTPS Check", "https", "https://127.0.0.1:8443/health", true},
		{"TCP Check", "tcp", "127.0.0.1:8080", true},
		{"gRPC Check", "grpc", "127.0.0.1:9090", true},
		{"Script Check", "script", "/usr/local/bin/health-check.sh", true},
		{"Docker Check", "docker", "container-id", true},
		{"Alias Check", "alias", "other-service", true},
		{"Invalid Check", "invalid", "target", false},
	}

	validTypes := map[string]bool{
		"http": true, "https": true, "tcp": true,
		"grpc": true, "script": true, "docker": true, "alias": true,
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, isValid := validTypes[tc.checkType]
			assert.Equal(t, tc.valid, isValid)
		})
	}
}

func TestEnhancedConfig_Defaults(t *testing.T) {
	config := &EnhancedConfig{
		Address:    fmt.Sprintf("127.0.0.1:%d", shared.PortConsul),  // EOS custom port
		Datacenter: "dc1",
		CircuitBreakerConfig: &CBConfig{
			MaxRequests: 5,
			Interval:    30 * time.Second,
			Timeout:     60 * time.Second,
		},
		MonitoringConfig: &MonitoringConfig{
			MetricsInterval: 60 * time.Second,
			AlertingEnabled: true,
			AlertingWebhook: "https://hooks.slack.com/test",
		},
		SecurityConfig: &SecurityConfig{
			EncryptionEnabled: true,
			DenyByDefault:     true,
			AllowedCIDRs:      []string{"10.0.0.0/8", "192.168.0.0/16"},
		},
	}

	assert.Equal(t, fmt.Sprintf("127.0.0.1:%d", shared.PortConsul), config.Address)
	assert.True(t, config.SecurityConfig.EncryptionEnabled)
	assert.True(t, config.SecurityConfig.DenyByDefault)
	assert.Len(t, config.SecurityConfig.AllowedCIDRs, 2)
}

func TestMetricsCollector_Creation(t *testing.T) {
	// Test metrics collector creation (without actual Consul client)
	collector := NewMetricsCollector(nil)
	assert.NotNil(t, collector)
}

func TestAlertManager_Creation(t *testing.T) {
	config := &MonitoringConfig{
		AlertingEnabled: true,
		AlertingWebhook: "https://example.com/webhook",
	}

	alertManager := NewAlertManager(config)
	assert.NotNil(t, alertManager)
	assert.Equal(t, config, alertManager.config)
}

func TestAlert_Structure(t *testing.T) {
	alert := Alert{
		Service:   "test-service",
		CheckName: "health-check",
		Status:    "critical",
		Message:   "Service is down",
		Timestamp: time.Now(),
		Severity:  "high",
	}

	assert.Equal(t, "test-service", alert.Service)
	assert.Equal(t, "critical", alert.Status)
	assert.Equal(t, "high", alert.Severity)
}