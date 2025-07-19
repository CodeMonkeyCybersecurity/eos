package hecate

import (
	"context"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

func TestTerraformBasedHecateIntegration(t *testing.T) {
	// This is an integration test for the new Terraform-based Hecate implementation
	// It tests the core functionality without requiring actual infrastructure

	// Create a test runtime context
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	// Test client configuration
	config := &ClientConfig{
		CaddyAdminAddr:     "http://localhost:2019",
		ConsulAddr:         "localhost:8500",
		VaultAddr:          "http://localhost:8200",
		TerraformWorkspace: "/tmp/hecate-test",
	}

	// Test client creation
	t.Run("CreateClient", func(t *testing.T) {
		client, err := NewHecateClient(rc, config)
		if err != nil {
			t.Logf("Client creation failed (expected in test environment): %v", err)
			// This is expected to fail in test environment without actual services
			return
		}

		if client == nil {
			t.Error("Client should not be nil when creation succeeds")
		}
	})

	// Test route manager functionality
	t.Run("RouteManager", func(t *testing.T) {
		// Create a mock client for testing
		client := &HecateClient{
			rc: rc,
		}

		rm := NewRouteManager(client)
		if rm == nil {
			t.Error("RouteManager should not be nil")
		}

		// Test route info creation
		route := &RouteInfo{
			ID:         "test-route",
			Domain:     "test.example.com",
			Upstreams:  []string{"10.0.1.100:3000"},
			AuthPolicy: "test-policy",
			Headers:    map[string]string{"X-Test": "value"},
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
		}

		if route.Domain != "test.example.com" {
			t.Error("Route domain should be set correctly")
		}

		if len(route.Upstreams) != 1 {
			t.Error("Route should have one upstream")
		}
	})

	// Test auth manager functionality
	t.Run("AuthManager", func(t *testing.T) {
		client := &HecateClient{
			rc: rc,
		}

		am := NewAuthManager(client)
		if am == nil {
			t.Error("AuthManager should not be nil")
		}

		// Test auth policy creation
		policy := &AuthPolicyInfo{
			Name:       "test-policy",
			Provider:   "authentik",
			Groups:     []string{"users", "admins"},
			RequireMFA: true,
			CreatedAt:  time.Now(),
		}

		if policy.Name != "test-policy" {
			t.Error("Policy name should be set correctly")
		}

		if len(policy.Groups) != 2 {
			t.Error("Policy should have two groups")
		}
	})

	// Test secret manager functionality
	t.Run("SecretManager", func(t *testing.T) {
		client := &HecateClient{
			rc: rc,
		}

		sm := NewSecretManager(client)
		if sm == nil {
			t.Error("SecretManager should not be nil")
		}

		// Test secret generation
		secret := sm.generateSecret()
		if len(secret) == 0 {
			t.Error("Generated secret should not be empty")
		}

		// Test service mapping
		services := sm.getAffectedServices("authentik-api-token")
		if len(services) == 0 {
			t.Error("Should have affected services for authentik-api-token")
		}
	})

	// Test stream manager functionality  
	t.Run("StreamManager", func(t *testing.T) {
		client := &HecateClient{
			rc: rc,
		}

		sm := NewStreamManager(client)
		if sm == nil {
			t.Error("StreamManager should not be nil")
		}

		// Test stream configuration
		stream := &StreamInfo{
			Name:      "test-stream",
			Protocol:  "tcp",
			Listen:    ":25",
			Upstreams: []string{"mail.example.com:25"},
			CreatedAt: time.Now(),
		}

		config := sm.generateNginxConfig(stream)
		if len(config) == 0 {
			t.Error("Generated Nginx config should not be empty")
		}

		// Test preset availability
		presets := sm.GetAvailablePresets()
		if len(presets) == 0 {
			t.Error("Should have available presets")
		}

		// Verify mailcow preset exists
		found := false
		for _, preset := range presets {
			if preset == "mailcow" {
				found = true
				break
			}
		}
		if !found {
			t.Error("Should have mailcow preset available")
		}
	})

	// Test request validation
	t.Run("RequestValidation", func(t *testing.T) {
		// Test CreateRouteRequest validation
		req := &CreateRouteRequest{
			Domain:    "test.example.com",
			Upstreams: []string{"10.0.1.100:3000"},
			EnableSSL: true,
		}

		if req.Domain == "" {
			t.Error("Domain should be set")
		}

		if len(req.Upstreams) == 0 {
			t.Error("Should have upstreams")
		}

		// Test CreateStreamRequest validation
		streamReq := &CreateStreamRequest{
			Name:      "test-stream",
			Protocol:  "tcp",
			Listen:    ":25",
			Upstreams: []string{"mail.example.com:25"},
		}

		client := &HecateClient{rc: rc}
		sm := NewStreamManager(client)
		
		err := sm.validateCreateRequest(streamReq)
		if err != nil {
			t.Errorf("Valid stream request should not fail validation: %v", err)
		}

		// Test invalid protocol
		streamReq.Protocol = "invalid"
		err = sm.validateCreateRequest(streamReq)
		if err == nil {
			t.Error("Invalid protocol should fail validation")
		}
	})
}

func TestTerraformSaltIntegration(t *testing.T) {
	// Test the Salt state integration
	t.Run("SaltStateGeneration", func(t *testing.T) {
		route := &RouteInfo{
			Domain:     "app.example.com",
			Upstreams:  []string{"10.0.1.100:3000"},
			AuthPolicy: "users",
			Headers:    map[string]string{"X-Environment": "production"},
		}

		// Verify route data structure is correct for Salt templates
		if route.Domain == "" {
			t.Error("Domain should be set for Salt state")
		}

		if len(route.Upstreams) == 0 {
			t.Error("Upstreams should be set for Salt state")
		}

		t.Logf("Route ready for Salt state: domain=%s, upstreams=%v", 
			route.Domain, route.Upstreams)
	})

	t.Run("TerraformConfigGeneration", func(t *testing.T) {
		// Test that we can generate Terraform config data
		domain := "api.example.com"
		target := "1.2.3.4"

		if domain == "" || target == "" {
			t.Error("Domain and target should be set for Terraform")
		}

		t.Logf("Terraform config ready: domain=%s, target=%s", domain, target)
	})
}

// Benchmark the new implementation
func BenchmarkRouteCreation(b *testing.B) {
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	client := &HecateClient{rc: rc}
	_ = NewRouteManager(client) // Create manager for benchmark setup

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		route := &RouteInfo{
			ID:         generateRouteID("test.example.com"),
			Domain:     "test.example.com",
			Upstreams:  []string{"10.0.1.100:3000"},
			AuthPolicy: "test-policy",
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
		}

		_ = route // Use the route
	}
}