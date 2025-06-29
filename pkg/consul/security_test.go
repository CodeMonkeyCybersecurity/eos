// pkg/consul/security_test.go

package consul

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/stretchr/testify/assert"
)

func TestSecurityValidator_ValidateConfig(t *testing.T) {
	validator := NewSecurityValidator()
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	t.Run("Secure Configuration", func(t *testing.T) {
		config := &EnhancedConfig{
			Address:    fmt.Sprintf("127.0.0.1:%d", shared.PortConsul),
			Datacenter: "dc1",
			Token:      "550e8400-e29b-41d4-a716-446655440000", // Valid UUID
			TLSConfig: &TLSConfig{
				Enabled:        true,
				CertFile:       "/etc/consul/tls/cert.pem",
				KeyFile:        "/etc/consul/tls/key.pem",
				CAFile:         "/etc/consul/tls/ca.pem",
				VerifyIncoming: true,
				VerifyOutgoing: true,
			},
			ACLConfig: &ACLConfig{
				Enabled:       true,
				DefaultPolicy: "deny",
				TokenPersist:  true,
			},
			SecurityConfig: &SecurityConfig{
				EncryptionEnabled: true,
				DenyByDefault:     true,
				AllowedCIDRs:      []string{"10.0.0.0/8", "192.168.1.0/24"},
			},
		}

		result := validator.ValidateConfig(rc, config)
		assert.True(t, result.Valid)
		assert.Empty(t, result.Errors)
		assert.GreaterOrEqual(t, result.Score, 80) // Should have high security score
	})

	t.Run("Insecure Configuration", func(t *testing.T) {
		config := &EnhancedConfig{
			Address:    "0.0.0.0:8500", // Insecure binding and default port
			Datacenter: "dc1",
			Token:      "password", // Weak token
			TLSConfig: &TLSConfig{
				Enabled: false, // TLS disabled
			},
			ACLConfig: &ACLConfig{
				Enabled:       false, // ACLs disabled
				DefaultPolicy: "allow",
			},
			SecurityConfig: &SecurityConfig{
				EncryptionEnabled: false,                 // Encryption disabled
				AllowedCIDRs:      []string{"0.0.0.0/0"}, // Allow all IPs
			},
		}

		result := validator.ValidateConfig(rc, config)
		assert.False(t, result.Valid)
		assert.NotEmpty(t, result.Errors)
		assert.Less(t, result.Score, 50) // Should have low security score
	})

	t.Run("Missing TLS Configuration", func(t *testing.T) {
		config := &EnhancedConfig{
			Address:    fmt.Sprintf("127.0.0.1:%d", shared.PortConsul),
			Datacenter: "dc1",
			TLSConfig:  nil, // Missing TLS config
		}

		result := validator.ValidateConfig(rc, config)
		assert.False(t, result.Valid)
		assert.Contains(t, result.Errors, "TLS configuration is required for production deployments")
	})
}

func TestSecurityValidator_ValidateService(t *testing.T) {
	validator := NewSecurityValidator()
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	t.Run("Secure Service", func(t *testing.T) {
		service := AdvancedService{
			ID:      "secure-api-1",
			Name:    "secure-api",
			Tags:    []string{"api", "production"},
			Port:    8443,
			Address: "127.0.0.1",
			Meta: map[string]string{
				"version":     "1.0.0",
				"environment": "production",
			},
			HealthChecks: []AdvancedHealthCheck{
				{
					ID:       "https-health",
					Name:     "HTTPS Health Check",
					Type:     "https",
					Target:   "https://127.0.0.1:8443/health",
					Interval: "10s",
					Timeout:  "3s",
				},
			},
			ConnectConfig: &ConnectConfiguration{
				Native: true,
			},
		}

		result := validator.ValidateService(rc, service)
		assert.True(t, result.Valid)
		assert.Empty(t, result.Errors)
	})

	t.Run("Insecure Service", func(t *testing.T) {
		service := AdvancedService{
			ID:   "",             // Empty ID
			Name: "test-service", // Contains 'test'
			Meta: map[string]string{
				"api_password": "secret123", // Sensitive data in metadata
			},
			HealthChecks: []AdvancedHealthCheck{
				{
					Name:          "HTTP Health",
					Type:          "http",
					Target:        "http://127.0.0.1:8080/health", // Insecure HTTP
					TLSSkipVerify: true,                           // Skips TLS verification
				},
				{
					Name:   "Script Check",
					Type:   "script",
					Target: "rm -rf /tmp && sudo systemctl restart", // Dangerous script
				},
			},
		}

		result := validator.ValidateService(rc, service)
		assert.False(t, result.Valid)
		assert.NotEmpty(t, result.Errors)
		// Check that warnings contain the expected message
		found := false
		for _, warning := range result.Warnings {
			if strings.Contains(warning, "Service name contains 'test'") {
				found = true
				break
			}
		}
		assert.True(t, found, "Expected warning about service name containing 'test'")
	})

	t.Run("No Health Checks", func(t *testing.T) {
		service := AdvancedService{
			ID:           "api-1",
			Name:         "api",
			HealthChecks: []AdvancedHealthCheck{}, // No health checks
		}

		result := validator.ValidateService(rc, service)
		assert.True(t, result.Valid) // Still valid but with warnings
		// Check that warnings contain the expected message
		found := false
		for _, warning := range result.Warnings {
			if strings.Contains(warning, "No health checks configured") {
				found = true
				break
			}
		}
		assert.True(t, found, "Expected warning about no health checks")
	})
}

func TestSecurityValidator_ValidateAddress(t *testing.T) {
	validator := NewSecurityValidator()

	testCases := []struct {
		name           string
		address        string
		expectErrors   bool
		expectWarnings bool
		minScore       int
	}{
		{
			name:         "Secure Custom Port",
			address:      fmt.Sprintf("127.0.0.1:%d", shared.PortConsul),
			expectErrors: false,
			minScore:     90,
		},
		{
			name:           "Default Port Warning",
			address:        "127.0.0.1:8500",
			expectErrors:   false,
			expectWarnings: true,
			minScore:       85,
		},
		{
			name:           "Wildcard Binding Warning",
			address:        fmt.Sprintf("0.0.0.0:%d", shared.PortConsul),
			expectErrors:   false,
			expectWarnings: true,
			minScore:       85,
		},
		{
			name:         "Invalid Format",
			address:      "invalid-address",
			expectErrors: true,
			minScore:     80,
		},
		{
			name:         "Empty Address",
			address:      "",
			expectErrors: true,
			minScore:     75,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := &ValidationResult{
				Valid:    true,
				Errors:   []string{},
				Warnings: []string{},
				Score:    100,
			}

			validator.validateAddress(tc.address, result)

			if tc.expectErrors {
				assert.NotEmpty(t, result.Errors, "Expected errors for address: %s", tc.address)
			} else {
				assert.Empty(t, result.Errors, "Unexpected errors for address: %s", tc.address)
			}

			if tc.expectWarnings {
				assert.NotEmpty(t, result.Warnings, "Expected warnings for address: %s", tc.address)
			}

			assert.GreaterOrEqual(t, result.Score, tc.minScore, "Security score too low for address: %s", tc.address)
		})
	}
}

func TestSecurityValidator_ValidateToken(t *testing.T) {
	validator := NewSecurityValidator()

	testCases := []struct {
		name         string
		token        string
		expectErrors bool
		minScore     int
	}{
		{
			name:     "Valid UUID Token",
			token:    "550e8400-e29b-41d4-a716-446655440000",
			minScore: 95,
		},
		{
			name:     "Strong Random Token",
			token:    "abcdef1234567890abcdef1234567890",
			minScore: 90,
		},
		{
			name:         "Weak Token",
			token:        "password",
			expectErrors: true,
			minScore:     60,
		},
		{
			name:         "Short Token",
			token:        "abc123",
			expectErrors: true,
			minScore:     80,
		},
		{
			name:     "Empty Token",
			token:    "",
			minScore: 95, // Empty is okay - might use other auth
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := &ValidationResult{
				Valid:    true,
				Errors:   []string{},
				Warnings: []string{},
				Score:    100,
			}

			validator.validateToken(tc.token, result)

			if tc.expectErrors {
				assert.NotEmpty(t, result.Errors, "Expected errors for token test: %s", tc.name)
			}

			assert.GreaterOrEqual(t, result.Score, tc.minScore, "Security score too low for token test: %s", tc.name)
		})
	}
}

func TestSecurityValidator_ValidateCIDRs(t *testing.T) {
	validator := NewSecurityValidator()

	testCases := []struct {
		name         string
		cidrs        []string
		expectErrors bool
		minScore     int
	}{
		{
			name:     "Valid Private CIDRs",
			cidrs:    []string{"10.0.0.0/8", "192.168.1.0/24"},
			minScore: 75,
		},
		{
			name:         "Overly Permissive CIDR",
			cidrs:        []string{"0.0.0.0/0"},
			expectErrors: true,
			minScore:     50,
		},
		{
			name:         "Invalid CIDR Format",
			cidrs:        []string{"256.256.256.256/8"},
			expectErrors: true,
			minScore:     70,
		},
		{
			name:     "Empty CIDRs",
			cidrs:    []string{},
			minScore: 75,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			secConfig := &SecurityConfig{
				AllowedCIDRs: tc.cidrs,
			}

			result := &ValidationResult{
				Valid:    true,
				Errors:   []string{},
				Warnings: []string{},
				Score:    100,
			}

			validator.validateSecurityConfig(secConfig, result)

			if tc.expectErrors {
				assert.NotEmpty(t, result.Errors, "Expected errors for CIDR test: %s", tc.name)
			}

			assert.GreaterOrEqual(t, result.Score, tc.minScore, "Security score too low for CIDR test: %s", tc.name)
		})
	}
}

func BenchmarkSecurityValidation(b *testing.B) {
	validator := NewSecurityValidator()
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	config := &EnhancedConfig{
		Address:    fmt.Sprintf("127.0.0.1:%d", shared.PortConsul),
		Datacenter: "dc1",
		Token:      "550e8400-e29b-41d4-a716-446655440000",
		TLSConfig: &TLSConfig{
			Enabled:        true,
			CertFile:       "/etc/consul/tls/cert.pem",
			KeyFile:        "/etc/consul/tls/key.pem",
			CAFile:         "/etc/consul/tls/ca.pem",
			VerifyIncoming: true,
			VerifyOutgoing: true,
		},
		ACLConfig: &ACLConfig{
			Enabled:       true,
			DefaultPolicy: "deny",
			TokenPersist:  true,
		},
		SecurityConfig: &SecurityConfig{
			EncryptionEnabled: true,
			DenyByDefault:     true,
			AllowedCIDRs:      []string{"10.0.0.0/8"},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := validator.ValidateConfig(rc, config)
		_ = result
	}
}
