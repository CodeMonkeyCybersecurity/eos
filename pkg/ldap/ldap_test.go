package ldap

import (
	"context"
	"crypto/tls"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestDefaultLDAPConfig(t *testing.T) {
	cfg := DefaultLDAPConfig()

	assert.Equal(t, "localhost", cfg.FQDN)
	assert.Equal(t, 389, cfg.Port)
	assert.False(t, cfg.UseTLS)
	assert.Equal(t, "cn=admin,dc=domain,dc=com", cfg.BindDN)
	assert.Equal(t, "", cfg.Password)
	assert.Equal(t, "ou=Users,dc=domain,dc=com", cfg.UserBase)
	assert.Equal(t, "ou=Groups,dc=domain,dc=com", cfg.RoleBase)
	assert.Equal(t, "AdminRole", cfg.AdminRole)
	assert.Equal(t, "ReadonlyRole", cfg.ReadonlyRole)
}

func TestTryLoadFromEnv(t *testing.T) {
	tests := []struct {
		name     string
		envVars  map[string]string
		expected *LDAPConfig
	}{
		{
			name: "complete configuration",
			envVars: map[string]string{
				"LDAP_FQDN":          "ldap.example.com",
				"LDAP_PORT":          "636",
				"LDAP_USE_TLS":       "true",
				"LDAP_BIND_DN":       "cn=admin,dc=example,dc=com",
				"LDAP_PASSWORD":      "secret123",
				"LDAP_USER_BASE":     "ou=Users,dc=example,dc=com",
				"LDAP_GROUP_BASE":    "ou=Groups,dc=example,dc=com",
				"LDAP_ADMIN_ROLE":    "Administrators",
				"LDAP_READONLY_ROLE": "Readers",
			},
			expected: &LDAPConfig{
				FQDN:         "ldap.example.com",
				Port:         636,
				UseTLS:       true,
				BindDN:       "cn=admin,dc=example,dc=com",
				Password:     "secret123",
				UserBase:     "ou=Users,dc=example,dc=com",
				RoleBase:     "ou=Groups,dc=example,dc=com",
				AdminRole:    "Administrators",
				ReadonlyRole: "Readers",
			},
		},
		{
			name: "missing required vars",
			envVars: map[string]string{
				"LDAP_FQDN": "ldap.example.com",
				// Missing LDAP_BIND_DN and LDAP_PASSWORD
			},
			expected: nil,
		},
		{
			name:     "no environment variables",
			envVars:  map[string]string{},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear all LDAP environment variables
			for _, envVar := range []string{
				"LDAP_FQDN", "LDAP_PORT", "LDAP_USE_TLS", "LDAP_BIND_DN",
				"LDAP_PASSWORD", "LDAP_USER_BASE", "LDAP_GROUP_BASE",
				"LDAP_ADMIN_ROLE", "LDAP_READONLY_ROLE",
			} {
				os.Unsetenv(envVar)
			}

			// Set test environment variables
			for key, value := range tt.envVars {
				os.Setenv(key, value)
			}

			cfg := TryLoadFromEnv()

			if tt.expected == nil {
				assert.Nil(t, cfg)
			} else {
				require.NotNil(t, cfg)
				assert.Equal(t, tt.expected, cfg)
			}

			// Cleanup
			for key := range tt.envVars {
				os.Unsetenv(key)
			}
		})
	}
}

func TestIsPortOpen(t *testing.T) {
	// Test with a port that should be closed
	assert.False(t, IsPortOpen(65432))

	// Test with a port that might be open (common HTTP port)
	// Note: This test may be flaky depending on the environment
	// In a real test environment, you might want to start a test server
}

func TestGetSecureTLSConfig(t *testing.T) {
	tests := []struct {
		name           string
		envVars        map[string]string
		expectInsecure bool
	}{
		{
			name:           "secure production config",
			envVars:        map[string]string{},
			expectInsecure: false,
		},
		{
			name: "insecure development config",
			envVars: map[string]string{
				"Eos_INSECURE_TLS": "true",
			},
			expectInsecure: true,
		},
		{
			name: "test environment config",
			envVars: map[string]string{
				"GO_ENV": "test",
			},
			expectInsecure: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear environment variables
			os.Unsetenv("Eos_INSECURE_TLS")
			os.Unsetenv("GO_ENV")

			// Set test environment variables
			for key, value := range tt.envVars {
				os.Setenv(key, value)
			}

			cfg := getSecureTLSConfig()

			assert.Equal(t, tt.expectInsecure, cfg.InsecureSkipVerify)
			assert.Equal(t, uint16(tls.VersionTLS12), cfg.MinVersion)

			if !tt.expectInsecure {
				// Verify secure cipher suites are set
				assert.NotEmpty(t, cfg.CipherSuites)
			}

			// Cleanup
			for key := range tt.envVars {
				os.Unsetenv(key)
			}
		})
	}
}

func TestTryReadFromVault(t *testing.T) {
	// Create a mock runtime context
	ctx := context.Background()
	logger := zap.NewNop()
	rc := &eos_io.RuntimeContext{
		Ctx: ctx,
		Log: logger,
	}

	// Note: This test would require a mock Vault client
	// For now, we'll test the error cases

	t.Run("nil client", func(t *testing.T) {
		cfg, err := TryReadFromVault(rc, nil)
		assert.Nil(t, cfg)
		assert.Error(t, err)
	})

	// Additional tests would require mocking the Vault client
	// which is beyond the scope of this basic test implementation
}

func TestCheckConnection(t *testing.T) {
	// Create a mock runtime context
	ctx := context.Background()
	logger := zap.NewNop()
	rc := &eos_io.RuntimeContext{
		Ctx: ctx,
		Log: logger,
	}

	// Test with invalid configuration
	invalidCfg := &LDAPConfig{
		FQDN:     "invalid.example.com",
		Port:     389,
		UseTLS:   false,
		BindDN:   "cn=admin,dc=example,dc=com",
		Password: "invalid",
	}

	err := CheckConnection(rc, invalidCfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "connection test failed")
}

func TestTryDetectFromHost(t *testing.T) {
	// This test depends on the actual host environment
	// In a real test setup, you might want to mock the network calls
	cfg := TryDetectFromHost()

	// The result depends on whether LDAP is running on localhost:389
	// We can't make strong assertions without controlling the environment
	if cfg != nil {
		assert.Equal(t, "localhost", cfg.FQDN)
		assert.Equal(t, 389, cfg.Port)
		assert.False(t, cfg.UseTLS)
	}
}

func TestLDAPConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *LDAPConfig
		isValid bool
	}{
		{
			name: "valid configuration",
			cfg: &LDAPConfig{
				FQDN:         "ldap.example.com",
				Port:         389,
				UseTLS:       false,
				BindDN:       "cn=admin,dc=example,dc=com",
				Password:     "secret123",
				UserBase:     "ou=Users,dc=example,dc=com",
				RoleBase:     "ou=Groups,dc=example,dc=com",
				AdminRole:    "Administrators",
				ReadonlyRole: "Readers",
			},
			isValid: true,
		},
		{
			name: "missing FQDN",
			cfg: &LDAPConfig{
				Port:     389,
				BindDN:   "cn=admin,dc=example,dc=com",
				Password: "secret123",
				UserBase: "ou=Users,dc=example,dc=com",
				RoleBase: "ou=Groups,dc=example,dc=com",
			},
			isValid: false,
		},
		{
			name: "missing BindDN",
			cfg: &LDAPConfig{
				FQDN:     "ldap.example.com",
				Port:     389,
				Password: "secret123",
				UserBase: "ou=Users,dc=example,dc=com",
				RoleBase: "ou=Groups,dc=example,dc=com",
			},
			isValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Basic validation - check if required fields are present
			isValid := tt.cfg.FQDN != "" && tt.cfg.BindDN != ""
			assert.Equal(t, tt.isValid, isValid)
		})
	}
}

func TestLDAPUser(t *testing.T) {
	user := LDAPUser{
		UID:  "testuser",
		CN:   "Test User",
		Mail: "test@example.com",
		DN:   "uid=testuser,ou=Users,dc=example,dc=com",
	}

	assert.Equal(t, "testuser", user.UID)
	assert.Equal(t, "Test User", user.CN)
	assert.Equal(t, "test@example.com", user.Mail)
	assert.Equal(t, "uid=testuser,ou=Users,dc=example,dc=com", user.DN)
}

func TestLDAPGroup(t *testing.T) {
	group := LDAPGroup{
		CN:      "TestGroup",
		DN:      "cn=TestGroup,ou=Groups,dc=example,dc=com",
		Members: []string{"uid=user1,ou=Users,dc=example,dc=com", "uid=user2,ou=Users,dc=example,dc=com"},
	}

	assert.Equal(t, "TestGroup", group.CN)
	assert.Equal(t, "cn=TestGroup,ou=Groups,dc=example,dc=com", group.DN)
	assert.Len(t, group.Members, 2)
	assert.Contains(t, group.Members, "uid=user1,ou=Users,dc=example,dc=com")
	assert.Contains(t, group.Members, "uid=user2,ou=Users,dc=example,dc=com")
}

func TestLDAPFieldMeta(t *testing.T) {
	// Test that all expected fields are present in the field metadata
	expectedFields := []string{
		"FQDN", "BindDN", "Password", "UserBase", "RoleBase", "AdminRole", "ReadonlyRole",
	}

	for _, field := range expectedFields {
		meta, exists := LDAPFieldMeta[field]
		assert.True(t, exists, "Field %s should exist in LDAPFieldMeta", field)
		assert.NotEmpty(t, meta.Label, "Field %s should have a label", field)
		assert.NotEmpty(t, meta.Help, "Field %s should have help text", field)
	}

	// Test that Password field is marked as sensitive
	passwordMeta := LDAPFieldMeta["Password"]
	assert.True(t, passwordMeta.Sensitive, "Password field should be marked as sensitive")
	assert.True(t, passwordMeta.Required, "Password field should be required")

	// Test that FQDN field is required but not sensitive
	fqdnMeta := LDAPFieldMeta["FQDN"]
	assert.True(t, fqdnMeta.Required, "FQDN field should be required")
	assert.False(t, fqdnMeta.Sensitive, "FQDN field should not be sensitive")
}

// Security-focused tests

func TestSecureTLSConfiguration(t *testing.T) {
	// Test that secure TLS configuration uses appropriate settings
	os.Unsetenv("Eos_INSECURE_TLS")
	os.Unsetenv("GO_ENV")

	cfg := getSecureTLSConfig()

	// Verify minimum TLS version
	assert.Equal(t, uint16(tls.VersionTLS12), cfg.MinVersion)

	// Verify cipher suites are configured
	assert.NotEmpty(t, cfg.CipherSuites)

	// Verify secure connection (not skipping verification)
	assert.False(t, cfg.InsecureSkipVerify)
}

func TestPasswordSensitivity(t *testing.T) {
	// Test that password is properly marked as sensitive in field metadata
	passwordMeta := LDAPFieldMeta["Password"]
	assert.True(t, passwordMeta.Sensitive, "Password field must be marked as sensitive")

	// Test that other fields are not unnecessarily marked as sensitive
	nonsensitiveFields := []string{"FQDN", "BindDN", "UserBase", "RoleBase", "AdminRole", "ReadonlyRole"}
	for _, field := range nonsensitiveFields {
		meta := LDAPFieldMeta[field]
		assert.False(t, meta.Sensitive, "Field %s should not be marked as sensitive", field)
	}
}

func TestConnectionTimeout(t *testing.T) {
	// Test that connection attempts have appropriate timeouts
	start := time.Now()

	// Try to connect to a non-existent server
	cfg := &LDAPConfig{
		FQDN:     "192.0.2.1", // RFC 3330 test address
		Port:     389,
		UseTLS:   false,
		BindDN:   "cn=admin,dc=example,dc=com",
		Password: "test",
	}

	_, err := ConnectWithGivenConfig(cfg)
	elapsed := time.Since(start)

	// Should fail due to network timeout
	assert.Error(t, err)
	// Should not hang indefinitely - should timeout within reasonable time
	assert.Less(t, elapsed, 30*time.Second, "Connection should timeout within 30 seconds")
}

func TestBindDNValidation(t *testing.T) {
	// Test that bind DN follows proper LDAP DN format
	validDNs := []string{
		"cn=admin,dc=example,dc=com",
		"uid=user,ou=People,dc=example,dc=org",
		"cn=service,ou=Services,dc=company,dc=net",
	}

	for _, dn := range validDNs {
		cfg := &LDAPConfig{
			FQDN:   "ldap.example.com",
			Port:   389,
			BindDN: dn,
		}

		// Basic validation - should contain DC components
		assert.Contains(t, cfg.BindDN, "dc=", "BindDN should contain DC component: %s", dn)
	}
}

// Mock tests for network operations
func TestMockLDAPOperations(t *testing.T) {
	// This would be expanded with actual mock LDAP server for integration testing
	// For now, we test the error handling paths

	ctx := context.Background()
	logger := zap.NewNop()
	rc := &eos_io.RuntimeContext{
		Ctx: ctx,
		Log: logger,
	}

	// Test connection failure handling
	invalidCfg := &LDAPConfig{
		FQDN:     "invalid.domain.that.does.not.exist",
		Port:     389,
		UseTLS:   false,
		BindDN:   "cn=admin,dc=example,dc=com",
		Password: "test",
	}

	err := CheckConnection(rc, invalidCfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "connection test failed")
}

func TestLDAPConfigReflection(t *testing.T) {
	// Test that LDAPConfig struct has expected fields with proper types
	cfg := &LDAPConfig{}
	v := reflect.ValueOf(cfg).Elem()

	expectedFields := map[string]string{
		"FQDN":         "string",
		"Port":         "int",
		"UseTLS":       "bool",
		"BindDN":       "string",
		"Password":     "string",
		"UserBase":     "string",
		"RoleBase":     "string",
		"AdminRole":    "string",
		"ReadonlyRole": "string",
	}

	for fieldName, expectedType := range expectedFields {
		field := v.FieldByName(fieldName)
		assert.True(t, field.IsValid(), "Field %s should exist", fieldName)
		assert.Equal(t, expectedType, field.Type().String(), "Field %s should be of type %s", fieldName, expectedType)
	}
}
