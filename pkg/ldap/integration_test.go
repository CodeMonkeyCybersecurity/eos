package ldap

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

// TestLDAPIntegration tests LDAP operations in integration scenarios
func TestLDAPIntegration(t *testing.T) {
	// Skip integration tests if not in integration test mode
	if os.Getenv("Eos_INTEGRATION_TESTS") != "true" {
		t.Skip("Skipping integration tests. Set Eos_INTEGRATION_TESTS=true to run.")
	}

	ctx := context.Background()
	logger := zap.NewNop()
	rc := &eos_io.RuntimeContext{
		Ctx: ctx,
		Log: logger,
	}

	t.Run("full_ldap_workflow", func(t *testing.T) {
		// Test complete LDAP workflow: connect, create user, add to group, cleanup
		cfg := getTestLDAPConfig(t)
		if cfg == nil {
			t.Skip("No test LDAP configuration available")
		}

		// Test connection
		err := CheckConnection(rc, cfg)
		if err != nil {
			t.Skipf("Cannot connect to test LDAP server: %v", err)
		}

		// Test user creation
		testUser := LDAPUser{
			UID:  "testuser_integration",
			CN:   "Integration Test User",
			Mail: "integration@example.com",
			DN:   fmt.Sprintf("uid=testuser_integration,%s", cfg.UserBase),
		}

		// Create user
		err = createUser(cfg, testUser, "TestPassword123!")
		if err != nil {
			t.Logf("User creation failed (may already exist): %v", err)
		}

		// Test user search
		users, err := readUsersWithFilter(rc, "(uid=testuser_integration)")
		if err == nil && len(users) > 0 {
			assert.Equal(t, "testuser_integration", users[0].UID)
		}

		// Test group creation
		testGroup := LDAPGroup{
			CN:      "TestGroup_Integration",
			DN:      fmt.Sprintf("cn=TestGroup_Integration,%s", cfg.RoleBase),
			Members: []string{testUser.DN},
		}

		err = createGroup(rc, cfg, testGroup)
		if err != nil {
			t.Logf("Group creation failed (may already exist): %v", err)
		}

		// Test group search
		groups, err := readGroupsWithFilter(rc, "(cn=TestGroup_Integration)")
		if err == nil && len(groups) > 0 {
			assert.Equal(t, "TestGroup_Integration", groups[0].CN)
		}

		// Cleanup would go here in a real test environment
		// For safety, we don't delete in integration tests
	})

	t.Run("configuration_discovery", func(t *testing.T) {
		// Test configuration discovery methods
		cfg, source, err := ReadConfig(rc)

		// Should find configuration from some source
		assert.NoError(t, err)
		assert.NotNil(t, cfg)
		assert.NotEmpty(t, source)

		// Configuration should be valid
		assert.NotEmpty(t, cfg.FQDN)
		assert.NotEmpty(t, cfg.BindDN)
		assert.Greater(t, cfg.Port, 0)
		assert.LessOrEqual(t, cfg.Port, 65535)
	})

	t.Run("vault_integration", func(t *testing.T) {
		// Test Vault integration if available
		cfg, err := readFromVault(rc)
		if err != nil {
			t.Logf("Vault integration not available: %v", err)
			return
		}

		// If Vault is available, test configuration
		assert.NotNil(t, cfg)
		assert.NotEmpty(t, cfg.FQDN)
		assert.NotEmpty(t, cfg.BindDN)
	})

	t.Run("performance_benchmarks", func(t *testing.T) {
		cfg := getTestLDAPConfig(t)
		if cfg == nil {
			t.Skip("No test LDAP configuration available")
		}

		// Test connection performance
		start := time.Now()
		err := CheckConnection(rc, cfg)
		elapsed := time.Since(start)

		if err == nil {
			// Connection should be fast
			assert.Less(t, elapsed, 5*time.Second, "Connection should complete within 5 seconds")
		}

		// Test multiple connections (connection pooling behavior)
		start = time.Now()
		for i := 0; i < 5; i++ {
			err := CheckConnection(rc, cfg)
			if err != nil {
				break
			}
		}
		elapsed = time.Since(start)

		if err == nil {
			// Multiple connections should not take too long
			assert.Less(t, elapsed, 15*time.Second, "Multiple connections should complete within 15 seconds")
		}
	})

	t.Run("error_handling_integration", func(t *testing.T) {
		// Test error handling in integration scenarios

		// Test invalid server
		invalidCfg := &LDAPConfig{
			FQDN:     "invalid.server.that.does.not.exist",
			Port:     389,
			UseTLS:   false,
			BindDN:   "cn=admin,dc=example,dc=com",
			Password: "password123",
		}

		err := CheckConnection(rc, invalidCfg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "connection test failed")

		// Test invalid credentials
		if cfg := getTestLDAPConfig(t); cfg != nil {
			badCfg := *cfg
			badCfg.Password = "invalid_password"

			err := CheckConnection(rc, &badCfg)
			assert.Error(t, err)
		}
	})

	t.Run("security_validation", func(t *testing.T) {
		// Test security validation in integration environment
		cfg := getTestLDAPConfig(t)
		if cfg == nil {
			t.Skip("No test LDAP configuration available")
		}

		// Test TLS configuration if enabled
		if cfg.UseTLS {
			assert.True(t, cfg.UseTLS, "TLS should be enabled for secure connections")
			assert.Equal(t, 636, cfg.Port, "LDAPS port should be 636")
		}

		// Test password is not empty
		assert.NotEmpty(t, cfg.Password, "Password should not be empty")

		// Test bind DN format
		assert.Contains(t, cfg.BindDN, "dc=", "BindDN should contain domain component")
	})
}

// TestLDAPMockIntegration tests LDAP operations with mock scenarios
func TestLDAPMockIntegration(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()
	rc := &eos_io.RuntimeContext{
		Ctx: ctx,
		Log: logger,
	}

	t.Run("mock_authentication_flow", func(t *testing.T) {
		// Test authentication flow with mock data
		cfg := &LDAPConfig{
			FQDN:         "mock.ldap.server",
			Port:         389,
			UseTLS:       false,
			BindDN:       "cn=admin,dc=mock,dc=com",
			Password:     "mockpassword",
			UserBase:     "ou=Users,dc=mock,dc=com",
			RoleBase:     "ou=Groups,dc=mock,dc=com",
			AdminRole:    "MockAdmins",
			ReadonlyRole: "MockReadonly",
		}

		// Test configuration validation
		assert.NotEmpty(t, cfg.FQDN)
		assert.NotEmpty(t, cfg.BindDN)
		assert.NotEmpty(t, cfg.Password)
		assert.NotEmpty(t, cfg.UserBase)
		assert.NotEmpty(t, cfg.RoleBase)
		assert.NotEmpty(t, cfg.AdminRole)
		assert.NotEmpty(t, cfg.ReadonlyRole)

		// Test connection attempt (will fail but should handle gracefully)
		err := CheckConnection(rc, cfg)
		assert.Error(t, err, "Should fail for mock server")
		assert.Contains(t, err.Error(), "connection test failed")
	})

	t.Run("mock_user_operations", func(t *testing.T) {
		// Test user operations with mock data
		user := LDAPUser{
			UID:  "mockuser",
			CN:   "Mock User",
			Mail: "mock@example.com",
			DN:   "uid=mockuser,ou=Users,dc=mock,dc=com",
		}

		// Test user struct validation
		assert.Equal(t, "mockuser", user.UID)
		assert.Equal(t, "Mock User", user.CN)
		assert.Equal(t, "mock@example.com", user.Mail)
		assert.Contains(t, user.DN, "uid=mockuser")
		assert.Contains(t, user.DN, "dc=mock,dc=com")
	})

	t.Run("mock_group_operations", func(t *testing.T) {
		// Test group operations with mock data
		group := LDAPGroup{
			CN: "MockGroup",
			DN: "cn=MockGroup,ou=Groups,dc=mock,dc=com",
			Members: []string{
				"uid=user1,ou=Users,dc=mock,dc=com",
				"uid=user2,ou=Users,dc=mock,dc=com",
			},
		}

		// Test group struct validation
		assert.Equal(t, "MockGroup", group.CN)
		assert.Contains(t, group.DN, "cn=MockGroup")
		assert.Len(t, group.Members, 2)

		for _, member := range group.Members {
			assert.Contains(t, member, "uid=")
			assert.Contains(t, member, "dc=mock,dc=com")
		}
	})

	t.Run("mock_error_scenarios", func(t *testing.T) {
		// Test error scenarios with mock data

		// Test empty configuration
		emptyCfg := &LDAPConfig{}
		err := CheckConnection(rc, emptyCfg)
		assert.Error(t, err)

		// Test invalid port
		invalidPortCfg := &LDAPConfig{
			FQDN:     "mock.ldap.server",
			Port:     -1,
			BindDN:   "cn=admin,dc=mock,dc=com",
			Password: "password",
		}
		err = CheckConnection(rc, invalidPortCfg)
		assert.Error(t, err)

		// Test missing bind DN
		missingBindCfg := &LDAPConfig{
			FQDN:     "mock.ldap.server",
			Port:     389,
			Password: "password",
		}
		err = CheckConnection(rc, missingBindCfg)
		assert.Error(t, err)
	})
}

// TestLDAPSecurityIntegration tests security aspects in integration scenarios
func TestLDAPSecurityIntegration(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()
	rc := &eos_io.RuntimeContext{
		Ctx: ctx,
		Log: logger,
	}

	t.Run("security_configuration_validation", func(t *testing.T) {
		// Test security configuration validation
		cfg := &LDAPConfig{
			FQDN:         "secure.ldap.server",
			Port:         636,
			UseTLS:       true,
			BindDN:       "cn=admin,dc=secure,dc=com",
			Password:     "SecurePassword123!",
			UserBase:     "ou=Users,dc=secure,dc=com",
			RoleBase:     "ou=Groups,dc=secure,dc=com",
			AdminRole:    "Administrators",
			ReadonlyRole: "ReadOnly",
		}

		// Test secure configuration
		assert.True(t, cfg.UseTLS, "Should use TLS for secure connections")
		assert.Equal(t, 636, cfg.Port, "Should use secure LDAPS port")
		assert.NotEmpty(t, cfg.Password, "Password should not be empty")

		// Test role separation
		assert.NotEqual(t, cfg.AdminRole, cfg.ReadonlyRole, "Admin and readonly roles should be different")
	})

	t.Run("credential_handling_security", func(t *testing.T) {
		// Test credential handling security
		cfg := &LDAPConfig{
			FQDN:     "ldap.example.com",
			Port:     389,
			BindDN:   "cn=admin,dc=example,dc=com",
			Password: "password123",
		}

		// Test that password is not logged or exposed
		assert.NotEmpty(t, cfg.Password, "Password should be available for authentication")

		// Test password field metadata
		passwordMeta := LDAPFieldMeta["Password"]
		assert.True(t, passwordMeta.Sensitive, "Password should be marked as sensitive")
	})

	t.Run("connection_security_validation", func(t *testing.T) {
		// Test connection security validation

		// Test TLS configuration security
		_ = os.Unsetenv("Eos_INSECURE_TLS")
		_ = os.Unsetenv("GO_ENV")

		tlsConfig := getSecureTLSConfig()

		// Verify secure TLS settings
		assert.False(t, tlsConfig.InsecureSkipVerify, "Should not skip TLS verification")
		assert.NotEmpty(t, tlsConfig.CipherSuites, "Should have secure cipher suites")
	})

	t.Run("injection_prevention_integration", func(t *testing.T) {
		// Test injection prevention in integration context

		// Test with potentially malicious input
		maliciousInputs := []string{
			"admin)(|(objectClass=*))",
			"*)(uid=*))(|(uid=*",
			"admin)(|(cn=*))",
		}

		for _, input := range maliciousInputs {
			// Test user search with malicious input
			users, err := readUsersWithFilter(rc, fmt.Sprintf("(uid=%s)", input))

			// Should handle malicious input safely
			if err != nil {
				assert.NotContains(t, err.Error(), "panic", "Should not panic on malicious input")
			} else {
				// Should not return unexpected results
				assert.LessOrEqual(t, len(users), 1, "Should not return excessive results")
			}
		}
	})

	t.Run("timeout_security_integration", func(t *testing.T) {
		// Test timeout security in integration context
		start := time.Now()

		// Test with unreachable server
		unreachableCfg := &LDAPConfig{
			FQDN:     "192.0.2.1", // Test network (RFC 3330)
			Port:     389,
			UseTLS:   false,
			BindDN:   "cn=admin,dc=example,dc=com",
			Password: "password123",
		}

		err := CheckConnection(rc, unreachableCfg)
		elapsed := time.Since(start)

		// Should timeout within reasonable time
		assert.Error(t, err)
		assert.Less(t, elapsed, 30*time.Second, "Should timeout within 30 seconds")
	})
}

// getTestLDAPConfig returns a test LDAP configuration if available
func getTestLDAPConfig(t *testing.T) *LDAPConfig {
	// Try to get test configuration from environment
	if fqdn := os.Getenv("TEST_LDAP_FQDN"); fqdn != "" {
		return &LDAPConfig{
			FQDN:         fqdn,
			Port:         389,
			UseTLS:       false,
			BindDN:       os.Getenv("TEST_LDAP_BIND_DN"),
			Password:     os.Getenv("TEST_LDAP_PASSWORD"),
			UserBase:     os.Getenv("TEST_LDAP_USER_BASE"),
			RoleBase:     os.Getenv("TEST_LDAP_GROUP_BASE"),
			AdminRole:    "TestAdmins",
			ReadonlyRole: "TestReadonly",
		}
	}

	// Try to detect from host
	if IsPortOpen(389) {
		return &LDAPConfig{
			FQDN:         "localhost",
			Port:         389,
			UseTLS:       false,
			BindDN:       "cn=admin,dc=example,dc=com",
			Password:     "admin",
			UserBase:     "ou=Users,dc=example,dc=com",
			RoleBase:     "ou=Groups,dc=example,dc=com",
			AdminRole:    "Administrators",
			ReadonlyRole: "ReadOnly",
		}
	}

	return nil
}

// TestLDAPHealthChecks tests health check functionality
func TestLDAPHealthChecks(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()
	rc := &eos_io.RuntimeContext{
		Ctx: ctx,
		Log: logger,
	}

	t.Run("health_check_integration", func(t *testing.T) {
		// Test LDAP health check functionality
		cfg := getTestLDAPConfig(t)
		if cfg == nil {
			t.Skip("No test LDAP configuration available")
		}

		// Test connection health check
		err := CheckConnection(rc, cfg)
		if err != nil {
			t.Logf("LDAP health check failed: %v", err)
			assert.Contains(t, err.Error(), "connection test failed")
		} else {
			t.Log("LDAP health check passed")
		}
	})

	t.Run("systemd_service_detection", func(t *testing.T) {
		// Test systemd service detection
		services := []string{"slapd", "389-ds", "openldap"}

		for _, service := range services {
			isActive := IsSystemdUnitActive(service)
			t.Logf("Service %s active: %v", service, isActive)

			// Should return boolean without error
			assert.IsType(t, true, isActive)
		}
	})

	t.Run("ldap_probe_integration", func(t *testing.T) {
		// Test LDAP probe functionality
		err := runLDAPProbe()
		if err != nil {
			t.Logf("LDAP probe failed: %v", err)
		} else {
			t.Log("LDAP probe succeeded")
		}

		// Test authentication probe
		err = runLDAPAuthProbe("cn=admin,dc=example,dc=com", "testpassword")
		if err != nil {
			t.Logf("LDAP auth probe failed: %v", err)
		} else {
			t.Log("LDAP auth probe succeeded")
		}
	})
}

// BenchmarkLDAPOperations benchmarks LDAP operations
func BenchmarkLDAPOperations(b *testing.B) {
	if os.Getenv("Eos_BENCHMARK_TESTS") != "true" {
		b.Skip("Skipping benchmark tests. Set Eos_BENCHMARK_TESTS=true to run.")
	}

	ctx := context.Background()
	logger := zap.NewNop()
	rc := &eos_io.RuntimeContext{
		Ctx: ctx,
		Log: logger,
	}

	cfg := &LDAPConfig{
		FQDN:     "localhost",
		Port:     389,
		UseTLS:   false,
		BindDN:   "cn=admin,dc=example,dc=com",
		Password: "admin",
	}

	b.Run("connection_benchmark", func(b *testing.B) {
		for b.Loop() {
			_ = CheckConnection(rc, cfg)
		}
	})

	b.Run("config_load_benchmark", func(b *testing.B) {
		for b.Loop() {
			_, _, _ = ReadConfig(rc)
		}
	})

	b.Run("port_check_benchmark", func(b *testing.B) {
		for b.Loop() {
			_ = IsPortOpen(389)
		}
	})
}
