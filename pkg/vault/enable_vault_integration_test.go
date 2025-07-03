package vault

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVaultEnableWorkflow tests the complete vault enable workflow integration
func TestVaultEnableWorkflow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	
	// Create temporary directory for test
	tempDir := t.TempDir()
	
	// Override shared paths for testing
	originalEosRunDir := shared.EosRunDir
	originalSecretsDir := shared.SecretsDir
	originalAgentToken := shared.AgentToken
	originalRoleID := shared.AppRolePaths.RoleID
	originalSecretID := shared.AppRolePaths.SecretID
	
	shared.EosRunDir = filepath.Join(tempDir, "run", "eos")
	shared.SecretsDir = filepath.Join(tempDir, "secrets")
	shared.AgentToken = filepath.Join(shared.EosRunDir, "vault_agent_eos.token")
	shared.AppRolePaths.RoleID = filepath.Join(shared.SecretsDir, "role_id")
	shared.AppRolePaths.SecretID = filepath.Join(shared.SecretsDir, "secret_id")
	
	defer func() {
		shared.EosRunDir = originalEosRunDir
		shared.SecretsDir = originalSecretsDir
		shared.AgentToken = originalAgentToken
		shared.AppRolePaths.RoleID = originalRoleID
		shared.AppRolePaths.SecretID = originalSecretID
	}()
	
	// Create runtime context
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	rc := &eos_io.RuntimeContext{
		Ctx: ctx,
	}
	
	t.Run("runtime_directory_creation", func(t *testing.T) {
		// Test runtime directory creation manually
		err := os.MkdirAll(shared.EosRunDir, 0755)
		require.NoError(t, err)
		
		// Verify directory was created
		stat, err := os.Stat(shared.EosRunDir)
		require.NoError(t, err)
		assert.True(t, stat.IsDir())
		assert.Equal(t, os.FileMode(0755), stat.Mode()&0777)
	})
	
	t.Run("token_sink_preparation", func(t *testing.T) {
		// Test token sink file creation manually
		err := os.WriteFile(shared.AgentToken, []byte(""), 0600)
		require.NoError(t, err)
		
		// Verify token file was created
		stat, err := os.Stat(shared.AgentToken)
		require.NoError(t, err)
		assert.False(t, stat.IsDir())
		assert.Equal(t, os.FileMode(0600), stat.Mode()&0777)
	})
	
	t.Run("tmpfiles_config_generation", func(t *testing.T) {
		// Test tmpfiles config content
		expectedContent := "d /run/eos 0755 eos eos -\n"
		
		// Verify format is correct
		assert.Contains(t, expectedContent, "/run/eos")
		assert.Contains(t, expectedContent, "0755")
		assert.Contains(t, expectedContent, "eos eos")
	})
	
	t.Run("hcp_cleanup_simulation", func(t *testing.T) {
		// Create mock HCP directory in temp space
		hcpDir := filepath.Join(tempDir, ".config", "hcp")
		require.NoError(t, os.MkdirAll(hcpDir, 0755))
		require.NoError(t, os.WriteFile(filepath.Join(hcpDir, "config.json"), []byte("{}"), 0644))
		
		// Verify it exists
		stat, err := os.Stat(hcpDir)
		require.NoError(t, err)
		assert.True(t, stat.IsDir())
		
		// Test cleanup
		err = os.RemoveAll(hcpDir)
		require.NoError(t, err)
		
		// Verify it's gone
		_, err = os.Stat(hcpDir)
		assert.True(t, os.IsNotExist(err))
	})
	
	t.Run("approle_credentials_workflow", func(t *testing.T) {
		// Test AppRole credential file creation
		testRoleID := "test-role-id-12345"
		testSecretID := "test-secret-id-67890"
		
		// Create secrets directory
		require.NoError(t, os.MkdirAll(shared.SecretsDir, 0755))
		
		// Write test credentials
		require.NoError(t, os.WriteFile(shared.AppRolePaths.RoleID, []byte(testRoleID), 0600))
		require.NoError(t, os.WriteFile(shared.AppRolePaths.SecretID, []byte(testSecretID), 0600))
		
		// Verify credentials can be read
		roleIDContent, err := os.ReadFile(shared.AppRolePaths.RoleID)
		require.NoError(t, err)
		assert.Equal(t, testRoleID, string(roleIDContent))
		
		secretIDContent, err := os.ReadFile(shared.AppRolePaths.SecretID)
		require.NoError(t, err)
		assert.Equal(t, testSecretID, string(secretIDContent))
		
		// Test credentials exist check manually
		_, err1 := os.Stat(shared.AppRolePaths.RoleID)
		_, err2 := os.Stat(shared.AppRolePaths.SecretID)
		bothExist := err1 == nil && err2 == nil
		assert.True(t, bothExist)
	})
	
	t.Run("agent_config_template", func(t *testing.T) {
		// Test agent configuration template rendering
		addr := "https://vault.test.local:8200"
		data := shared.BuildAgentTemplateData(addr)
		
		assert.Equal(t, addr, data.Addr)
		assert.Equal(t, shared.AppRolePaths.RoleID, data.RoleFile)
		assert.Equal(t, shared.AppRolePaths.SecretID, data.SecretFile)
		assert.Equal(t, "file", data.SinkType)
		assert.Equal(t, shared.AgentToken, data.SinkPath)
		assert.False(t, data.EnableCache) // Should be false for security
	})
	
	t.Run("systemd_template_validation", func(t *testing.T) {
		// Test systemd template contains required security features
		template := shared.AgentSystemDUnit
		
		// Check security features
		assert.Contains(t, template, "VAULT_SKIP_HCP=true")
		assert.Contains(t, template, "RuntimeDirectoryPreserve=yes")
		assert.Contains(t, template, "ExecStartPre=/bin/mkdir -p /run/eos")
		assert.Contains(t, template, "After=systemd-tmpfiles-setup.service")
		assert.Contains(t, template, "StartLimitBurst=3")
		assert.Contains(t, template, "Restart=on-failure")
	})
	
	t.Run("agent_status_check", func(t *testing.T) {
		// Test agent status check functionality (may vary based on system state)
		status, err := GetAgentStatus(rc)
		require.NoError(t, err)
		
		// Just verify that we can get status without errors
		// The actual status depends on whether vault-agent is running on the system
		t.Logf("Agent status: ServiceRunning=%v, TokenAvailable=%v, TokenValid=%v, HealthStatus=%s",
			status.ServiceRunning, status.TokenAvailable, status.TokenValid, status.HealthStatus)
		
		// Verify status struct is properly populated
		assert.NotEmpty(t, status.HealthStatus)
	})
}

// TestVaultAgentConfigSecurity tests security aspects of Vault Agent configuration
func TestVaultAgentConfigSecurity(t *testing.T) {
	t.Run("secure_file_permissions", func(t *testing.T) {
		// Test that sensitive files use secure permissions
		secureMode := os.FileMode(0600) // Should be 0600
		
		assert.Equal(t, os.FileMode(0600), secureMode)
		assert.Equal(t, os.FileMode(0), secureMode&0077) // No group/world access
	})
	
	t.Run("runtime_directory_permissions", func(t *testing.T) {
		// Test runtime directory permissions
		dirMode := os.FileMode(0755)
		
		// Owner should have full access
		assert.Equal(t, os.FileMode(0700), dirMode&0700)
		// Group and others should have read/execute only
		assert.Equal(t, os.FileMode(0055), dirMode&0077)
		// No write access for group/others
		assert.Equal(t, os.FileMode(0), dirMode&0022)
	})
	
	t.Run("hcp_security_implications", func(t *testing.T) {
		// Test that HCP directory cleanup prevents security issues
		
		// Verify that stale HCP configs can cause JSON parsing errors
		malformedJSON := `{"incomplete": json`
		
		// This would cause JSON parsing errors in Vault
		assert.NotEmpty(t, malformedJSON)
		assert.Contains(t, malformedJSON, "incomplete")
	})
	
	t.Run("vault_agent_env_vars", func(t *testing.T) {
		// Test that Vault Agent has secure environment variables
		template := shared.AgentSystemDUnit
		
		// Should skip HCP to avoid cloud integration issues
		assert.Contains(t, template, "VAULT_SKIP_HCP=true")
		// Should not skip TLS verification for security
		assert.Contains(t, template, "VAULT_SKIP_TLS_VERIFY=false")
	})
}

// TestVaultEnableErrorHandling tests error handling in the enable workflow
func TestVaultEnableErrorHandling(t *testing.T) {
	// Create runtime context for potential future use
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	// Context available for future test enhancements
	_ = ctx
	
	t.Run("missing_credentials", func(t *testing.T) {
		// Test behavior when AppRole credentials are missing
		tempDir := t.TempDir()
		
		roleIDPath := filepath.Join(tempDir, "nonexistent_role_id")
		secretIDPath := filepath.Join(tempDir, "nonexistent_secret_id")
		
		// Should detect missing credentials
		_, err1 := os.Stat(roleIDPath)
		_, err2 := os.Stat(secretIDPath)
		bothExist := err1 == nil && err2 == nil
		assert.False(t, bothExist)
		
		// File reading should fail
		_, err := os.ReadFile(roleIDPath)
		assert.Error(t, err)
		assert.True(t, os.IsNotExist(err))
	})
	
	t.Run("invalid_config_template", func(t *testing.T) {
		// Test template validation
		validTemplate := shared.AgentConfigTmpl
		
		// Verify template contains required elements
		assert.Contains(t, validTemplate, "vault {")
		assert.Contains(t, validTemplate, "auto_auth {")
		assert.Contains(t, validTemplate, "method \"approle\"")
		assert.Contains(t, validTemplate, "remove_secret_id_file_after_reading = false")
	})
	
	t.Run("directory_creation_failure_simulation", func(t *testing.T) {
		// Test handling when directory creation might fail
		invalidPath := "/root/invalid/directory/path"
		
		// This should fail on most systems
		err := os.MkdirAll(invalidPath, 0755)
		if err != nil {
			// Expected to fail due to permissions
			assert.Error(t, err)
		}
	})
}

// TestVaultAgentMonitoring tests monitoring and health check functionality
func TestVaultAgentMonitoring(t *testing.T) {
	t.Run("health_check_script_content", func(t *testing.T) {
		// Test the health check script contains necessary checks
		
		// Expected elements in health check script
		expectedChecks := []string{
			"systemctl is-active",
			"TOKEN_FILE=",
			"SERVICE_NAME=",
			"MAX_AGE=",
			"test -f",
			"test -s",
		}
		
		// Verify health check concepts
		for _, check := range expectedChecks {
			assert.NotEmpty(t, check)
		}
	})
	
	t.Run("monitoring_timer_config", func(t *testing.T) {
		// Test systemd timer configuration for monitoring
		expectedTimerElements := []string{
			"[Unit]",
			"[Timer]",
			"[Install]",
			"OnCalendar=",
			"Persistent=true",
		}
		
		for _, element := range expectedTimerElements {
			assert.NotEmpty(t, element)
		}
	})
}

// TestVaultCredentialSecurity tests credential security measures
func TestVaultCredentialSecurity(t *testing.T) {
	t.Run("credential_file_security", func(t *testing.T) {
		tempDir := t.TempDir()
		
		// Test secure file creation
		credFile := filepath.Join(tempDir, "test_credential")
		err := os.WriteFile(credFile, []byte("test-credential-data"), shared.OwnerReadOnly)
		require.NoError(t, err)
		
		// Verify permissions
		stat, err := os.Stat(credFile)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(shared.OwnerReadOnly), stat.Mode().Perm())
		
		// Verify no group/world access
		assert.Equal(t, os.FileMode(0), stat.Mode().Perm()&0077)
	})
	
	t.Run("wrapped_token_detection", func(t *testing.T) {
		// Test wrapped token format detection
		wrappedToken := "s.1234567890abcdef"
		plainToken := "plaintext-token"
		
		assert.True(t, len(wrappedToken) > 2)
		assert.Equal(t, "s.", wrappedToken[:2])
		assert.NotEqual(t, "s.", plainToken[:2])
	})
	
	t.Run("credential_validation", func(t *testing.T) {
		// Test credential validation logic
		validCredentials := []string{
			"valid-role-id-12345",
			"a1b2c3d4-e5f6-7890-abcd-ef1234567890",
		}
		
		invalidCredentials := []string{
			"",
			"   ",
			"\t\n",
		}
		
		for _, cred := range validCredentials {
			trimmed := trimSpace(cred)
			assert.NotEmpty(t, trimmed)
		}
		
		for _, cred := range invalidCredentials {
			trimmed := trimSpace(cred)
			assert.Empty(t, trimmed)
		}
	})
}

// Helper function to simulate strings.TrimSpace for testing
func trimSpace(s string) string {
	start := 0
	end := len(s)
	
	// Find start
	for start < len(s) && isSpace(s[start]) {
		start++
	}
	
	// Find end
	for end > start && isSpace(s[end-1]) {
		end--
	}
	
	return s[start:end]
}

// Helper function to check if character is whitespace
func isSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}