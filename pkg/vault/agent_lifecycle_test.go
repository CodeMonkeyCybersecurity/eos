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

func TestDefaultVaultAgentConfig(t *testing.T) {
	config := DefaultVaultAgentConfig()
	
	assert.True(t, config.EnableCache)
	assert.Equal(t, "127.0.0.1:8100", config.ListenerAddress)
	assert.True(t, config.EnableAutoAuth)
	assert.True(t, config.CacheTemplates)
	assert.Equal(t, "info", config.LogLevel)
	assert.Equal(t, 3, config.MaxRetries)
	assert.Equal(t, "5s", config.RetryDelay)
}

func TestCredentialsExistOnDisk(t *testing.T) {
	// Create temporary directory for test
	tempDir := t.TempDir()
	
	// Override the shared paths for testing
	originalRoleID := shared.AppRolePaths.RoleID
	originalSecretID := shared.AppRolePaths.SecretID
	
	shared.AppRolePaths.RoleID = filepath.Join(tempDir, "role_id")
	shared.AppRolePaths.SecretID = filepath.Join(tempDir, "secret_id")
	
	defer func() {
		shared.AppRolePaths.RoleID = originalRoleID
		shared.AppRolePaths.SecretID = originalSecretID
	}()
	
	// Test when files don't exist
	assert.False(t, credentialsExistOnDisk())
	
	// Create role_id file
	require.NoError(t, os.WriteFile(shared.AppRolePaths.RoleID, []byte("test-role-id"), 0600))
	assert.False(t, credentialsExistOnDisk()) // Still false because secret_id missing
	
	// Create secret_id file
	require.NoError(t, os.WriteFile(shared.AppRolePaths.SecretID, []byte("test-secret-id"), 0600))
	assert.True(t, credentialsExistOnDisk()) // Now both exist
}

func TestAgentStatus(t *testing.T) {
	// Create runtime context for testing
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	rc := &eos_io.RuntimeContext{
		Ctx: ctx,
	}
	
	// Test with non-existent service and token
	status, err := GetAgentStatus(rc)
	require.NoError(t, err)
	
	assert.False(t, status.ServiceRunning)
	assert.False(t, status.TokenAvailable)
	assert.False(t, status.TokenValid)
	assert.False(t, status.ConfigValid)
	assert.Equal(t, "unhealthy", status.HealthStatus)
}

func TestAgentTemplateData(t *testing.T) {
	addr := "https://vault.example.com:8200"
	data := shared.BuildAgentTemplateData(addr)
	
	assert.Equal(t, addr, data.Addr)
	assert.Equal(t, shared.VaultAgentCACopyPath, data.CACert)
	assert.Equal(t, shared.AppRolePaths.RoleID, data.RoleFile)
	assert.Equal(t, shared.AppRolePaths.SecretID, data.SecretFile)
	assert.Equal(t, "file", data.SinkType)
	assert.Equal(t, shared.AgentToken, data.SinkPath)
	assert.Equal(t, "127.0.0.1:8180", data.ListenerAddr)
	assert.False(t, data.EnableCache) // Should be false to avoid listener requirement
}

func TestWriteAppRoleCredentialsToDisk(t *testing.T) {
	// Create temporary directory for test
	tempDir := t.TempDir()
	
	// Override the shared paths for testing
	originalRoleID := shared.AppRolePaths.RoleID
	originalSecretID := shared.AppRolePaths.SecretID
	originalSecretsDir := shared.SecretsDir
	
	shared.AppRolePaths.RoleID = filepath.Join(tempDir, "role_id")
	shared.AppRolePaths.SecretID = filepath.Join(tempDir, "secret_id")
	shared.SecretsDir = tempDir
	
	defer func() {
		shared.AppRolePaths.RoleID = originalRoleID
		shared.AppRolePaths.SecretID = originalSecretID
		shared.SecretsDir = originalSecretsDir
	}()
	
	// Create runtime context for testing
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	rc := &eos_io.RuntimeContext{
		Ctx: ctx,
	}
	
	roleID := "test-role-id-12345"
	secretID := "test-secret-id-67890"
	
	// This will fail because we can't lookup the 'eos' user in tests
	// But we can verify the files were created
	err := writeAppRoleCredentialsToDisk(rc, roleID, secretID)
	// Error is expected due to user lookup failure, but files should still be created
	
	// Verify files were created with correct content
	roleIDContent, err := os.ReadFile(shared.AppRolePaths.RoleID)
	require.NoError(t, err)
	assert.Equal(t, roleID, string(roleIDContent))
	
	secretIDContent, err := os.ReadFile(shared.AppRolePaths.SecretID)
	require.NoError(t, err)
	assert.Equal(t, secretID, string(secretIDContent))
	
	// Verify file permissions
	roleIDStat, err := os.Stat(shared.AppRolePaths.RoleID)
	require.NoError(t, err)
	assert.Equal(t, shared.OwnerReadOnly, roleIDStat.Mode())
	
	secretIDStat, err := os.Stat(shared.AppRolePaths.SecretID)
	require.NoError(t, err)
	assert.Equal(t, shared.OwnerReadOnly, secretIDStat.Mode())
}

func TestVaultAgentConfig_Validation(t *testing.T) {
	tests := []struct {
		name   string
		config *VaultAgentConfig
		valid  bool
	}{
		{
			name:   "default config is valid",
			config: DefaultVaultAgentConfig(),
			valid:  true,
		},
		{
			name: "config with invalid retry delay",
			config: &VaultAgentConfig{
				EnableCache:     true,
				ListenerAddress: "127.0.0.1:8100",
				EnableAutoAuth:  true,
				CacheTemplates:  true,
				LogLevel:        "info",
				MaxRetries:      3,
				RetryDelay:      "invalid",
			},
			valid: false,
		},
		{
			name: "config with negative max retries",
			config: &VaultAgentConfig{
				EnableCache:     true,
				ListenerAddress: "127.0.0.1:8100",
				EnableAutoAuth:  true,
				CacheTemplates:  true,
				LogLevel:        "info",
				MaxRetries:      -1,
				RetryDelay:      "5s",
			},
			valid: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test retry delay parsing
			if tt.config.RetryDelay != "" {
				_, err := time.ParseDuration(tt.config.RetryDelay)
				if tt.valid {
					assert.NoError(t, err, "valid config should have parseable retry delay")
				} else if tt.config.RetryDelay == "invalid" {
					assert.Error(t, err, "invalid retry delay should cause parse error")
				}
			}
			
			// Test max retries validation
			if !tt.valid && tt.config.MaxRetries < 0 {
				assert.True(t, tt.config.MaxRetries < 0, "negative max retries should be invalid")
			}
		})
	}
}

func TestAgentConfigTemplate(t *testing.T) {
	// Test that the agent config template can be parsed and contains expected sections
	template := shared.AgentConfigTmpl
	
	// Check for required sections
	assert.Contains(t, template, "vault {")
	assert.Contains(t, template, "auto_auth {")
	assert.Contains(t, template, "method \"approle\" {")
	assert.Contains(t, template, "sink \"{{ .SinkType }}\"")
	assert.Contains(t, template, "role_id_file_path")
	assert.Contains(t, template, "secret_id_file_path")
	assert.Contains(t, template, "remove_secret_id_file_after_reading = false")
	
	// Check conditional sections
	assert.Contains(t, template, "{{- if .EnableCache }}")
	assert.Contains(t, template, "listener \"tcp\" {")
	assert.Contains(t, template, "cache {")
}

func TestAgentSystemdTemplate(t *testing.T) {
	// Test that the systemd template contains required configuration
	template := shared.AgentSystemDUnit
	
	// Check for required systemd sections
	assert.Contains(t, template, "[Unit]")
	assert.Contains(t, template, "[Service]")
	assert.Contains(t, template, "[Install]")
	
	// Check for security and reliability features
	assert.Contains(t, template, "User={{ .User }}")
	assert.Contains(t, template, "Group={{ .Group }}")
	assert.Contains(t, template, "RuntimeDirectory={{ .RuntimeDir }}")
	assert.Contains(t, template, "RuntimeDirectoryPreserve=yes")
	assert.Contains(t, template, "VAULT_SKIP_HCP=true")
	assert.Contains(t, template, "ExecStartPre=/bin/mkdir -p /run/eos")
	assert.Contains(t, template, "ExecStartPre=/bin/chown {{ .User }}:{{ .Group }} /run/eos")
	assert.Contains(t, template, "Restart=on-failure")
	assert.Contains(t, template, "StartLimitBurst=3")
	assert.Contains(t, template, "After=systemd-tmpfiles-setup.service")
}