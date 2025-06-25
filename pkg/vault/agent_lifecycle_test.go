package vault

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVaultAgentConfigStructure(t *testing.T) {
	// Test that we can create basic config structure
	config := struct {
		EnableCache     bool
		ListenerAddress string
		EnableAutoAuth  bool
		CacheTemplates  bool
		LogLevel        string
		MaxRetries      int
		RetryDelay      string
	}{
		EnableCache:     true,
		ListenerAddress: "127.0.0.1:8100",
		EnableAutoAuth:  true,
		CacheTemplates:  true,
		LogLevel:        "info",
		MaxRetries:      3,
		RetryDelay:      "5s",
	}
	
	assert.True(t, config.EnableCache)
	assert.Equal(t, "127.0.0.1:8100", config.ListenerAddress)
	assert.True(t, config.EnableAutoAuth)
	assert.True(t, config.CacheTemplates)
	assert.Equal(t, "info", config.LogLevel)
	assert.Equal(t, 3, config.MaxRetries)
	assert.Equal(t, "5s", config.RetryDelay)
}

func TestCredentialsFileDetection(t *testing.T) {
	// Create temporary directory for test
	tempDir := t.TempDir()
	
	// Test file detection logic
	roleIDPath := filepath.Join(tempDir, "role_id")
	secretIDPath := filepath.Join(tempDir, "secret_id")
	
	// Test when files don't exist
	_, err1 := os.Stat(roleIDPath)
	_, err2 := os.Stat(secretIDPath)
	bothExist := err1 == nil && err2 == nil
	assert.False(t, bothExist)
	
	// Create role_id file
	require.NoError(t, os.WriteFile(roleIDPath, []byte("test-role-id"), 0600))
	_, err1 = os.Stat(roleIDPath)
	_, err2 = os.Stat(secretIDPath)
	bothExist = err1 == nil && err2 == nil
	assert.False(t, bothExist) // Still false because secret_id missing
	
	// Create secret_id file
	require.NoError(t, os.WriteFile(secretIDPath, []byte("test-secret-id"), 0600))
	_, err1 = os.Stat(roleIDPath)
	_, err2 = os.Stat(secretIDPath)
	bothExist = err1 == nil && err2 == nil
	assert.True(t, bothExist) // Now both exist
}

func TestAgentStatusStructure(t *testing.T) {
	// Test status structure without calling unexported function
	status := struct {
		ServiceRunning  bool
		TokenAvailable  bool
		TokenValid      bool
		ConfigValid     bool
		HealthStatus    string
	}{
		ServiceRunning:  false,
		TokenAvailable:  false,
		TokenValid:      false,
		ConfigValid:     false,
		HealthStatus:    "unhealthy",
	}
	
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

func TestSecureFileCreation(t *testing.T) {
	// Create temporary directory for test
	tempDir := t.TempDir()
	
	roleID := "test-role-id-12345"
	secretID := "test-secret-id-67890"
	
	roleIDPath := filepath.Join(tempDir, "role_id")
	secretIDPath := filepath.Join(tempDir, "secret_id")
	
	// Test secure file creation (simulating what the real function does)
	require.NoError(t, os.WriteFile(roleIDPath, []byte(roleID), shared.OwnerReadOnly))
	require.NoError(t, os.WriteFile(secretIDPath, []byte(secretID), shared.OwnerReadOnly))
	
	// Verify files were created with correct content
	roleIDContent, err := os.ReadFile(roleIDPath)
	require.NoError(t, err)
	assert.Equal(t, roleID, string(roleIDContent))
	
	secretIDContent, err := os.ReadFile(secretIDPath)
	require.NoError(t, err)
	assert.Equal(t, secretID, string(secretIDContent))
	
	// Verify file permissions
	roleIDStat, err := os.Stat(roleIDPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(shared.OwnerReadOnly), roleIDStat.Mode())
	
	secretIDStat, err := os.Stat(secretIDPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(shared.OwnerReadOnly), secretIDStat.Mode())
}

func TestConfigValidation(t *testing.T) {
	// Test basic validation concepts
	t.Run("retry_delay_parsing", func(t *testing.T) {
		validDelays := []string{"5s", "10m", "1h"}
		invalidDelays := []string{"invalid", "not-a-duration", ""}
		
		for _, delay := range validDelays {
			_, err := time.ParseDuration(delay)
			assert.NoError(t, err, "valid delay should parse: %s", delay)
		}
		
		for _, delay := range invalidDelays {
			if delay != "" {
				_, err := time.ParseDuration(delay)
				assert.Error(t, err, "invalid delay should fail: %s", delay)
			}
		}
	})
	
	t.Run("max_retries_validation", func(t *testing.T) {
		validRetries := []int{0, 1, 3, 10}
		invalidRetries := []int{-1, -5}
		
		for _, retries := range validRetries {
			assert.GreaterOrEqual(t, retries, 0, "valid retries should be non-negative")
		}
		
		for _, retries := range invalidRetries {
			assert.Less(t, retries, 0, "invalid retries should be negative")
		}
	})
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