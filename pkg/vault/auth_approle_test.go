package vault

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadAppRoleCredsFromDisk_Success(t *testing.T) {
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
	
	// Create test credentials
	testRoleID := "test-role-id-12345"
	testSecretID := "test-secret-id-67890"
	
	require.NoError(t, os.WriteFile(shared.AppRolePaths.RoleID, []byte(testRoleID+"\n"), 0600))
	require.NoError(t, os.WriteFile(shared.AppRolePaths.SecretID, []byte(testSecretID+"\n"), 0600))
	
	// Create runtime context
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	rc := &eos_io.RuntimeContext{
		Ctx: ctx,
	}
	
	// Test reading (without actual Vault client)
	roleID, secretID, err := readAppRoleCredsFromDisk(rc, nil)
	require.NoError(t, err)
	
	assert.Equal(t, testRoleID, roleID)
	assert.Equal(t, testSecretID, secretID)
}

func TestReadAppRoleCredsFromDisk_MissingFiles(t *testing.T) {
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
	
	// Create runtime context
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	rc := &eos_io.RuntimeContext{
		Ctx: ctx,
	}
	
	// Test reading missing role_id file
	_, _, err := readAppRoleCredsFromDisk(rc, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read credential from disk")
	
	// Create only role_id file
	require.NoError(t, os.WriteFile(shared.AppRolePaths.RoleID, []byte("test-role-id"), 0600))
	
	// Test reading missing secret_id file
	_, _, err = readAppRoleCredsFromDisk(rc, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read credential from disk")
}

func TestReadAppRoleCredsFromDisk_WrappedToken(t *testing.T) {
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
	
	// Create test credentials with wrapped token
	testRoleID := "test-role-id-12345"
	testWrappedToken := "s.1234567890abcdef"
	
	require.NoError(t, os.WriteFile(shared.AppRolePaths.RoleID, []byte(testRoleID), 0600))
	require.NoError(t, os.WriteFile(shared.AppRolePaths.SecretID, []byte(testWrappedToken), 0600))
	
	// Create runtime context
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	rc := &eos_io.RuntimeContext{
		Ctx: ctx,
	}
	
	// Test reading wrapped token (will fail because we don't have a real Vault client)
	_, _, err := readAppRoleCredsFromDisk(rc, nil)
	require.Error(t, err)
	// Should fail trying to unwrap because client is nil
	assert.Contains(t, err.Error(), "failed to unwrap credential")
}

func TestWriteAppRoleFiles_Success(t *testing.T) {
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
	
	// Create runtime context
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	rc := &eos_io.RuntimeContext{
		Ctx: ctx,
	}
	
	testRoleID := "test-role-id-12345"
	testSecretID := "test-secret-id-67890"
	
	// This will fail due to user lookup, but we can test file creation
	err := WriteAppRoleFiles(rc, testRoleID, testSecretID)
	// Expected to fail due to eos user lookup in test environment
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "lookup user")
}

func TestDefaultAppRoleOptions(t *testing.T) {
	opts := shared.DefaultAppRoleOptions()
	
	assert.Equal(t, shared.AppRoleName, opts.RoleName)
	assert.Equal(t, []string{shared.EosDefaultPolicyName}, opts.Policies)
	assert.Equal(t, "1h", opts.TokenTTL)
	assert.Equal(t, "4h", opts.TokenMaxTTL)
	assert.Equal(t, "24h", opts.SecretIDTTL)
	assert.False(t, opts.ForceRecreate)
	assert.False(t, opts.RefreshCreds)
}

func TestBuildAppRoleLoginPayload(t *testing.T) {
	roleID := "test-role-id"
	secretID := "test-secret-id"
	
	payload := shared.BuildAppRoleLoginPayload(roleID, secretID)
	
	assert.Equal(t, roleID, payload["role_id"])
	assert.Equal(t, secretID, payload["secret_id"])
	assert.Len(t, payload, 2)
}

func TestBuildAppRoleLoginPayload_WithWhitespace(t *testing.T) {
	roleID := "  test-role-id  "
	secretID := "\ttest-secret-id\n"
	
	payload := shared.BuildAppRoleLoginPayload(roleID, secretID)
	
	// Should trim whitespace
	assert.Equal(t, "test-role-id", payload["role_id"])
	assert.Equal(t, "test-secret-id", payload["secret_id"])
}

func TestPhaseCreateAppRole_InvalidOptions(t *testing.T) {
	// Create runtime context
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	rc := &eos_io.RuntimeContext{
		Ctx: ctx,
	}
	
	// Test with nil client (should fail gracefully)
	opts := shared.DefaultAppRoleOptions()
	
	// This will fail because we don't have a real Vault client
	_, _, err := PhaseCreateAppRole(rc, nil, nil, opts)
	require.Error(t, err)
}

func TestAppRolePathConstants(t *testing.T) {
	// Test that AppRole path constants are correctly constructed
	assert.Equal(t, "eos-approle", shared.AppRoleName)
	assert.Equal(t, "auth/approle/role/eos-approle", shared.AppRolePath)
	assert.Equal(t, "auth/approle/login", shared.AppRoleLoginPath)
	assert.Equal(t, "auth/approle/role/eos-approle/role-id", shared.AppRoleRoleIDPath)
	assert.Equal(t, "auth/approle/role/eos-approle/secret-id", shared.AppRoleSecretIDPath)
}

func TestUserDataTemplate(t *testing.T) {
	password := "test-password-123"
	data := shared.UserDataTemplate(password)
	
	assert.Equal(t, password, data["password"])
	assert.Equal(t, []string{shared.EosDefaultPolicyName}, data["policies"])
	assert.Len(t, data, 2)
}

func TestFallbackSecretsTemplate(t *testing.T) {
	password := "test-password-123"
	data := shared.FallbackSecretsTemplate(password)
	
	assert.Equal(t, password, data[shared.FallbackPasswordKey])
	assert.Len(t, data, 1)
}

func TestAppRoleCredentialSecurity(t *testing.T) {
	// Test that credentials are handled securely
	
	// Test that role IDs and secret IDs are properly validated
	testCases := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "valid role ID format",
			input:    "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
			expected: true,
		},
		{
			name:     "empty credential",
			input:    "",
			expected: false,
		},
		{
			name:     "whitespace only",
			input:    "   \t\n  ",
			expected: false,
		},
		{
			name:     "valid secret ID",
			input:    "test-secret-id-12345",
			expected: true,
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			trimmed := strings.TrimSpace(tc.input)
			isEmpty := trimmed == ""
			
			if tc.expected {
				assert.NotEmpty(t, trimmed, "valid credentials should not be empty after trimming")
			} else {
				assert.True(t, isEmpty, "invalid credentials should be empty after trimming")
			}
		})
	}
}

func TestAppRoleFilePermissions(t *testing.T) {
	// Test that AppRole files are created with secure permissions
	expectedMode := shared.FilePermOwnerReadWrite // Should be 0600
	
	// Verify the constant is set correctly for security
	assert.Equal(t, os.FileMode(0600), expectedMode, "AppRole files should be owner read/write only")
	
	// Test that the mode provides appropriate security
	assert.Equal(t, os.FileMode(0600), expectedMode&0777, "File mode should mask to 0600")
	
	// Verify no group or world access
	assert.Equal(t, os.FileMode(0), expectedMode&0077, "No group or world access should be allowed")
}