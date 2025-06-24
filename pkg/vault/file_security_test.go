package vault

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/testutil"
)

func TestTokenFilePermissionValidation(t *testing.T) {
	rc := testutil.TestRuntimeContext(t)
	tempDir := t.TempDir()

	tests := []struct {
		name        string
		permissions os.FileMode
		expectError bool
		description string
	}{
		{
			name:        "secure_permissions",
			permissions: 0600,
			expectError: false,
			description: "Owner read/write only - secure",
		},
		{
			name:        "world_readable",
			permissions: 0644,
			expectError: true,
			description: "World readable - insecure",
		},
		{
			name:        "group_writable",
			permissions: 0660,
			expectError: true,
			description: "Group writable - insecure",
		},
		{
			name:        "world_writable",
			permissions: 0666,
			expectError: true,
			description: "World writable - very insecure",
		},
		{
			name:        "executable",
			permissions: 0700,
			expectError: true,
			description: "Executable permissions - insecure for token file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test token file with specific permissions
			tokenFile := filepath.Join(tempDir, tt.name+"_token")
			testToken := "hvs.test_token_123"

			err := os.WriteFile(tokenFile, []byte(testToken), tt.permissions)
			testutil.AssertNoError(t, err)

			// Test permission validation
			err = ValidateTokenFilePermissions(rc, tokenFile)

			if tt.expectError {
				testutil.AssertError(t, err)
				t.Logf(" Correctly rejected insecure permissions: %s", tt.description)
			} else {
				testutil.AssertNoError(t, err)
				t.Logf(" Correctly accepted secure permissions: %s", tt.description)
			}
		})
	}
}

func TestSecureTokenFileOperations(t *testing.T) {
	rc := testutil.TestRuntimeContext(t)
	tempDir := t.TempDir()

	t.Run("secure_write_and_read", func(t *testing.T) {
		tokenFile := filepath.Join(tempDir, "secure_token")
		testToken := "hvs.AAAAAQKLwI_VgPyvmn_dV7wR8xOz"

		// Write token securely
		err := SecureWriteTokenFile(rc, tokenFile, testToken)
		testutil.AssertNoError(t, err)

		// Verify file has correct permissions
		info, err := os.Stat(tokenFile)
		testutil.AssertNoError(t, err)
		testutil.AssertEqual(t, SecureFilePermissions, info.Mode().Perm())

		// Read token securely
		readToken, err := SecureReadTokenFile(rc, tokenFile)
		testutil.AssertNoError(t, err)
		testutil.AssertEqual(t, testToken, readToken)
	})

	t.Run("refuse_to_read_insecure_file", func(t *testing.T) {
		tokenFile := filepath.Join(tempDir, "insecure_token")
		testToken := "hvs.InsecureToken123"

		// Write file with insecure permissions
		err := os.WriteFile(tokenFile, []byte(testToken), 0644) // World readable
		testutil.AssertNoError(t, err)

		// Should refuse to read
		_, err = SecureReadTokenFile(rc, tokenFile)
		testutil.AssertError(t, err)
		testutil.AssertErrorContains(t, err, "insecure permissions")
	})

	t.Run("create_secure_directory", func(t *testing.T) {
		deepPath := filepath.Join(tempDir, "deep", "nested", "path", "token")
		testToken := "hvs.DeepPathToken"

		// Should create directory structure with secure permissions
		err := SecureWriteTokenFile(rc, deepPath, testToken)
		testutil.AssertNoError(t, err)

		// Verify file exists and is readable
		readToken, err := SecureReadTokenFile(rc, deepPath)
		testutil.AssertNoError(t, err)
		testutil.AssertEqual(t, testToken, readToken)

		// Verify directory has secure permissions (700)
		dirInfo, err := os.Stat(filepath.Dir(deepPath))
		testutil.AssertNoError(t, err)
		testutil.AssertEqual(t, os.FileMode(0700), dirInfo.Mode().Perm())
	})
}

func TestVaultTokenFormatValidation(t *testing.T) {
	tests := []struct {
		name        string
		token       string
		expectValid bool
	}{
		{
			name:        "valid_hvs_token",
			token:       "hvs.AAAAAQKLwI_VgPyvmn_dV7wR8xOz",
			expectValid: true,
		},
		{
			name:        "valid_legacy_service_token",
			token:       "s.AbCdEfGhIjKlMnOpQrStUvWx",
			expectValid: true,
		},
		{
			name:        "valid_uuid_token",
			token:       "12345678-1234-1234-1234-123456789012",
			expectValid: true,
		},
		{
			name:        "token_with_whitespace",
			token:       "  hvs.AAAAAQKLwI_VgPyvmn_dV7wR8xOz  \n",
			expectValid: true,
		},
		{
			name:        "empty_token",
			token:       "",
			expectValid: false,
		},
		{
			name:        "too_short",
			token:       "short",
			expectValid: false,
		},
		{
			name:        "invalid_characters",
			token:       "hvs.token$with$invalid&chars",
			expectValid: false,
		},
		{
			name:        "just_whitespace",
			token:       "   \n\t   ",
			expectValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isValid := isValidVaultTokenFormat(tt.token)
			testutil.AssertEqual(t, tt.expectValid, isValid)
		})
	}
}

func TestSecureTokenFileIntegration(t *testing.T) {
	rc := testutil.TestRuntimeContext(t)
	tempDir := t.TempDir()

	t.Run("integration_with_readTokenFile", func(t *testing.T) {
		tokenFile := filepath.Join(tempDir, "integration_token")
		testToken := "hvs.IntegrationTestToken123"

		// Write token using secure function
		err := SecureWriteTokenFile(rc, tokenFile, testToken)
		testutil.AssertNoError(t, err)

		// Read using the auth.go readTokenFile function
		readFn := readTokenFile(rc, tokenFile)

		// Client parameter is not used in readTokenFile
		token, err := readFn(nil)
		testutil.AssertNoError(t, err)
		testutil.AssertEqual(t, testToken, token)
	})
}
