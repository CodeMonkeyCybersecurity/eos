package vault

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/testutil"
)

// TestCredentialFilePermissions tests that credential files have secure permissions
func TestCredentialFilePermissions(t *testing.T) {
	rc := testutil.TestRuntimeContext(t)

	t.Run("role_id_file_permissions", func(t *testing.T) {
		tempDir := testutil.TempDir(t)
		roleIDPath := filepath.Join(tempDir, "role_id")

		// Create a role ID file
		roleID := "test-role-id-12345"
		err := os.WriteFile(roleIDPath, []byte(roleID), 0644) // Intentionally insecure
		testutil.AssertNoError(t, err)

		// Test that the security validation catches insecure permissions
		err = ValidateFilePermissions(rc, roleIDPath, shared.OwnerReadOnly)
		testutil.AssertError(t, err)
		testutil.AssertContains(t, err.Error(), "permission")

		// Fix permissions and test again
		err = os.Chmod(roleIDPath, shared.OwnerReadOnly)
		testutil.AssertNoError(t, err)

		err = ValidateFilePermissions(rc, roleIDPath, shared.OwnerReadOnly)
		testutil.AssertNoError(t, err)
	})

	t.Run("secret_id_file_permissions", func(t *testing.T) {
		tempDir := testutil.TempDir(t)
		secretIDPath := filepath.Join(tempDir, "secret_id")

		// Create a secret ID file
		secretID := "test-secret-id-67890"
		err := os.WriteFile(secretIDPath, []byte(secretID), 0644) // Intentionally insecure
		testutil.AssertNoError(t, err)

		// Test that the security validation catches insecure permissions
		err = ValidateFilePermissions(rc, secretIDPath, shared.OwnerReadOnly)
		testutil.AssertError(t, err)

		// Fix permissions and test again
		err = os.Chmod(secretIDPath, shared.OwnerReadOnly)
		testutil.AssertNoError(t, err)

		err = ValidateFilePermissions(rc, secretIDPath, shared.OwnerReadOnly)
		testutil.AssertNoError(t, err)
	})

	t.Run("world_readable_detection", func(t *testing.T) {
		tempDir := testutil.TempDir(t)
		credentialPath := filepath.Join(tempDir, "credential")

		// Test various insecure permission combinations
		insecurePerms := []os.FileMode{
			0644, // World readable
			0664, // Group and world readable
			0666, // World readable and writable
			0755, // World readable and executable
		}

		credential := "sensitive-credential-data"
		for _, perm := range insecurePerms {
			err := os.WriteFile(credentialPath, []byte(credential), perm)
			testutil.AssertNoError(t, err)

			err = ValidateFilePermissions(rc, credentialPath, shared.OwnerReadOnly)
			testutil.AssertError(t, err)
			testutil.AssertContains(t, err.Error(), "permission")
		}
	})

	t.Run("group_writable_detection", func(t *testing.T) {
		tempDir := testutil.TempDir(t)
		credentialPath := filepath.Join(tempDir, "credential")

		// Test group writable permissions (also insecure for credentials)
		groupWritablePerms := []os.FileMode{
			0620, // Group writable
			0660, // Group readable and writable
			0670, // Group readable, writable, executable
		}

		credential := "sensitive-credential-data"
		for _, perm := range groupWritablePerms {
			err := os.WriteFile(credentialPath, []byte(credential), perm)
			testutil.AssertNoError(t, err)

			err = ValidateFilePermissions(rc, credentialPath, shared.OwnerReadOnly)
			testutil.AssertError(t, err)
		}
	})
}

// TestCredentialContentValidation tests validation of credential file contents
func TestCredentialContentValidation(t *testing.T) {
	t.Run("role_id_format_validation", func(t *testing.T) {
		validRoleIDs := []string{
			"01234567-89ab-cdef-0123-456789abcdef",
			"abcdef01-2345-6789-abcd-ef0123456789",
		}

		invalidRoleIDs := []string{
			"", // Empty
			"not-a-uuid",
			"01234567-89ab-cdef-0123-456789abcdef-extra",
			"01234567-89ab-cdef-0123-456789abcdeg", // Invalid hex character
			"01234567_89ab_cdef_0123_456789abcdef", // Wrong separator
			"role_id_injection; rm -rf /",          // Injection attempt
			"../../../etc/passwd",                  // Path traversal
		}

		for _, roleID := range validRoleIDs {
			err := ValidateRoleIDFormat(roleID)
			testutil.AssertNoError(t, err)
		}

		for _, roleID := range invalidRoleIDs {
			err := ValidateRoleIDFormat(roleID)
			testutil.AssertError(t, err)
		}
	})

	t.Run("secret_id_format_validation", func(t *testing.T) {
		validSecretIDs := []string{
			"fedcba98-7654-3210-fedc-ba9876543210",
			"12345678-90ab-cdef-1234-567890abcdef",
		}

		invalidSecretIDs := []string{
			"", // Empty
			"not-a-uuid",
			"fedcba98-7654-3210-fedc-ba9876543210-extra",
			"fedcba98-7654-3210-fedc-ba9876543210x", // Invalid hex character
			"secret_injection; curl evil.com",       // Injection attempt
			"$(whoami)",                             // Command substitution
			"\x00secret",                            // Null bytes
		}

		for _, secretID := range validSecretIDs {
			err := ValidateSecretIDFormat(secretID)
			testutil.AssertNoError(t, err)
		}

		for _, secretID := range invalidSecretIDs {
			err := ValidateSecretIDFormat(secretID)
			testutil.AssertError(t, err)
		}
	})

	t.Run("vault_token_format_validation", func(t *testing.T) {
		validTokens := []string{
			"hvs.AAAAAQKLwI_VgPyvmn_dV7wR8xOz",
			"hvb.AAAAAQKLwI_VgPyvmn_dV7wR8xOz",
			"s.1234567890abcdef1234567890abcdef", // Legacy format
		}

		invalidTokens := []string{
			"", // Empty
			"not-a-token",
			"hvs.", // Too short
			"hvs.invalid-base64-characters!@#$",
			"token_injection; rm -rf /", // Injection attempt
			"../../etc/passwd",          // Path traversal
			"hvs.token\nrm -rf /",       // Newline injection
			"\x00hvs.token",             // Null bytes
		}

		for _, token := range validTokens {
			err := ValidateVaultTokenFormat(token)
			testutil.AssertNoError(t, err)
		}

		for _, token := range invalidTokens {
			err := ValidateVaultTokenFormat(token)
			testutil.AssertError(t, err)
		}
	})
}

// TestCredentialPathTraversalPrevention tests prevention of path traversal attacks
func TestCredentialPathTraversalPrevention(t *testing.T) {
	rc := testutil.TestRuntimeContext(t)

	t.Run("path_traversal_in_credential_paths", func(t *testing.T) {
		maliciousPaths := []string{
			"../../../etc/passwd",
			"..\\..\\..\\windows\\system32\\config\\sam",
			"/etc/shadow",
			"/var/lib/eos/secrets/../../../etc/passwd",
			"role_id/../../../etc/passwd",
			"./../../etc/passwd",
			"~root/.ssh/id_rsa",
			"/proc/self/environ",
		}

		for _, path := range maliciousPaths {
			err := ValidateCredentialPath(rc, path)
			testutil.AssertError(t, err)
			testutil.AssertContains(t, err.Error(), "path")
		}
	})

	t.Run("symlink_attack_prevention", func(t *testing.T) {
		tempDir := testutil.TempDir(t)
		credentialPath := filepath.Join(tempDir, "credential")
		symlinkPath := filepath.Join(tempDir, "symlink_credential")

		// Create a legitimate credential file
		err := os.WriteFile(credentialPath, []byte("test-credential"), shared.OwnerReadOnly)
		testutil.AssertNoError(t, err)

		// Create a symlink pointing to a sensitive file
		err = os.Symlink("/etc/passwd", symlinkPath)
		if err != nil {
			t.Skip("Cannot create symlinks on this system")
		}

		// Validation should detect and reject symlinks
		err = ValidateCredentialPath(rc, symlinkPath)
		testutil.AssertError(t, err)
		testutil.AssertContains(t, err.Error(), "symlink")
	})

	t.Run("directory_traversal_in_filenames", func(t *testing.T) {
		rc := testutil.TestRuntimeContext(t)

		maliciousFilenames := []string{
			"../role_id",
			"../../secret_id",
			"role_id/../../etc/passwd",
			".\\..\\role_id",
		}

		for _, filename := range maliciousFilenames {
			err := ValidateCredentialPath(rc, filename)
			testutil.AssertError(t, err)
		}
	})
}

// TestCredentialLeakageInLogs tests that credentials don't leak in log messages
func TestCredentialLeakageInLogs(t *testing.T) {

	t.Run("error_message_sanitization", func(t *testing.T) {
		sensitiveData := []string{
			"hvs.AAAAAQKLwI_VgPyvmn_dV7wR8xOz",
			"fedcba98-7654-3210-fedc-ba9876543210",
			"01234567-89ab-cdef-0123-456789abcdef",
			"secret-password-123",
		}

		for _, sensitive := range sensitiveData {
			// Simulate an error that might contain sensitive data
			err := CreateSanitizedError("credential validation failed", sensitive)

			// Error message should not contain the sensitive data
			errorMsg := err.Error()
			if strings.Contains(errorMsg, sensitive) {
				t.Errorf("Error message contains sensitive data: %s", errorMsg)
			}

			// Should contain a safe placeholder or redacted message
			if !strings.Contains(errorMsg, "[REDACTED]") && !strings.Contains(errorMsg, "***") {
				t.Errorf("Error message should contain redaction placeholder: %s", errorMsg)
			}
		}
	})

	t.Run("log_message_sanitization", func(t *testing.T) {
		sensitiveCredentials := []string{
			"hvs.TokenValue123",
			"role-id-12345",
			"secret-id-67890",
		}

		for _, credential := range sensitiveCredentials {
			// Test that logging functions sanitize credentials
			sanitized := SanitizeForLogging(credential)

			// Original credential should not appear in sanitized version
			if strings.Contains(sanitized, credential) {
				t.Errorf("Sanitized log message contains original credential: %s -> %s", credential, sanitized)
			}

			// Should be replaced with safe placeholder
			if sanitized == credential {
				t.Errorf("Credential was not sanitized: %s", credential)
			}
		}
	})
}

// TestCredentialRotationSecurity tests security aspects of credential rotation
func TestCredentialRotationSecurity(t *testing.T) {
	rc := testutil.TestRuntimeContext(t)

	t.Run("old_credential_cleanup", func(t *testing.T) {
		tempDir := testutil.TempDir(t)
		credentialPath := filepath.Join(tempDir, "credential")

		// Create old credential
		oldCredential := "old-credential-data"
		err := os.WriteFile(credentialPath, []byte(oldCredential), shared.OwnerReadOnly)
		testutil.AssertNoError(t, err)

		// Rotate to new credential
		newCredential := "new-credential-data"
		err = SecureCredentialRotation(rc, credentialPath, newCredential)
		testutil.AssertNoError(t, err)

		// Verify new credential is in place
		content, err := os.ReadFile(credentialPath)
		testutil.AssertNoError(t, err)
		testutil.AssertEqual(t, newCredential, string(content))

		// Verify old credential is not recoverable (this is a best-effort test)
		// In reality, the old data might still be in memory or on disk
		if strings.Contains(string(content), oldCredential) {
			t.Error("Old credential data still present after rotation")
		}
	})

	t.Run("atomic_credential_replacement", func(t *testing.T) {
		tempDir := testutil.TempDir(t)
		credentialPath := filepath.Join(tempDir, "credential")

		// Create initial credential
		initialCredential := "initial-credential"
		err := os.WriteFile(credentialPath, []byte(initialCredential), shared.OwnerReadOnly)
		testutil.AssertNoError(t, err)

		// Test atomic replacement
		newCredential := "new-atomic-credential"
		err = AtomicCredentialWrite(rc, credentialPath, newCredential)
		testutil.AssertNoError(t, err)

		// Verify the file contains only the new credential
		content, err := os.ReadFile(credentialPath)
		testutil.AssertNoError(t, err)
		testutil.AssertEqual(t, newCredential, string(content))

		// Verify permissions are correct
		stat, err := os.Stat(credentialPath)
		testutil.AssertNoError(t, err)
		testutil.AssertEqual(t, shared.OwnerReadOnly, stat.Mode().Perm())
	})

	t.Run("credential_backup_security", func(t *testing.T) {
		tempDir := testutil.TempDir(t)
		credentialPath := filepath.Join(tempDir, "credential")
		backupPath := filepath.Join(tempDir, "credential.backup")

		// Create credential file
		credential := "backup-test-credential"
		err := os.WriteFile(credentialPath, []byte(credential), shared.OwnerReadOnly)
		testutil.AssertNoError(t, err)

		// Create backup with secure permissions
		err = SecureCredentialBackup(rc, credentialPath, backupPath)
		testutil.AssertNoError(t, err)

		// Verify backup exists with correct permissions
		stat, err := os.Stat(backupPath)
		testutil.AssertNoError(t, err)
		testutil.AssertEqual(t, shared.OwnerReadOnly, stat.Mode().Perm())

		// Verify backup content
		backupContent, err := os.ReadFile(backupPath)
		testutil.AssertNoError(t, err)
		testutil.AssertEqual(t, credential, string(backupContent))
	})
}

// TestCredentialTimingAttacks tests protection against timing attacks
func TestCredentialTimingAttacks(t *testing.T) {
	t.Run("constant_time_comparison", func(t *testing.T) {
		validCredential := "hvs.AAAAAQKLwI_VgPyvmn_dV7wR8xOz"

		// Test various invalid credentials of different lengths
		invalidCredentials := []string{
			"",
			"a",
			"ab",
			"abc",
			"hvs.invalid",
			"hvs.AAAAAQKLwI_VgPyvmn_dV7wR8xO",   // One character short
			"hvs.AAAAAQKLwI_VgPyvmn_dV7wR8xOzX", // One character long
			"hvs.WRONG_TOKEN_ENTIRELY_DIFFERENT",
		}

		// Measure timing for valid credential
		validTimes := make([]time.Duration, 10)
		for i := 0; i < 10; i++ {
			start := time.Now()
			_ = ConstantTimeCredentialCompare(validCredential, validCredential)
			validTimes[i] = time.Since(start)
		}

		// Measure timing for invalid credentials
		for _, invalid := range invalidCredentials {
			invalidTimes := make([]time.Duration, 10)
			for i := 0; i < 10; i++ {
				start := time.Now()
				_ = ConstantTimeCredentialCompare(validCredential, invalid)
				invalidTimes[i] = time.Since(start)
			}

			// Calculate average times
			var validAvg, invalidAvg time.Duration
			for i := 0; i < 10; i++ {
				validAvg += validTimes[i]
				invalidAvg += invalidTimes[i]
			}
			validAvg /= 10
			invalidAvg /= 10

			// The timing difference should be minimal (within reasonable bounds)
			timingDiff := validAvg - invalidAvg
			if timingDiff < 0 {
				timingDiff = -timingDiff
			}

			// Allow for some variance due to system noise, but flag significant differences
			maxAllowedDiff := time.Microsecond * 100
			if timingDiff > maxAllowedDiff {
				t.Errorf("Timing attack possible: valid=%v, invalid=%v, diff=%v for credential length %d",
					validAvg, invalidAvg, timingDiff, len(invalid))
			}
		}
	})
}

// TestCredentialMemorySecurity tests secure handling of credentials in memory
func TestCredentialMemorySecurity(t *testing.T) {
	t.Run("credential_zeroing", func(t *testing.T) {
		sensitiveData := "hvs.AAAAAQKLwI_VgPyvmn_dV7wR8xOz"
		credentialBytes := []byte(sensitiveData)

		// Verify data is initially present
		testutil.AssertEqual(t, sensitiveData, string(credentialBytes))

		// Zero the credential memory
		SecureZeroCredential(credentialBytes)

		// Verify data is zeroed
		for i, b := range credentialBytes {
			if b != 0 {
				t.Errorf("Credential not properly zeroed at index %d: got %d, want 0", i, b)
			}
		}
	})

	t.Run("credential_lifetime_management", func(t *testing.T) {
		// Test that credentials are not kept in memory longer than necessary
		tempDir := testutil.TempDir(t)
		credentialPath := filepath.Join(tempDir, "credential")

		credential := "temporary-credential-for-testing"
		err := os.WriteFile(credentialPath, []byte(credential), shared.OwnerReadOnly)
		testutil.AssertNoError(t, err)

		// Read credential with secure handling
		credentialData, err := SecureCredentialRead(credentialPath)
		testutil.AssertNoError(t, err)

		// Verify credential was read correctly
		testutil.AssertEqual(t, credential, string(credentialData))

		// Credential should be automatically zeroed when no longer needed
		// This test validates the function exists and works
		SecureZeroCredential(credentialData)

		// Verify zeroing worked
		for i, b := range credentialData {
			if b != 0 {
				t.Errorf("Credential data not zeroed at index %d", i)
			}
		}
	})
}
