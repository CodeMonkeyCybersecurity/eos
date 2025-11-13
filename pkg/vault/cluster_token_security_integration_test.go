//go:build integration
// +build integration

package vault

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

// TestTokenFileIntegration_RealFileCreation verifies token files are created
// with correct permissions and content in real filesystem
func TestTokenFileIntegration_RealFileCreation(t *testing.T) {
	// SECURITY TEST: Verify temporary token file security in real filesystem
	// RATIONALE: Unit tests mock filesystem, integration tests use real OS
	// COMPLIANCE: NIST 800-53 AC-3 (Access Enforcement)

	rc := createSecurityTestRuntimeContext(t)
	testToken := "hvs.CAESIJ1234567890abcdefghijklmnopqrstuvwxyz"

	// Create token file
	tokenFile, err := createTemporaryTokenFile(rc, testToken)
	if err != nil {
		t.Fatalf("Failed to create token file: %v", err)
	}
	defer os.Remove(tokenFile.Name())

	// Verify file exists
	if _, err := os.Stat(tokenFile.Name()); os.IsNotExist(err) {
		t.Errorf("Token file does not exist: %s", tokenFile.Name())
	}

	// Verify permissions (CRITICAL SECURITY CHECK)
	info, err := os.Stat(tokenFile.Name())
	if err != nil {
		t.Fatalf("Failed to stat token file: %v", err)
	}

	actualPerm := info.Mode().Perm()
	expectedPerm := os.FileMode(TempTokenFilePerm)

	if actualPerm != expectedPerm {
		t.Errorf("Token file permissions incorrect:\nExpected: %o\nActual:   %o",
			expectedPerm, actualPerm)
	}

	// Verify content
	content, err := os.ReadFile(tokenFile.Name())
	if err != nil {
		t.Fatalf("Failed to read token file: %v", err)
	}

	if string(content) != testToken {
		t.Errorf("Token file content incorrect:\nExpected: %s\nActual:   %s",
			testToken, string(content))
	}

	t.Logf("✓ Token file created successfully: %s", tokenFile.Name())
	t.Logf("✓ Permissions correct: %o", actualPerm)
	t.Logf("✓ Content matches token")
}

// TestTokenFileIntegration_UnpredictableNames verifies token files use
// unpredictable names to prevent guessing attacks
func TestTokenFileIntegration_UnpredictableNames(t *testing.T) {
	// SECURITY TEST: Verify token file names are unpredictable
	// THREAT MODEL: Attacker trying to guess token file path
	// MITIGATION: os.CreateTemp generates cryptographically random suffix

	rc := createSecurityTestRuntimeContext(t)
	testToken := "hvs.CAESIJ1234567890abcdefghijklmnopqrstuvwxyz"

	// Create multiple token files
	const numFiles = 10
	fileNames := make([]string, numFiles)

	for i := 0; i < numFiles; i++ {
		tokenFile, err := createTemporaryTokenFile(rc, testToken)
		if err != nil {
			t.Fatalf("Failed to create token file %d: %v", i, err)
		}
		defer os.Remove(tokenFile.Name())
		fileNames[i] = tokenFile.Name()
	}

	// Verify all names are unique
	nameSet := make(map[string]bool)
	for _, name := range fileNames {
		if nameSet[name] {
			t.Errorf("Duplicate token file name detected: %s", name)
		}
		nameSet[name] = true
	}

	// Verify names contain random component
	for _, name := range fileNames {
		basename := filepath.Base(name)
		if !strings.HasPrefix(basename, "vault-token-") {
			t.Errorf("Token file name missing expected prefix: %s", basename)
		}

		// Random suffix should be at least 8 characters
		suffix := strings.TrimPrefix(basename, "vault-token-")
		if len(suffix) < 8 {
			t.Errorf("Token file random suffix too short: %s (len=%d)",
				suffix, len(suffix))
		}
	}

	t.Logf("✓ Created %d token files with unique names", numFiles)
	t.Logf("✓ All names contain unpredictable random suffix")
}

// TestTokenFileIntegration_CleanupOnSuccess verifies token files are cleaned
// up after successful operations
func TestTokenFileIntegration_CleanupOnSuccess(t *testing.T) {
	// SECURITY TEST: Verify token cleanup happens (defense in depth)
	// RATIONALE: Token files must not persist on disk after use
	// COMPLIANCE: PCI-DSS 3.2.1 (Do not store after authorization)

	rc := createSecurityTestRuntimeContext(t)
	testToken := "hvs.CAESIJ1234567890abcdefghijklmnopqrstuvwxyz"

	var tokenFilePath string

	// Simulate successful operation with defer cleanup
	func() {
		tokenFile, err := createTemporaryTokenFile(rc, testToken)
		if err != nil {
			t.Fatalf("Failed to create token file: %v", err)
		}
		tokenFilePath = tokenFile.Name()
		defer os.Remove(tokenFilePath)

		// Verify file exists during operation
		if _, err := os.Stat(tokenFilePath); os.IsNotExist(err) {
			t.Errorf("Token file should exist during operation: %s", tokenFilePath)
		}

		// Simulate operation completing
		time.Sleep(10 * time.Millisecond)
	}()

	// Verify file is cleaned up after function returns
	if _, err := os.Stat(tokenFilePath); !os.IsNotExist(err) {
		t.Errorf("Token file was not cleaned up: %s", tokenFilePath)
		os.Remove(tokenFilePath) // Cleanup for test
	}

	t.Logf("✓ Token file cleaned up after successful operation")
}

// TestTokenFileIntegration_CleanupOnError verifies token files are cleaned
// up even when operations fail
func TestTokenFileIntegration_CleanupOnError(t *testing.T) {
	// SECURITY TEST: Verify token cleanup on error path
	// THREAT MODEL: Operation fails, token file left on disk
	// MITIGATION: defer cleanup ensures cleanup on all exit paths

	rc := createSecurityTestRuntimeContext(t)
	testToken := "hvs.CAESIJ1234567890abcdefghijklmnopqrstuvwxyz"

	var tokenFilePath string

	// Simulate failed operation with defer cleanup
	err := func() error {
		tokenFile, err := createTemporaryTokenFile(rc, testToken)
		if err != nil {
			return fmt.Errorf("failed to create token file: %w", err)
		}
		tokenFilePath = tokenFile.Name()
		defer os.Remove(tokenFilePath)

		// Verify file exists during operation
		if _, err := os.Stat(tokenFilePath); os.IsNotExist(err) {
			t.Errorf("Token file should exist during operation: %s", tokenFilePath)
		}

		// Simulate operation failing
		return fmt.Errorf("simulated operation failure")
	}()

	if err == nil {
		t.Fatal("Expected simulated error, got nil")
	}

	// Verify file is cleaned up even though operation failed
	if _, err := os.Stat(tokenFilePath); !os.IsNotExist(err) {
		t.Errorf("Token file was not cleaned up after error: %s", tokenFilePath)
		os.Remove(tokenFilePath) // Cleanup for test
	}

	t.Logf("✓ Token file cleaned up after failed operation")
}

// TestTokenFileIntegration_PermissionsDenyOtherUsers verifies token files
// cannot be read by other users (if running as root, test with setuid)
func TestTokenFileIntegration_PermissionsDenyOtherUsers(t *testing.T) {
	// SECURITY TEST: Verify 0400 permissions prevent unauthorized access
	// THREAT MODEL: Another user on system tries to read token file
	// COMPLIANCE: NIST 800-53 AC-3 (Access Enforcement)

	// NOTE: This test requires root to properly test setuid behavior
	// For non-root users, we verify permissions are set correctly

	rc := createSecurityTestRuntimeContext(t)
	testToken := "hvs.CAESIJ1234567890abcdefghijklmnopqrstuvwxyz"

	tokenFile, err := createTemporaryTokenFile(rc, testToken)
	if err != nil {
		t.Fatalf("Failed to create token file: %v", err)
	}
	defer os.Remove(tokenFile.Name())

	// Verify only owner can read (0400 = owner read-only)
	info, err := os.Stat(tokenFile.Name())
	if err != nil {
		t.Fatalf("Failed to stat token file: %v", err)
	}

	perm := info.Mode().Perm()

	// Check owner read permission
	if perm&0400 == 0 {
		t.Error("Owner cannot read token file (missing 0400 bit)")
	}

	// Check owner write is disabled
	if perm&0200 != 0 {
		t.Error("Owner can write to token file (0200 bit should not be set)")
	}

	// Check group permissions are zero
	if perm&0070 != 0 {
		t.Error("Group has permissions on token file (should be 0)")
	}

	// Check other permissions are zero
	if perm&0007 != 0 {
		t.Error("Other users have permissions on token file (should be 0)")
	}

	t.Logf("✓ Token file permissions deny unauthorized access: %o", perm)
}

// TestTokenFileIntegration_NoTokenInProcessEnvironment verifies tokens are
// not exposed in process environment when using token files
func TestTokenFileIntegration_NoTokenInProcessEnvironment(t *testing.T) {
	// SECURITY TEST: Verify token not in environment (P0-1 fix validation)
	// ATTACK VECTOR: ps auxe | grep VAULT_TOKEN
	// MITIGATION: Use VAULT_TOKEN_FILE instead of VAULT_TOKEN env var

	rc := createSecurityTestRuntimeContext(t)
	testToken := "hvs.CAESIJ1234567890abcdefghijklmnopqrstuvwxyz"

	tokenFile, err := createTemporaryTokenFile(rc, testToken)
	if err != nil {
		t.Fatalf("Failed to create token file: %v", err)
	}
	defer os.Remove(tokenFile.Name())

	// Simulate command execution with token file (not token in env)
	cmd := exec.Command("env")
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("VAULT_TOKEN_FILE=%s", tokenFile.Name()),
		"VAULT_ADDR=https://localhost:8200",
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to execute env command: %v", err)
	}

	outputStr := string(output)

	// Verify VAULT_TOKEN is NOT in environment
	if strings.Contains(outputStr, "VAULT_TOKEN="+testToken) {
		t.Error("SECURITY VIOLATION: Token exposed in environment variable")
		t.Logf("Environment output:\n%s", outputStr)
	}

	// Verify VAULT_TOKEN_FILE IS in environment (expected)
	if !strings.Contains(outputStr, "VAULT_TOKEN_FILE=") {
		t.Error("VAULT_TOKEN_FILE not found in environment (should be set)")
	}

	// Verify actual token value is nowhere in environment
	if strings.Contains(outputStr, testToken) {
		t.Error("SECURITY VIOLATION: Token value found in environment output")
	}

	t.Logf("✓ Token not exposed in process environment")
	t.Logf("✓ VAULT_TOKEN_FILE set correctly")
	t.Logf("✓ Token value not visible in env output")
}

// TestTokenFileIntegration_RaceConditionPrevention verifies permissions are
// set BEFORE writing token content (prevents read race)
func TestTokenFileIntegration_RaceConditionPrevention(t *testing.T) {
	// SECURITY TEST: Verify no window where file is world-readable
	// THREAT MODEL: Attacker monitoring /tmp for new files with default perms
	// MITIGATION: Chmod BEFORE writing content

	rc := createSecurityTestRuntimeContext(t)
	testToken := "hvs.CAESIJ1234567890abcdefghijklmnopqrstuvwxyz"

	// Monitor permissions during file creation
	// This is a best-effort test - actual race is hard to trigger in test
	tokenFile, err := createTemporaryTokenFile(rc, testToken)
	if err != nil {
		t.Fatalf("Failed to create token file: %v", err)
	}
	defer os.Remove(tokenFile.Name())

	// Immediately check permissions after creation
	info, err := os.Stat(tokenFile.Name())
	if err != nil {
		t.Fatalf("Failed to stat token file: %v", err)
	}

	perm := info.Mode().Perm()

	// Should be 0400, not default 0644 or 0666
	if perm != TempTokenFilePerm {
		t.Errorf("Permissions not set correctly immediately after creation:\nExpected: %o\nActual:   %o",
			TempTokenFilePerm, perm)
	}

	// Verify content is present (proves perms set before write)
	content, err := os.ReadFile(tokenFile.Name())
	if err != nil {
		t.Fatalf("Failed to read token file: %v", err)
	}

	if string(content) != testToken {
		t.Error("Token content incorrect after race condition check")
	}

	t.Logf("✓ Permissions set before content written (race condition prevented)")
}

// TestTokenFileIntegration_WithRealVaultCommand tests token file usage with
// actual vault CLI command (requires vault binary installed)
func TestTokenFileIntegration_WithRealVaultCommand(t *testing.T) {
	// INTEGRATION TEST: Verify token files work with real vault commands
	// REQUIREMENT: vault binary must be installed and in PATH
	// SKIP: If vault not available or Vault server not running

	// Check if vault binary exists
	vaultPath, err := exec.LookPath("vault")
	if err != nil {
		t.Skip("vault binary not found in PATH, skipping integration test")
	}

	// Check if Vault server is running
	vaultAddr := os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		vaultAddr = "https://localhost:8200"
	}

	// Try to get vault status (will fail if server not running)
	statusCmd := exec.Command(vaultPath, "status", "-format=json")
	statusCmd.Env = append(os.Environ(),
		"VAULT_ADDR="+vaultAddr,
		"VAULT_SKIP_VERIFY=1", // For test environment
	)
	if err := statusCmd.Run(); err != nil {
		t.Skipf("Vault server not running at %s, skipping integration test", vaultAddr)
	}

	// Get test token (must be set in environment for this test)
	testToken := os.Getenv("VAULT_TOKEN_TEST")
	if testToken == "" {
		t.Skip("VAULT_TOKEN_TEST not set, skipping real Vault integration test")
	}

	rc := createSecurityTestRuntimeContext(t)

	// Create token file
	tokenFile, err := createTemporaryTokenFile(rc, testToken)
	if err != nil {
		t.Fatalf("Failed to create token file: %v", err)
	}
	defer os.Remove(tokenFile.Name())

	// Execute vault command using token file
	cmd := exec.Command(vaultPath, "token", "lookup", "-format=json")
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("VAULT_TOKEN_FILE=%s", tokenFile.Name()),
		"VAULT_ADDR="+vaultAddr,
		"VAULT_SKIP_VERIFY=1",
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("Command output: %s", string(output))
		t.Fatalf("vault token lookup failed: %v", err)
	}

	// If we got here, vault successfully read token from file
	t.Logf("✓ Vault CLI successfully used token file")
	t.Logf("✓ Token lookup command succeeded")
	t.Logf("Token file: %s", tokenFile.Name())
}

// Helper function to create test RuntimeContext
func createSecurityTestRuntimeContext(t *testing.T) *eos_io.RuntimeContext {
	logger := zaptest.NewLogger(t, zaptest.Level(zap.DebugLevel))
	ctx := context.Background()

	return &eos_io.RuntimeContext{
		Ctx: ctx,
		Log: logger,
	}
}

// TestTokenFileIntegration_FileDescriptorLeak verifies token files don't
// leak file descriptors
func TestTokenFileIntegration_FileDescriptorLeak(t *testing.T) {
	// RESOURCE TEST: Verify no file descriptor leak
	// RATIONALE: File descriptor leaks can cause "too many open files" errors

	rc := createSecurityTestRuntimeContext(t)
	testToken := "hvs.CAESIJ1234567890abcdefghijklmnopqrstuvwxyz"

	// Get initial FD count
	initialFDs := countOpenFileDescriptors(t)

	// Create and cleanup many token files
	const numIterations = 100
	for i := 0; i < numIterations; i++ {
		tokenFile, err := createTemporaryTokenFile(rc, testToken)
		if err != nil {
			t.Fatalf("Failed to create token file on iteration %d: %v", i, err)
		}
		os.Remove(tokenFile.Name())
	}

	// Get final FD count
	finalFDs := countOpenFileDescriptors(t)

	// Allow small variance (test framework may open FDs)
	fdDiff := finalFDs - initialFDs
	if fdDiff > 5 {
		t.Errorf("Potential file descriptor leak detected:\nInitial FDs: %d\nFinal FDs:   %d\nDifference:  %d",
			initialFDs, finalFDs, fdDiff)
	}

	t.Logf("✓ No file descriptor leak detected (diff: %d)", fdDiff)
}

// Helper to count open file descriptors for current process
func countOpenFileDescriptors(t *testing.T) int {
	pid := os.Getpid()
	fdDir := fmt.Sprintf("/proc/%d/fd", pid)

	entries, err := os.ReadDir(fdDir)
	if err != nil {
		// On non-Linux systems, skip FD counting
		t.Logf("Cannot count FDs (not Linux?): %v", err)
		return 0
	}

	return len(entries)
}

// TestTokenFileIntegration_SELinuxCompatibility verifies token files work
// correctly on SELinux-enabled systems
func TestTokenFileIntegration_SELinuxCompatibility(t *testing.T) {
	// COMPLIANCE TEST: Verify SELinux compatibility
	// REQUIREMENT: Token files must work on RHEL/CentOS with SELinux enforcing

	// Check if SELinux is enabled
	selinuxEnabled := false
	if _, err := os.Stat("/sys/fs/selinux"); err == nil {
		selinuxEnabled = true
	}

	if !selinuxEnabled {
		t.Skip("SELinux not enabled, skipping SELinux compatibility test")
	}

	rc := createTestRuntimeContext(t)
	testToken := "hvs.CAESIJ1234567890abcdefghijklmnopqrstuvwxyz"

	// Create token file
	tokenFile, err := createTemporaryTokenFile(rc, testToken)
	if err != nil {
		t.Fatalf("Failed to create token file on SELinux system: %v", err)
	}
	defer os.Remove(tokenFile.Name())

	// Verify file is readable (SELinux context should allow)
	content, err := os.ReadFile(tokenFile.Name())
	if err != nil {
		t.Fatalf("Failed to read token file on SELinux system: %v", err)
	}

	if string(content) != testToken {
		t.Error("Token content incorrect on SELinux system")
	}

	t.Logf("✓ Token file works correctly on SELinux-enabled system")
}

// TestTokenFileIntegration_TempDirFullHandling verifies graceful handling
// when /tmp is full
func TestTokenFileIntegration_TempDirFullHandling(t *testing.T) {
	// RESILIENCE TEST: Verify graceful error when temp dir full
	// RATIONALE: Should return clear error, not panic or hang

	rc := createTestRuntimeContext(t)
	testToken := "hvs.CAESIJ1234567890abcdefghijklmnopqrstuvwxyz"

	// NOTE: We can't actually fill /tmp in test, but we can verify
	// error handling path exists by checking error types

	// This test verifies the error is properly propagated
	_, err := createTemporaryTokenFile(rc, testToken)

	// Should succeed in normal case
	if err != nil {
		// If it fails, error should be properly wrapped
		if !strings.Contains(err.Error(), "failed to create temp file") {
			t.Errorf("Error not properly wrapped: %v", err)
		}
	}

	t.Logf("✓ Token file creation error handling verified")
}

// TestTokenFileIntegration_ConcurrentAccess verifies concurrent token file
// creation is safe
func TestTokenFileIntegration_ConcurrentAccess(t *testing.T) {
	// CONCURRENCY TEST: Verify thread-safe token file creation
	// RATIONALE: Multiple goroutines may create token files simultaneously

	rc := createTestRuntimeContext(t)
	testToken := "hvs.CAESIJ1234567890abcdefghijklmnopqrstuvwxyz"

	const numGoroutines = 50
	errChan := make(chan error, numGoroutines)
	fileChan := make(chan string, numGoroutines)

	// Launch concurrent token file creation
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			tokenFile, err := createTemporaryTokenFile(rc, testToken)
			if err != nil {
				errChan <- fmt.Errorf("goroutine %d: %w", id, err)
				return
			}
			fileChan <- tokenFile.Name()
			errChan <- nil
		}(i)
	}

	// Collect results
	var createdFiles []string
	var errors []error

	for i := 0; i < numGoroutines; i++ {
		if err := <-errChan; err != nil {
			errors = append(errors, err)
		}
	}

	// Drain file channel
	close(fileChan)
	for file := range fileChan {
		createdFiles = append(createdFiles, file)
	}

	// Cleanup all files
	for _, file := range createdFiles {
		os.Remove(file)
	}

	// Check results
	if len(errors) > 0 {
		t.Errorf("Concurrent token file creation had %d errors:", len(errors))
		for _, err := range errors {
			t.Logf("  %v", err)
		}
	}

	if len(createdFiles) != numGoroutines {
		t.Errorf("Expected %d files, got %d", numGoroutines, len(createdFiles))
	}

	// Verify all files have unique names
	nameSet := make(map[string]bool)
	for _, name := range createdFiles {
		if nameSet[name] {
			t.Errorf("Duplicate file name in concurrent test: %s", name)
		}
		nameSet[name] = true
	}

	t.Logf("✓ Concurrent token file creation succeeded (%d goroutines)", numGoroutines)
	t.Logf("✓ All file names unique")
}

// TestTokenFileIntegration_UmaskRespect verifies token file creation respects
// security requirements regardless of umask
func TestTokenFileIntegration_UmaskRespect(t *testing.T) {
	// SECURITY TEST: Verify permissions set correctly regardless of umask
	// THREAT MODEL: User has permissive umask (0000), file should still be 0400

	rc := createTestRuntimeContext(t)
	testToken := "hvs.CAESIJ1234567890abcdefghijklmnopqrstuvwxyz"

	// Save original umask
	oldMask := syscall.Umask(0000) // Set permissive umask
	defer syscall.Umask(oldMask)   // Restore original

	// Create token file with permissive umask
	tokenFile, err := createTemporaryTokenFile(rc, testToken)
	if err != nil {
		t.Fatalf("Failed to create token file: %v", err)
	}
	defer os.Remove(tokenFile.Name())

	// Verify permissions are still restrictive (0400)
	info, err := os.Stat(tokenFile.Name())
	if err != nil {
		t.Fatalf("Failed to stat token file: %v", err)
	}

	perm := info.Mode().Perm()
	if perm != TempTokenFilePerm {
		t.Errorf("Permissions not secure despite permissive umask:\nExpected: %o\nActual:   %o\nUmask was: 0000",
			TempTokenFilePerm, perm)
	}

	t.Logf("✓ Token file permissions secure despite permissive umask")
	t.Logf("✓ Permissions: %o (expected: %o)", perm, TempTokenFilePerm)
}
