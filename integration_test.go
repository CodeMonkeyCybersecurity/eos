//go:build integration
// +build integration

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/privilege_check"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/secrets"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/security_permissions"
)

// TestSecretGenerationAndPermissionSetting tests the workflow of:
// 1. Generating a secret
// 2. Writing it to a file
// 3. Setting appropriate permissions
func TestSecretGenerationAndPermissionSetting(t *testing.T) {
	tempDir := t.TempDir()
	secretFile := filepath.Join(tempDir, "secret.key")

	// Step 1: Generate a secret
	secret, err := secrets.GenerateHex(32)
	if err != nil {
		t.Fatalf("Failed to generate secret: %v", err)
	}

	if len(secret) != 64 { // 32 bytes = 64 hex chars
		t.Errorf("Secret length = %d, want 64", len(secret))
	}

	// Step 2: Write secret to file
	err = os.WriteFile(secretFile, []byte(secret), 0644)
	if err != nil {
		t.Fatalf("Failed to write secret file: %v", err)
	}

	// Step 3: Check and fix permissions
	pm := security_permissions.NewPermissionManager(&security_permissions.SecurityConfig{
		DryRun:        false,
		CreateBackups: false,
	})

	check := pm.CheckSinglePath(secretFile, 0600, "secret key", true)
	if !check.NeedsChange {
		t.Error("Expected permission change needed for secret file")
	}

	// Fix permissions
	fixCheck := pm.FixSinglePath(secretFile, 0600, "secret key", true)
	if fixCheck.Error != "" {
		t.Errorf("Failed to fix permissions: %s", fixCheck.Error)
	}

	// Verify permissions are correct
	stat, err := os.Stat(secretFile)
	if err != nil {
		t.Fatalf("Failed to stat file: %v", err)
	}

	mode := stat.Mode() & os.ModePerm
	if mode != 0600 {
		t.Errorf("Permissions = %o, want %o", mode, 0600)
	}
}

// TestPrivilegeCheckWorkflow tests privilege checking workflow
func TestPrivilegeCheckWorkflow(t *testing.T) {
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	// Step 1: Check current privileges
	privMgr := privilege_check.NewPrivilegeManager(&privilege_check.PrivilegeConfig{
		RequireRoot:     false,
		AllowSudo:       true,
		ExitOnFailure:   false,
		ShowColorOutput: false,
	})

	check, err := privMgr.CheckPrivileges(rc)
	if err != nil {
		t.Fatalf("Failed to check privileges: %v", err)
	}

	// Step 2: Generate appropriate secret based on privilege level
	var secretLength int
	switch check.Level {
	case privilege_check.PrivilegeLevelRoot:
		secretLength = 64 // Longer for root
	case privilege_check.PrivilegeLevelSudo:
		secretLength = 48
	default:
		secretLength = 32
	}

	secret, err := secrets.GenerateBase64(secretLength)
	if err != nil {
		t.Fatalf("Failed to generate secret: %v", err)
	}

	// Verify secret was generated
	if secret == "" {
		t.Error("Empty secret generated")
	}

	// Step 3: Use privilege info to determine file location
	var secretDir string
	if check.IsRoot {
		secretDir = "/tmp/root_secrets"
	} else {
		secretDir = filepath.Join("/tmp", check.Username+"_secrets")
	}

	// Create directory with appropriate permissions
	if err := os.MkdirAll(secretDir, 0700); err != nil {
		// May fail if not enough permissions
		t.Logf("Could not create directory %s: %v", secretDir, err)
	}
}

// TestSecurityWorkflowWithTimeout tests timeout handling across packages
func TestSecurityWorkflowWithTimeout(t *testing.T) {
	// Create context with short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	rc := &eos_io.RuntimeContext{
		Ctx: ctx,
	}

	// Step 1: Quick privilege check
	privMgr := privilege_check.NewPrivilegeManager(nil)
	check, err := privMgr.CheckPrivileges(rc)
	if err != nil {
		// Might fail with timeout
		t.Logf("Privilege check with timeout: %v", err)
		return
	}

	// Step 2: Generate secret (should be quick)
	secret, err := secrets.GenerateHex(16)
	if err != nil {
		t.Fatalf("Secret generation failed: %v", err)
	}

	// Step 3: Permission check on multiple files (might timeout)
	tempDir := t.TempDir()
	permMgr := security_permissions.NewPermissionManager(nil)

	// Create several test files
	for i := 0; i < 5; i++ {
		select {
		case <-ctx.Done():
			t.Log("Context cancelled during file creation")
			return
		default:
			filename := filepath.Join(tempDir, string(rune('a'+i))+".txt")
			os.WriteFile(filename, []byte(secret), 0644)
		}
	}

	// Check SSH directory permissions (might timeout)
	result, err := permMgr.ScanSSHDirectory(tempDir)
	if err != nil {
		t.Logf("SSH scan with timeout: %v", err)
	} else if result != nil {
		t.Logf("Scanned %d files before timeout", result.TotalChecks)
	}
}

// TestConcurrentSecurityOperations tests concurrent operations across packages
func TestConcurrentSecurityOperations(t *testing.T) {
	done := make(chan bool, 3)
	errors := make(chan error, 3)

	// Concurrent secret generation
	go func() {
		defer func() { done <- true }()
		for i := 0; i < 10; i++ {
			_, err := secrets.GenerateHex(32)
			if err != nil {
				errors <- err
				return
			}
		}
	}()

	// Concurrent privilege checking
	go func() {
		defer func() { done <- true }()
		rc := &eos_io.RuntimeContext{
			Ctx: context.Background(),
		}
		pm := privilege_check.NewPrivilegeManager(nil)
		for i := 0; i < 10; i++ {
			_, err := pm.CheckPrivileges(rc)
			if err != nil {
				errors <- err
				return
			}
		}
	}()

	// Concurrent permission checking
	go func() {
		defer func() { done <- true }()
		tempDir := t.TempDir()
		testFile := filepath.Join(tempDir, "test.txt")
		os.WriteFile(testFile, []byte("test"), 0644)

		pm := security_permissions.NewPermissionManager(nil)
		for i := 0; i < 10; i++ {
			_ = pm.CheckSinglePath(testFile, 0600, "test", false)
		}
	}()

	// Wait for completion
	for i := 0; i < 3; i++ {
		select {
		case <-done:
			// Good
		case err := <-errors:
			t.Errorf("Concurrent operation failed: %v", err)
		case <-time.After(5 * time.Second):
			t.Fatal("Timeout waiting for concurrent operations")
		}
	}
}

// TestErrorPropagation tests error handling across package boundaries
func TestErrorPropagation(t *testing.T) {
	// Test with invalid inputs that should propagate errors

	// 1. Invalid secret generation
	_, err := secrets.GenerateHex(-1)
	if err == nil {
		t.Error("Expected error for negative length")
	}

	// 2. Permission check on non-existent path
	pm := security_permissions.NewPermissionManager(nil)
	check := pm.CheckSinglePath("/non/existent/path", 0600, "test", true)
	if check.Error == "" {
		t.Error("Expected error for non-existent path")
	}

	// 3. Privilege check with cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	rc := &eos_io.RuntimeContext{
		Ctx: ctx,
	}

	privMgr := privilege_check.NewPrivilegeManager(nil)
	// Should still work for basic operations even with cancelled context
	_, err = privMgr.CheckPrivileges(rc)
	// Basic user info might still work despite cancelled context
	if err != nil {
		t.Logf("Privilege check with cancelled context: %v", err)
	}
}
