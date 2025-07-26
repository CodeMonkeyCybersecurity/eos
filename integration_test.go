//go:build integration
// +build integration

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/privilege_check"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/secrets"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/telemetry"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// TestMain sets up logging for integration tests
func TestMain(m *testing.M) {
	// Set up verbose logging for tests
	os.Setenv("LOG_LEVEL", "DEBUG")
	
	// Initialize telemetry for tests
	if err := telemetry.Init("eos-integration-test"); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize telemetry: %v\n", err)
	}

	// Create development logger configuration for verbose test output
	cfg := zap.NewDevelopmentConfig()
	cfg.Level = zap.NewAtomicLevelAt(zapcore.DebugLevel)
	cfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	
	// Add both console and file outputs for tests
	logPath := "/tmp/eos-integration-test.log"
	cfg.OutputPaths = []string{"stdout", logPath}
	cfg.ErrorOutputPaths = []string{"stderr"}
	
	// Build the logger
	baseLogger, err := cfg.Build()
	if err != nil {
		// Fallback to basic logger if config fails
		logger.InitFallback()
	} else {
		// Replace global loggers
		zap.ReplaceGlobals(baseLogger)
		otelzap.ReplaceGlobals(otelzap.New(baseLogger))
		
		baseLogger.Info("Integration test logger initialized",
			zap.String("log_level", "DEBUG"),
			zap.String("log_file", logPath),
		)
	}
	
	// Run tests
	code := m.Run()
	
	// Cleanup
	_ = zap.L().Sync()
	
	os.Exit(code)
}

// TestSecretGenerationAndPermissionSetting tests the workflow of:
// 1. Generating a secret
// 2. Writing it to a file
// 3. Setting appropriate permissions
func TestSecretGenerationAndPermissionSetting(t *testing.T) {
	// Create runtime context for logging
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
		Log: zap.L().Named("TestSecretGeneration"),
	}
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Starting secret generation and permission test")
	
	tempDir := t.TempDir()
	secretFile := filepath.Join(tempDir, "secret.key")
	
	logger.Debug("Test directory created",
		zap.String("temp_dir", tempDir),
		zap.String("secret_file", secretFile))

	// Step 1: Generate a secret
	logger.Info("Generating secret")
	secret, err := secrets.GenerateHex(32)
	if err != nil {
		logger.Error("Failed to generate secret", zap.Error(err))
		t.Fatalf("Failed to generate secret: %v", err)
	}

	logger.Debug("Secret generated successfully",
		zap.Int("secret_length", len(secret)))

	if len(secret) != 64 { // 32 bytes = 64 hex chars
		t.Errorf("Secret length = %d, want 64", len(secret))
	}

	// Step 2: Write secret to file
	logger.Info("Writing secret to file", zap.String("file", secretFile))
	err = os.WriteFile(secretFile, []byte(secret), 0644)
	if err != nil {
		logger.Error("Failed to write secret file", zap.Error(err))
		t.Fatalf("Failed to write secret file: %v", err)
	}
	logger.Debug("Secret written to file with initial permissions 0644")

	// Step 3: Check and fix permissions using os.Chmod directly
	logger.Info("Checking file permissions")
	stat, err := os.Stat(secretFile)
	if err != nil {
		logger.Error("Failed to stat file", zap.Error(err))
		t.Fatalf("Failed to stat file: %v", err)
	}
	
	currentMode := stat.Mode() & os.ModePerm
	logger.Debug("Current file permissions",
		zap.String("mode", fmt.Sprintf("%o", currentMode)))
		
	if currentMode != 0644 {
		t.Errorf("Expected initial permissions 0644, got %o", currentMode)
	}
	
	// Fix permissions
	logger.Info("Fixing file permissions to 0600")
	err = os.Chmod(secretFile, 0600)
	if err != nil {
		logger.Error("Failed to fix permissions", zap.Error(err))
		t.Errorf("Failed to fix permissions: %v", err)
	}

	// Verify permissions are correct
	stat2, err := os.Stat(secretFile)
	if err != nil {
		logger.Error("Failed to stat file after chmod", zap.Error(err))
		t.Fatalf("Failed to stat file: %v", err)
	}

	finalMode := stat2.Mode() & os.ModePerm
	logger.Debug("Final file permissions",
		zap.String("mode", fmt.Sprintf("%o", finalMode)))
		
	if finalMode != 0600 {
		t.Errorf("Permissions = %o, want %o", finalMode, 0600)
	}
	
	logger.Info("Secret generation and permission test completed successfully")
}

// TestPrivilegeCheckWorkflow tests privilege checking workflow
func TestPrivilegeCheckWorkflow(t *testing.T) {
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
		Log: zap.L().Named("TestPrivilegeCheck"),
	}
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Starting privilege check workflow test")

	// Step 1: Check current privileges
	logger.Info("Checking current user privileges")
	privMgr := privilege_check.NewPrivilegeManager(&privilege_check.PrivilegeConfig{
		RequireRoot:     false,
		AllowSudo:       true,
		ExitOnFailure:   false,
		ShowColorOutput: false,
	})

	check, err := privMgr.CheckPrivileges(rc)
	if err != nil {
		logger.Error("Failed to check privileges", zap.Error(err))
		t.Fatalf("Failed to check privileges: %v", err)
	}
	
	logger.Info("Privilege check completed",
		zap.String("level", string(check.Level)),
		zap.Bool("is_root", check.IsRoot),
		zap.Bool("has_sudo", check.HasSudo),
		zap.String("username", check.Username))

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
		Log: zap.L().Named("TestTimeout"),
	}
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Starting timeout workflow test")

	// Step 1: Quick privilege check
	privMgr := privilege_check.NewPrivilegeManager(nil)
	_, err := privMgr.CheckPrivileges(rc)
	if err != nil {
		// Might fail with timeout
		logger.Warn("Privilege check failed (might be timeout)", zap.Error(err))
		t.Logf("Privilege check with timeout: %v", err)
		return
	}
	logger.Debug("Privilege check completed before timeout")

	// Step 2: Generate secret (should be quick)
	secret, err := secrets.GenerateHex(16)
	if err != nil {
		t.Fatalf("Secret generation failed: %v", err)
	}

	// Step 3: File operations with timeout check
	tempDir := t.TempDir()
	logger.Debug("Creating test files", zap.String("dir", tempDir))

	// Create several test files
	for i := 0; i < 5; i++ {
		select {
		case <-ctx.Done():
			logger.Info("Context cancelled during file creation", zap.Int("files_created", i))
			t.Log("Context cancelled during file creation")
			return
		default:
			filename := filepath.Join(tempDir, string(rune('a'+i))+".txt")
			os.WriteFile(filename, []byte(secret), 0644)
			logger.Debug("Created test file", zap.String("file", filename))
		}
	}

	// Simulate time-consuming operation
	logger.Info("Simulating time-consuming operation")
	time.Sleep(50 * time.Millisecond)
	
	select {
	case <-ctx.Done():
		logger.Info("Context timeout occurred as expected")
		t.Log("Context timeout occurred as expected")
	default:
		t.Log("Operation completed without timeout")
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

	// Concurrent file operations
	go func() {
		defer func() { done <- true }()
		tempDir := t.TempDir()
		testFile := filepath.Join(tempDir, "test.txt")
		os.WriteFile(testFile, []byte("test"), 0644)

		for i := 0; i < 10; i++ {
			// Check file permissions
			if stat, err := os.Stat(testFile); err == nil {
				_ = stat.Mode() & os.ModePerm
			}
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
	_, err = os.Stat("/non/existent/path")
	if err == nil {
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
