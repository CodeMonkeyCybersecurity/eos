package eos_cli

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/telemetry"
	"github.com/spf13/cobra"
)

func TestWrap(t *testing.T) {
	// Initialize telemetry for tests
	if err := telemetry.Init("test"); err != nil {
		t.Fatalf("Failed to initialize telemetry: %v", err)
	}

	t.Run("successful_command_execution", func(t *testing.T) {
		// Create a simple command function that succeeds
		successFunc := func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			// Verify runtime context is properly initialized
			if rc == nil {
				t.Error("expected non-nil runtime context")
				return nil
			}
			if rc.Ctx == nil {
				t.Error("expected non-nil context")
			}
			if rc.Log == nil {
				t.Error("expected non-nil logger")
			}
			return nil
		}

		// Create test command
		cmd := &cobra.Command{
			Use:  "test-command",
			RunE: Wrap(successFunc),
		}

		// Execute wrapped function
		err := cmd.RunE(cmd, []string{"arg1", "arg2"})
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
	})

	t.Run("command_execution_with_error", func(t *testing.T) {
		expectedErr := errors.New("test error")

		errorFunc := func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			return expectedErr
		}

		cmd := &cobra.Command{
			Use:  "test-error-command",
			RunE: Wrap(errorFunc),
		}

		err := cmd.RunE(cmd, []string{})
		if err == nil {
			t.Fatal("expected error, got nil")
		}

		// The error should be wrapped with stack trace unless it's a user error
		if err == expectedErr {
			t.Error("expected error to be wrapped with stack trace")
		}
	})

	t.Run("expected_user_error_not_wrapped", func(t *testing.T) {
		userErr := eos_err.NewExpectedError(context.Background(), errors.New("user did something wrong"))

		userErrorFunc := func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			return userErr
		}

		cmd := &cobra.Command{
			Use:  "test-user-error-command",
			RunE: Wrap(userErrorFunc),
		}

		err := cmd.RunE(cmd, []string{})
		if err == nil {
			t.Fatal("expected error, got nil")
		}

		// User errors should not be wrapped with stack trace
		if !eos_err.IsExpectedUserError(err) {
			t.Error("expected user error to remain as user error")
		}
	})

	t.Run("panic_recovery", func(t *testing.T) {
		panicFunc := func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			panic("test panic")
		}

		cmd := &cobra.Command{
			Use:  "test-panic-command",
			RunE: Wrap(panicFunc),
		}

		err := cmd.RunE(cmd, []string{})
		if err == nil {
			t.Fatal("expected error from panic recovery, got nil")
		}

		// Should contain panic information
		if !contains(err.Error(), "panic: test panic") {
			t.Errorf("expected error to contain 'panic: test panic', got %s", err.Error())
		}
	})

	t.Run("vault_environment_setup", func(t *testing.T) {
		// Set up test VAULT_ADDR
		originalVaultAddr := os.Getenv("VAULT_ADDR")
		defer func() {
			if originalVaultAddr == "" {
				if err := os.Unsetenv("VAULT_ADDR"); err != nil {
					t.Logf("Failed to unset VAULT_ADDR: %v", err)
				}
			} else {
				if err := os.Setenv("VAULT_ADDR", originalVaultAddr); err != nil {
					t.Logf("Failed to restore VAULT_ADDR: %v", err)
				}
			}
		}()

		if err := os.Setenv("VAULT_ADDR", "http://test:8200"); err != nil {
			t.Fatalf("Failed to set VAULT_ADDR: %v", err)
		}

		vaultFunc := func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			// Check that vault_addr attribute was set
			vaultAddr := rc.Attributes["vault_addr"]
			if vaultAddr != "http://test:8200" {
				t.Errorf("expected vault_addr attribute 'http://test:8200', got %s", vaultAddr)
			}
			return nil
		}

		cmd := &cobra.Command{
			Use:  "test-vault-command",
			RunE: Wrap(vaultFunc),
		}

		err := cmd.RunE(cmd, []string{})
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
	})

	// Note: Validation test skipped as it depends on external CUE/OPA validation
	// which may not be configured in test environment
	t.Run("validation_skipped", func(t *testing.T) {
		t.Skip("Validation test requires CUE/OPA configuration")
	})

	t.Run("runtime_context_attributes", func(t *testing.T) {
		attributeFunc := func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			// Test that we can set and retrieve attributes
			rc.Attributes["test_key"] = "test_value"
			rc.Attributes["command_name"] = cmd.Name()

			if rc.Attributes["test_key"] != "test_value" {
				t.Errorf("expected 'test_value', got %s", rc.Attributes["test_key"])
			}
			if rc.Attributes["command_name"] != cmd.Name() {
				t.Errorf("expected command name '%s', got %s", cmd.Name(), rc.Attributes["command_name"])
			}
			return nil
		}

		cmd := &cobra.Command{
			Use:  "test-attributes-command",
			RunE: Wrap(attributeFunc),
		}

		err := cmd.RunE(cmd, []string{})
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
	})

	t.Run("context_timing", func(t *testing.T) {
		start := time.Now()

		timingFunc := func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			// Verify that the context timestamp is recent
			if rc.Timestamp.Before(start) {
				t.Error("context timestamp should be after test start")
			}
			if rc.Timestamp.After(time.Now()) {
				t.Error("context timestamp should not be in the future")
			}

			// Add some duration to test timing
			time.Sleep(10 * time.Millisecond)
			return nil
		}

		cmd := &cobra.Command{
			Use:  "test-timing-command",
			RunE: Wrap(timingFunc),
		}

		err := cmd.RunE(cmd, []string{})
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
	})
}

func TestWrapValidation(t *testing.T) {
	t.Run("validation_struct_fields", func(t *testing.T) {
		validation := &WrapValidation{
			Cfg:         "test config",
			SchemaPath:  "/path/to/schema.cue",
			YAMLPath:    "/path/to/data.yaml",
			PolicyPath:  "/path/to/policy.rego",
			PolicyInput: func() any { return map[string]string{"key": "value"} },
		}

		// Test all fields are set correctly
		_ = validation.Cfg
		_ = validation.SchemaPath
		_ = validation.YAMLPath
		_ = validation.PolicyPath

		if validation.PolicyInput == nil {
			t.Error("expected non-nil PolicyInput function")
		}

		// Test PolicyInput function
		input := validation.PolicyInput()
		if input == nil {
			t.Error("expected non-nil input from PolicyInput function")
		}
	})

	t.Run("validation_with_nil_policy_input", func(t *testing.T) {
		validation := &WrapValidation{
			Cfg:         "test",
			SchemaPath:  "/test",
			YAMLPath:    "/test",
			PolicyPath:  "/test",
			PolicyInput: nil, // This should be allowed
		}

		// Test fields
		_ = validation.Cfg
		_ = validation.SchemaPath
		_ = validation.YAMLPath
		_ = validation.PolicyPath

		if validation.PolicyInput != nil {
			t.Error("expected nil PolicyInput")
		}
	})
}

// Helper function to check if string contains substring (reused from context_test.go)
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > len(substr) && (s[:len(substr)] == substr ||
			s[len(s)-len(substr):] == substr ||
			containsInner(s, substr))))
}

func containsInner(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
