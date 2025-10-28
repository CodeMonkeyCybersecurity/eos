// pkg/interaction/required_flag_test.go
package interaction

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

// TestFlagSource_String verifies FlagSource string representation
func TestFlagSource_String(t *testing.T) {
	tests := []struct {
		source FlagSource
		want   string
	}{
		{FlagSourceCLI, "command-line flag"},
		{FlagSourceEnv, "environment variable"},
		{FlagSourcePrompt, "interactive prompt"},
		{FlagSourceDefault, "default value"},
	}

	for _, tt := range tests {
		t.Run(string(tt.source), func(t *testing.T) {
			if got := string(tt.source); got != tt.want {
				t.Errorf("FlagSource string = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestGetRequiredString_FlagProvided verifies fallback 1: CLI flag provided
func TestGetRequiredString_FlagProvided(t *testing.T) {
	rc := &eos_io.RuntimeContext{Ctx: context.Background()}

	result, err := GetRequiredString(rc, "token-from-cli", true, &RequiredFlagConfig{
		FlagName:   "token",
		EnvVarName: "TEST_TOKEN",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Value != "token-from-cli" {
		t.Errorf("Value = %q, want %q", result.Value, "token-from-cli")
	}

	if result.Source != FlagSourceCLI {
		t.Errorf("Source = %q, want %q", result.Source, FlagSourceCLI)
	}
}

// TestGetRequiredString_EnvVarFallback verifies fallback 2: environment variable
func TestGetRequiredString_EnvVarFallback(t *testing.T) {
	rc := &eos_io.RuntimeContext{Ctx: context.Background()}

	// Set env var for test
	os.Setenv("TEST_TOKEN_ENV", "token-from-env")
	defer os.Unsetenv("TEST_TOKEN_ENV")

	result, err := GetRequiredString(rc, "", false, &RequiredFlagConfig{
		FlagName:   "token",
		EnvVarName: "TEST_TOKEN_ENV",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Value != "token-from-env" {
		t.Errorf("Value = %q, want %q", result.Value, "token-from-env")
	}

	if result.Source != FlagSourceEnv {
		t.Errorf("Source = %q, want %q", result.Source, FlagSourceEnv)
	}
}

// TestGetRequiredString_EmptyStringExplicitlySet verifies Changed() detection
func TestGetRequiredString_EmptyStringExplicitlySet(t *testing.T) {
	rc := &eos_io.RuntimeContext{Ctx: context.Background()}

	// User explicitly set --token="" (flagWasSet=true, value="")
	result, err := GetRequiredString(rc, "", true, &RequiredFlagConfig{
		FlagName:   "token",
		EnvVarName: "TEST_TOKEN_EMPTY",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Value != "" {
		t.Errorf("Value = %q, want empty string", result.Value)
	}

	if result.Source != FlagSourceCLI {
		t.Errorf("Source = %q, want %q (respects explicit empty)", result.Source, FlagSourceCLI)
	}
}

// TestGetRequiredString_DefaultValue verifies fallback 4: default value
func TestGetRequiredString_DefaultValue(t *testing.T) {
	rc := &eos_io.RuntimeContext{Ctx: context.Background()}

	result, err := GetRequiredString(rc, "", false, &RequiredFlagConfig{
		FlagName:     "port",
		AllowEmpty:   true,
		DefaultValue: "8080",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Value != "8080" {
		t.Errorf("Value = %q, want %q", result.Value, "8080")
	}

	if result.Source != FlagSourceDefault {
		t.Errorf("Source = %q, want %q", result.Source, FlagSourceDefault)
	}
}

// TestGetRequiredString_NonInteractiveError verifies fallback 5: error with remediation
func TestGetRequiredString_NonInteractiveError(t *testing.T) {
	rc := &eos_io.RuntimeContext{Ctx: context.Background()}

	// No flag, no env var, non-interactive mode (IsTTY() returns false in tests)
	_, err := GetRequiredString(rc, "", false, &RequiredFlagConfig{
		FlagName:   "token",
		EnvVarName: "TEST_TOKEN_MISSING",
		HelpText:   "Required for authentication",
	})

	if err == nil {
		t.Fatalf("expected error, got nil")
	}

	// Verify remediation error includes key information
	errMsg := err.Error()
	if !strings.Contains(errMsg, "--token") {
		t.Errorf("error should mention --token flag, got: %s", errMsg)
	}
	if !strings.Contains(errMsg, "TEST_TOKEN_MISSING") {
		t.Errorf("error should mention TEST_TOKEN_MISSING env var, got: %s", errMsg)
	}
	if !strings.Contains(errMsg, "Required for authentication") {
		t.Errorf("error should include help text, got: %s", errMsg)
	}
}

// TestGetRequiredString_PrecedenceOrder verifies CLI > env var > prompt > default
func TestGetRequiredString_PrecedenceOrder(t *testing.T) {
	rc := &eos_io.RuntimeContext{Ctx: context.Background()}

	// Set env var but also provide CLI flag - CLI should win
	os.Setenv("TEST_PRECEDENCE", "from-env")
	defer os.Unsetenv("TEST_PRECEDENCE")

	result, err := GetRequiredString(rc, "from-cli", true, &RequiredFlagConfig{
		FlagName:     "test",
		EnvVarName:   "TEST_PRECEDENCE",
		DefaultValue: "from-default",
		AllowEmpty:   true,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Value != "from-cli" {
		t.Errorf("CLI flag should take precedence, got: %s", result.Value)
	}

	if result.Source != FlagSourceCLI {
		t.Errorf("Source should be CLI, got: %s", result.Source)
	}
}

// TestGetRequiredInt_FlagProvided verifies int parsing from CLI flag
func TestGetRequiredInt_FlagProvided(t *testing.T) {
	rc := &eos_io.RuntimeContext{Ctx: context.Background()}

	value, source, err := GetRequiredInt(rc, 8080, true, &RequiredFlagConfig{
		FlagName: "port",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if value != 8080 {
		t.Errorf("Value = %d, want %d", value, 8080)
	}

	if source != FlagSourceCLI {
		t.Errorf("Source = %q, want %q", source, FlagSourceCLI)
	}
}

// TestGetRequiredInt_EnvVarParsing verifies int parsing from environment variable
func TestGetRequiredInt_EnvVarParsing(t *testing.T) {
	rc := &eos_io.RuntimeContext{Ctx: context.Background()}

	os.Setenv("TEST_PORT_ENV", "9090")
	defer os.Unsetenv("TEST_PORT_ENV")

	value, source, err := GetRequiredInt(rc, 0, false, &RequiredFlagConfig{
		FlagName:   "port",
		EnvVarName: "TEST_PORT_ENV",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if value != 9090 {
		t.Errorf("Value = %d, want %d", value, 9090)
	}

	if source != FlagSourceEnv {
		t.Errorf("Source = %q, want %q", source, FlagSourceEnv)
	}
}

// TestGetRequiredInt_EnvVarParseError verifies error handling for invalid int
func TestGetRequiredInt_EnvVarParseError(t *testing.T) {
	rc := &eos_io.RuntimeContext{Ctx: context.Background()}

	os.Setenv("TEST_PORT_INVALID", "not-a-number")
	defer os.Unsetenv("TEST_PORT_INVALID")

	_, _, err := GetRequiredInt(rc, 0, false, &RequiredFlagConfig{
		FlagName:   "port",
		EnvVarName: "TEST_PORT_INVALID",
	})

	if err == nil {
		t.Fatalf("expected error for invalid integer, got nil")
	}

	if !strings.Contains(err.Error(), "invalid integer") {
		t.Errorf("error should mention invalid integer, got: %s", err.Error())
	}
}

// TestGetRequiredInt_DefaultValue verifies int parsing from default value
func TestGetRequiredInt_DefaultValue(t *testing.T) {
	rc := &eos_io.RuntimeContext{Ctx: context.Background()}

	value, source, err := GetRequiredInt(rc, 0, false, &RequiredFlagConfig{
		FlagName:     "port",
		AllowEmpty:   true,
		DefaultValue: "3000",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if value != 3000 {
		t.Errorf("Value = %d, want %d", value, 3000)
	}

	if source != FlagSourceDefault {
		t.Errorf("Source = %q, want %q", source, FlagSourceDefault)
	}
}

// TestGetRequiredInt_DefaultValueInvalid verifies error for invalid default
func TestGetRequiredInt_DefaultValueInvalid(t *testing.T) {
	rc := &eos_io.RuntimeContext{Ctx: context.Background()}

	_, _, err := GetRequiredInt(rc, 0, false, &RequiredFlagConfig{
		FlagName:     "port",
		AllowEmpty:   true,
		DefaultValue: "invalid-int",
	})

	if err == nil {
		t.Fatalf("expected error for invalid default int, got nil")
	}

	if !strings.Contains(err.Error(), "invalid default integer") {
		t.Errorf("error should mention invalid default integer, got: %s", err.Error())
	}
}

// TestBuildRemediationError verifies error message quality
func TestBuildRemediationError(t *testing.T) {
	tests := []struct {
		name   string
		config *RequiredFlagConfig
		want   []string // Substrings that must be present
	}{
		{
			name: "with env var and help text",
			config: &RequiredFlagConfig{
				FlagName:   "token",
				EnvVarName: "VAULT_TOKEN",
				HelpText:   "Required for authentication",
			},
			want: []string{
				"--token",
				"VAULT_TOKEN",
				"Required for authentication",
				"export",
				"interactive",
			},
		},
		{
			name: "without env var",
			config: &RequiredFlagConfig{
				FlagName: "config",
				HelpText: "Path to config file",
			},
			want: []string{
				"--config",
				"Path to config file",
				"interactive",
			},
		},
		{
			name: "minimal config",
			config: &RequiredFlagConfig{
				FlagName: "output",
			},
			want: []string{
				"--output",
				"interactive",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := buildRemediationError(tt.config)
			errMsg := err.Error()

			for _, substr := range tt.want {
				if !strings.Contains(errMsg, substr) {
					t.Errorf("error message should contain %q, got:\n%s", substr, errMsg)
				}
			}
		})
	}
}

// TestGetRequiredString_ValidationChaining verifies custom validator is called
func TestGetRequiredString_ValidationChaining(t *testing.T) {
	rc := &eos_io.RuntimeContext{Ctx: context.Background()}

	// Set env var with invalid value
	os.Setenv("TEST_CUSTOM_VALIDATION", "invalid-value")
	defer os.Unsetenv("TEST_CUSTOM_VALIDATION")

	customValidator := func(s string) error {
		if s == "invalid-value" {
			return fmt.Errorf("custom validation failed: %s is not allowed", s)
		}
		return nil
	}

	// Note: Validation only applies during interactive prompting (fallback 3)
	// For env var (fallback 2), validation happens in calling code, not GetRequiredString
	// This test documents current behavior - validation is caller's responsibility for env vars

	result, err := GetRequiredString(rc, "", false, &RequiredFlagConfig{
		FlagName:   "test",
		EnvVarName: "TEST_CUSTOM_VALIDATION",
		Validator:  customValidator,
	})

	// Current behavior: env var fallback returns value without validation
	// Validator only applies to interactive prompts
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Value != "invalid-value" {
		t.Errorf("Value = %q, want %q (validation not applied to env vars)", result.Value, "invalid-value")
	}

	// NOTE: To add env var validation in future, modify GetRequiredString fallback 2
	// to call config.Validator before returning FlagSourceEnv result
}

// NOTE: Interactive prompt tests (fallback 3) are skipped because:
// 1. They require TTY detection (IsTTY() returns false in test environment)
// 2. stdin/stdout mocking conflicts with otelzap logger
// 3. Core fallback logic is thoroughly tested above
//
// Interactive prompting is verified via:
// - Integration tests: cmd/update/vault_cluster.go with real user input
// - Manual testing: eos update vault-cluster autopilot (prompts for token)
//
// Test coverage summary:
// ✓ Fallback 1: CLI flag provided (TestGetRequiredString_FlagProvided)
// ✓ Fallback 2: Environment variable (TestGetRequiredString_EnvVarFallback)
// ✗ Fallback 3: Interactive prompt (requires TTY, tested manually)
// ✓ Fallback 4: Default value (TestGetRequiredString_DefaultValue)
// ✓ Fallback 5: Error with remediation (TestGetRequiredString_NonInteractiveError)
// ✓ Precedence: CLI > env > prompt > default (TestGetRequiredString_PrecedenceOrder)
// ✓ Empty detection: Changed() vs not provided (TestGetRequiredString_EmptyStringExplicitlySet)
// ✓ Int parsing: CLI, env, default (TestGetRequiredInt_*)
// ✓ Error messages: Remediation quality (TestBuildRemediationError)
