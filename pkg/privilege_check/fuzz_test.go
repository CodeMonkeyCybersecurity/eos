package privilege_check

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

// FuzzCheckOptions tests CheckOptions with various inputs
func FuzzCheckOptions(f *testing.F) {
	// Add seed corpus
	seeds := []struct {
		requirement   string
		customMessage string
		silentMode    bool
	}{
		{"required", "Custom error", true},
		{"preferred", "", false},
		{"not_required", "Another message", true},
		{"", "", false},
		{"invalid", "Test message", true},
		{"REQUIRED", "UPPERCASE", false},
		{"required\n", "Message\nwith\nnewlines", true},
		{strings.Repeat("x", 1000), strings.Repeat("y", 1000), false},
	}

	for _, seed := range seeds {
		f.Add(seed.requirement, seed.customMessage, seed.silentMode)
	}

	f.Fuzz(func(t *testing.T, requirement string, customMessage string, silentMode bool) {
		// Create valid options
		var req SudoRequirement
		switch strings.ToLower(strings.TrimSpace(requirement)) {
		case "required":
			req = SudoRequired
		case "preferred":
			req = SudoPreferred
		case "not_required":
			req = SudoNotRequired
		default:
			req = SudoNotRequired // Default for invalid input
		}

		options := &CheckOptions{
			Requirement:   req,
			CustomMessage: customMessage,
			SilentMode:    silentMode,
		}

		pm := NewPrivilegeManager(&PrivilegeConfig{
			RequireRoot:     false,
			AllowSudo:       true,
			ExitOnFailure:   false,
			ShowColorOutput: false,
		})

		rc := &eos_io.RuntimeContext{
			Ctx: context.Background(),
		}

		// Should not panic
		result, err := pm.RequireSudo(rc, options)

		// Basic validation
		if err == nil && result == nil {
			t.Fatal("Result should not be nil when error is nil")
		}

		if result != nil {
			// Timestamp should be set
			if result.Timestamp.IsZero() {
				t.Error("Timestamp should be set")
			}

			// Message should not be empty
			if result.Message == "" {
				t.Error("Message should not be empty")
			}

			// For SudoRequired, Required field should be true
			if req == SudoRequired && !result.Required {
				t.Error("Required field should be true for SudoRequired")
			}

			// Custom message should be used on failure if provided
			if !result.Success && customMessage != "" && req == SudoRequired {
				if result.Message != customMessage {
					t.Errorf("Custom message not used: got %q, want %q", result.Message, customMessage)
				}
			}
		}
	})
}

// FuzzPrivilegeConfig tests PrivilegeConfig with various inputs
func FuzzPrivilegeConfig(f *testing.F) {
	// Add seed corpus
	seeds := []struct {
		requireRoot     bool
		allowSudo       bool
		exitOnFailure   bool
		showColorOutput bool
	}{
		{true, true, true, true},
		{false, false, false, false},
		{true, false, true, false},
		{false, true, false, true},
	}

	for _, seed := range seeds {
		f.Add(seed.requireRoot, seed.allowSudo, seed.exitOnFailure, seed.showColorOutput)
	}

	f.Fuzz(func(t *testing.T, requireRoot bool, allowSudo bool, exitOnFailure bool, showColorOutput bool) {
		config := &PrivilegeConfig{
			RequireRoot:     requireRoot,
			AllowSudo:       allowSudo,
			ExitOnFailure:   false, // Always false to prevent test exit
			ShowColorOutput: showColorOutput,
		}

		pm := NewPrivilegeManager(config)

		// Verify config is set correctly
		if pm.config.RequireRoot != requireRoot {
			t.Errorf("RequireRoot = %v, want %v", pm.config.RequireRoot, requireRoot)
		}
		if pm.config.AllowSudo != allowSudo {
			t.Errorf("AllowSudo = %v, want %v", pm.config.AllowSudo, allowSudo)
		}

		rc := &eos_io.RuntimeContext{
			Ctx: context.Background(),
		}

		// Test various scenarios based on config
		options := &CheckOptions{
			Requirement: SudoRequired,
			SilentMode:  true,
		}

		// Should not panic
		result, err := pm.RequireSudo(rc, options)

		if err != nil {
			// Error is acceptable in some cases
			return
		}

		// If not allowing sudo and not root, should fail
		if !allowSudo && !result.Check.IsRoot && requireRoot {
			if result.Success {
				t.Error("Should fail when sudo not allowed and not root")
			}
		}
	})
}

// FuzzGetPrivilegeInfo tests privilege info formatting with context variations
func FuzzGetPrivilegeInfo(f *testing.F) {
	// Add seed corpus for timeout durations
	seeds := []int64{
		0,
		1,
		1000,
		-1,
		int64(time.Hour),
		int64(time.Millisecond),
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, timeoutNanos int64) {
		pm := NewPrivilegeManager(nil)

		// Create context with timeout if positive
		var ctx context.Context
		var cancel context.CancelFunc

		if timeoutNanos > 0 && timeoutNanos < int64(time.Hour) {
			ctx, cancel = context.WithTimeout(context.Background(), time.Duration(timeoutNanos))
			defer cancel()
		} else {
			ctx = context.Background()
		}

		rc := &eos_io.RuntimeContext{
			Ctx: ctx,
		}

		// Should not panic
		info, err := pm.GetPrivilegeInfo(rc)

		// With very short timeout, might fail
		if err != nil {
			if timeoutNanos > 0 && timeoutNanos < int64(time.Millisecond) {
				// Expected for very short timeouts
				return
			}
		}

		// If successful, verify output format
		if err == nil {
			if info == "" {
				t.Error("Info should not be empty")
			}

			// Should contain expected fields
			expectedParts := []string{"User:", "Group:", "Privilege Level:", "Is Root:", "Has Sudo:"}
			for _, part := range expectedParts {
				if !strings.Contains(info, part) {
					t.Errorf("Missing expected part: %s", part)
				}
			}

			// Should contain newlines
			lines := strings.Split(info, "\n")
			if len(lines) < 5 {
				t.Error("Info should have at least 5 lines")
			}
		}
	})
}

// FuzzSudoCheckMessage tests message generation with various inputs
func FuzzSudoCheckMessage(f *testing.F) {
	// Add seed corpus
	seeds := []struct {
		requirement string
		success     bool
		isRoot      bool
		hasSudo     bool
		customMsg   string
	}{
		{"required", true, true, true, ""},
		{"required", false, false, false, "Custom error"},
		{"preferred", true, false, true, ""},
		{"not_required", true, false, false, ""},
		{"required", false, false, true, strings.Repeat("x", 1000)},
		{"preferred", true, true, true, "Ignored message"},
	}

	for _, seed := range seeds {
		f.Add(seed.requirement, seed.success, seed.isRoot, seed.hasSudo, seed.customMsg)
	}

	f.Fuzz(func(t *testing.T, requirement string, success bool, isRoot bool, hasSudo bool, customMsg string) {
		// Create a valid requirement
		var req SudoRequirement
		switch requirement {
		case string(SudoRequired):
			req = SudoRequired
		case string(SudoPreferred):
			req = SudoPreferred
		case string(SudoNotRequired):
			req = SudoNotRequired
		default:
			req = SudoNotRequired
		}

		// Create a mock result
		result := &SudoCheckResult{
			Required:  (req == SudoRequired),
			Success:   success,
			Message:   "", // Will be set by logic
			Timestamp: time.Now(),
			Check: PrivilegeCheck{
				IsRoot:  isRoot,
				HasSudo: hasSudo,
			},
		}

		// Simulate message generation logic
		switch req {
		case SudoNotRequired:
			result.Message = "No elevated privileges required"
		case SudoPreferred:
			if isRoot || hasSudo {
				result.Message = "Running with elevated privileges"
			} else {
				result.Message = "Running with regular privileges (elevated privileges preferred but not required)"
			}
		case SudoRequired:
			if success {
				if isRoot {
					result.Message = "Running as root"
				} else {
					result.Message = "Running with sudo privileges"
				}
			} else {
				if customMsg != "" {
					result.Message = customMsg
				} else {
					result.Message = "This operation requires root privileges. Please run with sudo."
				}
			}
		}

		// Validate message
		if result.Message == "" {
			t.Error("Message should not be empty")
		}

		// For failed required checks with custom message
		if req == SudoRequired && !success && customMsg != "" {
			if result.Message != customMsg {
				t.Errorf("Custom message not used: got %q, want %q", result.Message, customMsg)
			}
		}

		// Consistency checks
		if success && strings.Contains(result.Message, "requires root privileges") {
			t.Error("Success message should not mention requirements")
		}

		if !success && req == SudoNotRequired {
			t.Error("SudoNotRequired should always succeed")
		}
	})
}

// FuzzContextCancellation tests behavior with various context states
func FuzzContextCancellation(f *testing.F) {
	// Add seed corpus
	seeds := []struct {
		canceled      bool
		withDeadline  bool
		deadlineNanos int64
	}{
		{false, false, 0},
		{true, false, 0},
		{false, true, int64(time.Second)},
		{true, true, int64(time.Millisecond)},
		{false, true, -1},
	}

	for _, seed := range seeds {
		f.Add(seed.canceled, seed.withDeadline, seed.deadlineNanos)
	}

	f.Fuzz(func(t *testing.T, canceled bool, withDeadline bool, deadlineNanos int64) {
		pm := NewPrivilegeManager(&PrivilegeConfig{
			ExitOnFailure:   false,
			ShowColorOutput: false,
		})

		var ctx context.Context
		var cancel context.CancelFunc

		// Create context based on parameters
		if withDeadline && deadlineNanos > 0 {
			ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(time.Duration(deadlineNanos)))
			defer cancel()
		} else {
			ctx, cancel = context.WithCancel(context.Background())
			defer cancel()
		}

		if canceled {
			cancel()
		}

		rc := &eos_io.RuntimeContext{
			Ctx: ctx,
		}

		// Should not panic even with cancelled context
		check, err := pm.CheckPrivileges(rc)

		// Basic checks should still work even with cancelled context
		if err == nil && check != nil {
			// UserID should always be set
			if check.UserID < 0 {
				t.Error("UserID should not be negative")
			}

			// Timestamp should be set
			if check.Timestamp.IsZero() {
				t.Error("Timestamp should be set")
			}
		}

		// Test RequireSudo with same context
		options := &CheckOptions{
			Requirement: SudoRequired,
			SilentMode:  true,
		}

		// Should not panic
		result, _ := pm.RequireSudo(rc, options)

		if result != nil && result.Timestamp.IsZero() {
			t.Error("Result timestamp should be set")
		}
	})
}
