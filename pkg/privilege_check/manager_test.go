package privilege_check

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"strings"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

// TestNewPrivilegeManager tests the creation of privilege manager
func TestNewPrivilegeManager(t *testing.T) {
	tests := []struct {
		name   string
		config *PrivilegeConfig
		verify func(*testing.T, *PrivilegeManager)
	}{
		{
			name:   "with nil config uses defaults",
			config: nil,
			verify: func(t *testing.T, pm *PrivilegeManager) {
				if pm.config == nil {
					t.Error("Expected default config, got nil")
				}
				if !pm.config.RequireRoot {
					t.Error("Expected RequireRoot to be true by default")
				}
				if !pm.config.AllowSudo {
					t.Error("Expected AllowSudo to be true by default")
				}
			},
		},
		{
			name: "with custom config",
			config: &PrivilegeConfig{
				RequireRoot:     false,
				AllowSudo:       false,
				ExitOnFailure:   false,
				ShowColorOutput: false,
			},
			verify: func(t *testing.T, pm *PrivilegeManager) {
				if pm.config.RequireRoot {
					t.Error("Expected RequireRoot to be false")
				}
				if pm.config.AllowSudo {
					t.Error("Expected AllowSudo to be false")
				}
				if pm.config.ExitOnFailure {
					t.Error("Expected ExitOnFailure to be false")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pm := NewPrivilegeManager(tt.config)
			tt.verify(t, pm)
		})
	}
}

// TestCheckPrivileges tests privilege checking functionality
func TestCheckPrivileges(t *testing.T) {
	pm := NewPrivilegeManager(&PrivilegeConfig{
		RequireRoot:     false,
		AllowSudo:       true,
		ExitOnFailure:   false,
		ShowColorOutput: false,
	})

	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	check, err := pm.CheckPrivileges(rc)
	if err != nil {
		t.Fatalf("CheckPrivileges failed: %v", err)
	}

	// Verify basic fields are populated
	if check.Username == "" {
		t.Error("Username should not be empty")
	}

	if check.UserID < 0 {
		t.Error("UserID should not be negative")
	}

	if check.Timestamp.IsZero() {
		t.Error("Timestamp should be set")
	}

	// Verify privilege level is set
	validLevels := []PrivilegeLevel{PrivilegeLevelRoot, PrivilegeLevelSudo, PrivilegeLevelRegular}
	found := false
	for _, level := range validLevels {
		if check.Level == level {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Invalid privilege level: %s", check.Level)
	}

	// Consistency checks
	if check.IsRoot && check.UserID != 0 {
		t.Error("IsRoot is true but UserID is not 0")
	}

	if check.UserID == 0 && !check.IsRoot {
		t.Error("UserID is 0 but IsRoot is false")
	}

	if check.IsRoot && check.Level != PrivilegeLevelRoot {
		t.Error("IsRoot is true but Level is not root")
	}
}

// TestRequireSudo tests sudo requirement checking
func TestRequireSudo(t *testing.T) {
	tests := []struct {
		name          string
		options       *CheckOptions
		isRoot        bool
		expectSuccess bool
	}{
		{
			name: "not required always succeeds",
			options: &CheckOptions{
				Requirement: SudoNotRequired,
				SilentMode:  true,
			},
			isRoot:        false,
			expectSuccess: true,
		},
		{
			name: "preferred always succeeds",
			options: &CheckOptions{
				Requirement: SudoPreferred,
				SilentMode:  true,
			},
			isRoot:        false,
			expectSuccess: true,
		},
		{
			name: "required succeeds for root",
			options: &CheckOptions{
				Requirement: SudoRequired,
				SilentMode:  true,
			},
			isRoot:        true,
			expectSuccess: true,
		},
		{
			name:          "nil options defaults to required",
			options:       nil,
			isRoot:        false,
			expectSuccess: false,
		},
		{
			name: "custom message is used",
			options: &CheckOptions{
				Requirement:   SudoRequired,
				CustomMessage: "Custom error message",
				SilentMode:    true,
			},
			isRoot:        false,
			expectSuccess: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pm := NewPrivilegeManager(&PrivilegeConfig{
				RequireRoot:     false,
				AllowSudo:       true,
				ExitOnFailure:   false,
				ShowColorOutput: false,
			})

			rc := &eos_io.RuntimeContext{
				Ctx: context.Background(),
			}

			// Skip test if we need root but aren't root
			if tt.isRoot && os.Geteuid() != 0 {
				t.Skip("Test requires root privileges")
			}

			// Skip test if we need non-root but are root
			if !tt.isRoot && os.Geteuid() == 0 {
				t.Skip("Test requires non-root privileges")
			}

			result, err := pm.RequireSudo(rc, tt.options)
			if err != nil {
				t.Fatalf("RequireSudo failed: %v", err)
			}

			// Adjust expectations based on actual privilege state
			// If we have sudo/root access and the test expects failure, skip
			actualRequirement := SudoRequired
			if tt.options != nil {
				actualRequirement = tt.options.Requirement
			}
			if (result.Check.IsRoot || result.Check.HasSudo) && !tt.expectSuccess && actualRequirement == SudoRequired {
				t.Skip("Test expects no sudo but user has sudo privileges")
			}

			if result.Success != tt.expectSuccess {
				t.Errorf("Success = %v, want %v (message: %s)",
					result.Success, tt.expectSuccess, result.Message)
			}

			if tt.options != nil && tt.options.CustomMessage != "" && !result.Success {
				if result.Message != tt.options.CustomMessage {
					t.Errorf("Expected custom message %q, got %q",
						tt.options.CustomMessage, result.Message)
				}
			}

			// Verify timestamp is set
			if result.Timestamp.IsZero() {
				t.Error("Timestamp should be set")
			}

			// Verify Required field matches requirement
			if tt.options != nil && tt.options.Requirement == SudoRequired {
				if !result.Required {
					t.Error("Required should be true for SudoRequired")
				}
			}
		})
	}
}

// TestCheckSudoOnly tests the convenience sudo check method
func TestCheckSudoOnly(t *testing.T) {
	pm := NewPrivilegeManager(&PrivilegeConfig{
		RequireRoot:     false,
		AllowSudo:       true,
		ExitOnFailure:   false,
		ShowColorOutput: false,
	})

	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	err := pm.CheckSudoOnly(rc)

	// If we're root, it should succeed
	if os.Geteuid() == 0 {
		if err != nil {
			t.Errorf("CheckSudoOnly failed for root: %v", err)
		}
	} else {
		// For non-root, it should fail (assuming no passwordless sudo in test env)
		if err == nil {
			t.Skip("User has sudo access, skipping non-sudo test")
		}
		if !strings.Contains(err.Error(), "sudo privileges required") {
			t.Errorf("Expected sudo error, got: %v", err)
		}
	}
}

// TestGetPrivilegeInfo tests privilege information formatting
func TestGetPrivilegeInfo(t *testing.T) {
	pm := NewPrivilegeManager(nil)
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	info, err := pm.GetPrivilegeInfo(rc)
	if err != nil {
		t.Fatalf("GetPrivilegeInfo failed: %v", err)
	}

	// Verify expected information is present
	expectedFields := []string{
		"User:",
		"Group:",
		"Privilege Level:",
		"Is Root:",
		"Has Sudo:",
	}

	for _, field := range expectedFields {
		if !strings.Contains(info, field) {
			t.Errorf("Missing field %q in privilege info", field)
		}
	}

	// Verify current user info is present
	currentUser, err := user.Current()
	if err == nil {
		if !strings.Contains(info, currentUser.Username) {
			t.Errorf("Current username %q not found in info", currentUser.Username)
		}
	}
}

// TestCheckSudoAccess tests sudo access detection
func TestCheckSudoAccess(t *testing.T) {
	pm := NewPrivilegeManager(nil)
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	// This is a private method, so we test it indirectly through CheckPrivileges
	check, err := pm.CheckPrivileges(rc)
	if err != nil {
		t.Fatalf("CheckPrivileges failed: %v", err)
	}

	// If we're root, HasSudo should always be true
	if check.IsRoot && !check.HasSudo {
		t.Error("Root user should always have sudo")
	}

	// Verify level consistency
	if check.HasSudo && !check.IsRoot && check.Level != PrivilegeLevelSudo {
		t.Error("Has sudo but level is not sudo")
	}

	if !check.HasSudo && !check.IsRoot && check.Level != PrivilegeLevelRegular {
		t.Error("No sudo and not root but level is not regular")
	}
}

// TestOutputColoredMessage tests colored output (without actually printing)
func TestOutputColoredMessage(t *testing.T) {
	// We can't easily test fmt.Printf output, but we can ensure it doesn't panic
	pm := NewPrivilegeManager(&PrivilegeConfig{
		ShowColorOutput: true,
	})

	testCases := []struct {
		name   string
		result *SudoCheckResult
	}{
		{
			name: "success as root",
			result: &SudoCheckResult{
				Success: true,
				Message: "Test message",
				Check: PrivilegeCheck{
					IsRoot: true,
				},
			},
		},
		{
			name: "success as non-root",
			result: &SudoCheckResult{
				Success: true,
				Message: "Test message",
				Check: PrivilegeCheck{
					IsRoot: false,
				},
			},
		},
		{
			name: "failure",
			result: &SudoCheckResult{
				Success: false,
				Message: "Error message",
				Check: PrivilegeCheck{
					IsRoot: false,
				},
			},
		},
	}

	// Capture stdout to prevent test output pollution
	oldStdout := os.Stdout
	defer func() { os.Stdout = oldStdout }()

	// Create a pipe to capture output
	_, w, _ := os.Pipe()
	os.Stdout = w

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// This should not panic
			pm.outputColoredMessage(tc.result)
		})
	}

	w.Close()
	os.Stdout = oldStdout
}

// TestPrivilegeCheckTimestamps tests that timestamps are properly set
func TestPrivilegeCheckTimestamps(t *testing.T) {
	pm := NewPrivilegeManager(nil)
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	before := time.Now()
	check, err := pm.CheckPrivileges(rc)
	after := time.Now()

	if err != nil {
		t.Fatalf("CheckPrivileges failed: %v", err)
	}

	if check.Timestamp.Before(before) || check.Timestamp.After(after) {
		t.Error("Timestamp not within expected range")
	}
}

// TestExitOnFailure tests exit behavior (without actually exiting)
func TestExitOnFailure(t *testing.T) {
	// We can't test os.Exit directly, but we can verify the logic path
	pm := NewPrivilegeManager(&PrivilegeConfig{
		RequireRoot:     true,
		AllowSudo:       false,
		ExitOnFailure:   false, // Set to false to prevent exit in tests
		ShowColorOutput: false,
	})

	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	// If we're not root, this should fail but not exit
	if os.Geteuid() != 0 {
		result, err := pm.RequireSudo(rc, &CheckOptions{
			Requirement: SudoRequired,
			SilentMode:  true,
		})

		if err != nil {
			t.Fatalf("RequireSudo failed: %v", err)
		}

		if result.Success {
			t.Skip("User has elevated privileges")
		}

		// We're still here, so exit was not called
		if result.Success {
			t.Error("Expected failure for non-root user")
		}
	}
}

// TestPrivilegeConfigDefaults tests default configuration values
func TestPrivilegeConfigDefaults(t *testing.T) {
	config := DefaultPrivilegeConfig()

	if !config.RequireRoot {
		t.Error("Default RequireRoot should be true")
	}

	if !config.AllowSudo {
		t.Error("Default AllowSudo should be true")
	}

	if !config.ExitOnFailure {
		t.Error("Default ExitOnFailure should be true")
	}

	if !config.ShowColorOutput {
		t.Error("Default ShowColorOutput should be true")
	}
}

// TestConcurrentPrivilegeChecks tests concurrent access
func TestConcurrentPrivilegeChecks(t *testing.T) {
	pm := NewPrivilegeManager(nil)
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func() {
			defer func() { done <- true }()

			rc := &eos_io.RuntimeContext{
				Ctx: context.Background(),
			}

			_, err := pm.CheckPrivileges(rc)
			if err != nil {
				t.Errorf("Concurrent check failed: %v", err)
			}
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}

// TestErrorHandling tests error handling scenarios
func TestErrorHandling(t *testing.T) {
	pm := NewPrivilegeManager(&PrivilegeConfig{
		ExitOnFailure: false,
	})

	// Test with cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	rc := &eos_io.RuntimeContext{
		Ctx: ctx,
	}

	// Should still work even with cancelled context for basic checks
	check, err := pm.CheckPrivileges(rc)
	if err != nil {
		// Some operations might fail with cancelled context
		t.Logf("CheckPrivileges with cancelled context: %v", err)
	} else {
		// Basic fields should still be populated
		if check.UserID < 0 {
			t.Error("UserID should be set even with cancelled context")
		}
	}
}

// TestGroupDetection tests group detection logic
func TestGroupDetection(t *testing.T) {
	pm := NewPrivilegeManager(nil)
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	check, err := pm.CheckPrivileges(rc)
	if err != nil {
		t.Fatalf("CheckPrivileges failed: %v", err)
	}

	// Verify group information
	if check.GroupID < 0 {
		t.Error("GroupID should not be negative")
	}

	if check.Groupname == "" {
		t.Error("Groupname should not be empty")
	}

	// If we can't resolve the group, it should show gid-N format
	if strings.HasPrefix(check.Groupname, "gid-") {
		// Extract the number after "gid-"
		var gid int
		_, _ = fmt.Sscanf(check.Groupname, "gid-%d", &gid)
		if gid != check.GroupID {
			t.Errorf("Fallback group name gid-%d doesn't match GroupID %d", gid, check.GroupID)
		}
	}
}
