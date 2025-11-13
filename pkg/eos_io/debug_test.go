package eos_io

import (
	"os"
	"testing"
)

func TestSetDebugMode(t *testing.T) {
	t.Parallel()
	// Save original debug state
	originalDebug := os.Getenv("Eos_DEBUG")
	defer func() {
		if originalDebug != "" {
			_ = os.Setenv("Eos_DEBUG", originalDebug) // Test cleanup, error not critical
		} else {
			_ = os.Unsetenv("Eos_DEBUG")
		}
	}()

	t.Run("enables_debug_mode", func(t *testing.T) {
		t.Parallel()
		// Clear any existing debug setting
		_ = os.Unsetenv("Eos_DEBUG")

		// Enable debug
		SetDebugMode(true)

		// Verify debug is enabled
		if !DebugEnabled() {
			t.Error("expected debug to be enabled")
		}

		// Verify DebugMode variable is set
		if DebugMode != true {
			t.Error("expected DebugMode to be true")
		}
	})

	t.Run("disables_debug_mode", func(t *testing.T) {
		t.Parallel()
		// First enable debug
		SetDebugMode(true)
		if !DebugEnabled() {
			t.Fatal("setup failed: debug should be enabled")
		}

		// Disable debug
		SetDebugMode(false)

		// Verify debug is disabled
		if DebugEnabled() {
			t.Error("expected debug to be disabled")
		}

		// Verify environment variable is unset
		if os.Getenv("Eos_DEBUG") != "" {
			t.Error("expected Eos_DEBUG environment variable to be unset")
		}
	})

	t.Run("toggle_debug_mode_multiple_times", func(t *testing.T) {
		t.Parallel()
		// Start with debug disabled
		SetDebugMode(false)
		if DebugEnabled() {
			t.Fatal("setup failed: debug should be disabled")
		}

		// Enable -> Disable -> Enable
		SetDebugMode(true)
		if !DebugEnabled() {
			t.Error("first enable failed")
		}

		SetDebugMode(false)
		if DebugEnabled() {
			t.Error("disable failed")
		}

		SetDebugMode(true)
		if !DebugEnabled() {
			t.Error("second enable failed")
		}
	})
}

func TestDebugEnabled(t *testing.T) {
	t.Parallel()
	// Save original debug state
	originalDebug := DebugMode
	defer func() {
		DebugMode = originalDebug
	}()

	t.Run("returns_false_when_unset", func(t *testing.T) {
		t.Parallel()
		DebugMode = false

		if DebugEnabled() {
			t.Error("expected debug to be disabled when DebugMode is false")
		}
	})

	t.Run("returns_true_when_set_to_true", func(t *testing.T) {
		t.Parallel()
		DebugMode = true

		if !DebugEnabled() {
			t.Error("expected debug to be enabled when DebugMode=true")
		}
	})

	t.Run("returns_false_when_set_to_false", func(t *testing.T) {
		t.Parallel()
		DebugMode = false

		if DebugEnabled() {
			t.Error("expected debug to be disabled when DebugMode=false")
		}
	})

	t.Run("debug_mode_toggle_test", func(t *testing.T) {
		t.Parallel()
		// Test true state
		DebugMode = true
		if !DebugEnabled() {
			t.Error("expected debug to be enabled when DebugMode=true")
		}

		// Test false state
		DebugMode = false
		if DebugEnabled() {
			t.Error("expected debug to be disabled when DebugMode=false")
		}
	})
}

// TestDebugModeIntegration tests the integration between SetDebugMode and DebugEnabled
func TestDebugModeIntegration(t *testing.T) {
	t.Parallel()
	// Save original debug state
	originalDebug := DebugMode
	defer func() {
		DebugMode = originalDebug
	}()

	t.Run("set_and_check_consistency", func(t *testing.T) {
		t.Parallel()
		// Test enable
		SetDebugMode(true)
		if !DebugEnabled() {
			t.Error("SetDebugMode(true) should make DebugEnabled() return true")
		}

		// Test disable
		SetDebugMode(false)
		if DebugEnabled() {
			t.Error("SetDebugMode(false) should make DebugEnabled() return false")
		}
	})

	t.Run("multiple_toggles", func(t *testing.T) {
		t.Parallel()
		// Start false
		SetDebugMode(false)
		if DebugEnabled() {
			t.Error("SetDebugMode(false) should disable debug")
		}

		// Toggle to true
		SetDebugMode(true)
		if !DebugEnabled() {
			t.Error("SetDebugMode(true) should enable debug")
		}

		// Toggle back to false
		SetDebugMode(false)
		if DebugEnabled() {
			t.Error("SetDebugMode(false) should disable debug again")
		}
	})
}
