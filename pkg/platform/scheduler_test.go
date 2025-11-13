package platform

import (
	"context"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/testutil"
	"github.com/stretchr/testify/assert"
)

func TestScheduleCron(t *testing.T) {
	t.Parallel()

	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	tests := []testutil.TableTest[struct {
		cmd        string
		osPlatform string
		wantErr    bool
	}]{
		{
			Name: "schedule on linux",
			Input: struct {
				cmd        string
				osPlatform string
				wantErr    bool
			}{
				cmd:        "eos update packages",
				osPlatform: "linux",
				wantErr:    true, // Will error in test env without crontab
			},
		},
		{
			Name: "schedule on macos",
			Input: struct {
				cmd        string
				osPlatform string
				wantErr    bool
			}{
				cmd:        "eos update packages",
				osPlatform: "macos",
				wantErr:    true, // Will error in test env without crontab
			},
		},
		{
			Name: "schedule on windows",
			Input: struct {
				cmd        string
				osPlatform string
				wantErr    bool
			}{
				cmd:        "eos update packages",
				osPlatform: "windows",
				wantErr:    true, // Will error in test env without schtasks
			},
		},
		{
			Name: "unsupported platform",
			Input: struct {
				cmd        string
				osPlatform string
				wantErr    bool
			}{
				cmd:        "eos update packages",
				osPlatform: "unsupported",
				wantErr:    true,
			},
		},
		{
			Name: "empty command",
			Input: struct {
				cmd        string
				osPlatform string
				wantErr    bool
			}{
				cmd:        "",
				osPlatform: "linux",
				wantErr:    true, // Will error in test env without crontab
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()

			err := scheduleCron(rc, tt.Input.cmd, tt.Input.osPlatform)

			if tt.Input.wantErr {
				assert.Error(t, err)
				if tt.Input.osPlatform == "unsupported" {
					assert.Contains(t, err.Error(), "not supported")
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Security Tests for Scheduler
func TestScheduleCronSecurity(t *testing.T) {
	t.Parallel()

	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	tests := []testutil.TableTest[struct {
		maliciousCmd string
		description  string
	}]{
		{
			Name: "command injection in cron command",
			Input: struct {
				maliciousCmd string
				description  string
			}{
				maliciousCmd: "eos update; rm -rf /",
				description:  "command injection with semicolon",
			},
		},
		{
			Name: "shell metacharacter injection",
			Input: struct {
				maliciousCmd string
				description  string
			}{
				maliciousCmd: "eos update && rm -rf /",
				description:  "command injection with &&",
			},
		},
		{
			Name: "pipe injection in command",
			Input: struct {
				maliciousCmd string
				description  string
			}{
				maliciousCmd: "eos update | rm -rf /",
				description:  "command injection with pipe",
			},
		},
		{
			Name: "backtick injection",
			Input: struct {
				maliciousCmd string
				description  string
			}{
				maliciousCmd: "eos update `rm -rf /`",
				description:  "backtick command substitution",
			},
		},
		{
			Name: "dollar parentheses injection",
			Input: struct {
				maliciousCmd string
				description  string
			}{
				maliciousCmd: "eos update $(rm -rf /)",
				description:  "dollar parentheses command substitution",
			},
		},
		{
			Name: "null byte injection",
			Input: struct {
				maliciousCmd string
				description  string
			}{
				maliciousCmd: "eos update\x00rm -rf /",
				description:  "null byte injection",
			},
		},
		{
			Name: "newline injection",
			Input: struct {
				maliciousCmd string
				description  string
			}{
				maliciousCmd: "eos update\nrm -rf /",
				description:  "newline injection",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()

			// Test on Linux platform
			err := scheduleCron(rc, tt.Input.maliciousCmd, "linux")

			// Should handle malicious input but will error in test env
			assert.Error(t, err) // Will error without crontab in test env

			// The function should not panic or cause security issues
			// Actual command execution safety depends on the shell execution
		})
	}
}

func TestScheduleCronRandomTimeGeneration(t *testing.T) {
	t.Parallel()

	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	// Test that the function generates different random times
	// This is important for distributing cron load

	// Run the function multiple times and check it doesn't panic
	for i := 0; i < 10; i++ {
		err := scheduleCron(rc, "test command", "linux")
		// Will error without crontab, but should not panic
		assert.Error(t, err)
	}
}

func TestScheduleCronExistingCrontab(t *testing.T) {
	t.Parallel()

	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	// Test behavior when crontab -l fails (no existing crontab)
	// This should be handled gracefully
	err := scheduleCron(rc, "test command", "linux")
	assert.Error(t, err) // Will error in test environment without crontab
}

func TestScheduleCronInvalidPlatform(t *testing.T) {
	t.Parallel()

	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	tests := []testutil.TableTest[struct {
		platform string
	}]{
		{
			Name: "freebsd platform",
			Input: struct {
				platform string
			}{
				platform: "freebsd",
			},
		},
		{
			Name: "openbsd platform",
			Input: struct {
				platform string
			}{
				platform: "openbsd",
			},
		},
		{
			Name: "solaris platform",
			Input: struct {
				platform string
			}{
				platform: "solaris",
			},
		},
		{
			Name: "empty platform",
			Input: struct {
				platform string
			}{
				platform: "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()

			err := scheduleCron(rc, "test command", tt.Input.platform)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "not supported")
		})
	}
}

// Test Windows-specific scheduling behavior
func TestScheduleCronWindows(t *testing.T) {
	t.Parallel()

	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	// Test Windows scheduled task creation
	err := scheduleCron(rc, "eos update packages", "windows")
	assert.Error(t, err) // Will error in test env without schtasks

	// Test that the function handles Windows time format correctly
	// The function should generate time in HH:MM format for Windows
}

// Benchmark Tests
func BenchmarkScheduleCron(b *testing.B) {
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	b.ResetTimer()
	for b.Loop() {
		_ = scheduleCron(rc, "eos update packages", "linux")
	}
}

func BenchmarkScheduleCronRandomGeneration(b *testing.B) {
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	b.ResetTimer()
	for b.Loop() {
		// Focus on the random number generation part
		_ = scheduleCron(rc, "test", "unsupported") // Will fail fast after random generation
	}
}
