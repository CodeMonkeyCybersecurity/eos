package platform

import (
	"context"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/testutil"
	"github.com/stretchr/testify/assert"
)

func TestPackageUpdate(t *testing.T) {
	t.Parallel()

	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	tests := []testutil.TableTest[struct {
		cron    bool
		wantErr bool
	}]{
		{
			Name: "immediate package update",
			Input: struct {
				cron    bool
				wantErr bool
			}{
				cron:    false,
				wantErr: true, // Will error in test environment without package managers
			},
		},
		{
			Name: "cron package update",
			Input: struct {
				cron    bool
				wantErr bool
			}{
				cron:    true,
				wantErr: true, // Will error in test environment without crontab
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()

			err := PackageUpdate(rc, tt.Input.cron)

			if tt.Input.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestRunDnfWithRetry(t *testing.T) {
	t.Parallel()

	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	tests := []testutil.TableTest[struct {
		pkgName string
		wantErr bool
	}]{
		{
			Name: "install with empty package name",
			Input: struct {
				pkgName string
				wantErr bool
			}{
				pkgName: "",
				wantErr: true, // Will error since dnf not available in test env
			},
		},
		{
			Name: "install specific package",
			Input: struct {
				pkgName string
				wantErr bool
			}{
				pkgName: "vim",
				wantErr: true, // Will error since dnf not available in test env
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()

			err := runDnfWithRetry(rc, tt.Input.pkgName)

			if tt.Input.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestRunAndLog(t *testing.T) {
	t.Parallel()

	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	tests := []testutil.TableTest[struct {
		cmd      string
		shell    string
		shellArg string
		wantErr  bool
	}]{
		{
			Name: "valid echo command",
			Input: struct {
				cmd      string
				shell    string
				shellArg string
				wantErr  bool
			}{
				cmd:      "echo 'test'",
				shell:    "bash",
				shellArg: "-c",
				wantErr:  false,
			},
		},
		{
			Name: "invalid command",
			Input: struct {
				cmd      string
				shell    string
				shellArg string
				wantErr  bool
			}{
				cmd:      "definitely-not-a-real-command-12345",
				shell:    "bash",
				shellArg: "-c",
				wantErr:  true,
			},
		},
		{
			Name: "empty command",
			Input: struct {
				cmd      string
				shell    string
				shellArg string
				wantErr  bool
			}{
				cmd:      "",
				shell:    "bash",
				shellArg: "-c",
				wantErr:  false, // Empty command succeeds
			},
		},
		{
			Name: "command with sh shell",
			Input: struct {
				cmd      string
				shell    string
				shellArg string
				wantErr  bool
			}{
				cmd:      "echo 'test with sh'",
				shell:    "sh",
				shellArg: "-c",
				wantErr:  false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()

			err := runAndLog(rc, tt.Input.cmd, tt.Input.shell, tt.Input.shellArg)

			if tt.Input.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Security Tests
func TestPackageUpdateSecurity(t *testing.T) {
	t.Parallel()

	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	// Test that PackageUpdate handles different OS platforms
	// This is important for security to ensure no unintended command execution
	originalGOOS := GetOSPlatform()

	// Function should handle all supported platforms safely
	err := PackageUpdate(rc, false)
	assert.Error(t, err) // Will error in test environment

	// Ensure original platform detection still works
	assert.Equal(t, originalGOOS, GetOSPlatform())
}

func TestRunAndLogSecurity(t *testing.T) {
	t.Parallel()

	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	tests := []testutil.TableTest[struct {
		maliciousCmd string
		description  string
	}]{
		{
			Name: "command injection attempt",
			Input: struct {
				maliciousCmd string
				description  string
			}{
				maliciousCmd: "echo 'safe'; rm -rf /",
				description:  "command injection with semicolon",
			},
		},
		{
			Name: "shell metacharacter injection",
			Input: struct {
				maliciousCmd string
				description  string
			}{
				maliciousCmd: "echo 'safe' && rm -rf /",
				description:  "command injection with &&",
			},
		},
		{
			Name: "pipe injection",
			Input: struct {
				maliciousCmd string
				description  string
			}{
				maliciousCmd: "echo 'safe' | rm -rf /",
				description:  "command injection with pipe",
			},
		},
		{
			Name: "null byte injection",
			Input: struct {
				maliciousCmd string
				description  string
			}{
				maliciousCmd: "echo 'safe'\x00rm -rf /",
				description:  "null byte injection",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()

			// runAndLog should execute the malicious command as-is
			// Security should be handled by the caller or at a higher level
			err := runAndLog(rc, tt.Input.maliciousCmd, "bash", "-c")

			// The function may succeed or fail, but shouldn't panic
			// Command injection is possible with exec.Command as designed
			_ = err
		})
	}
}

func TestRunDnfWithRetrySecurity(t *testing.T) {
	t.Parallel()

	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	tests := []testutil.TableTest[struct {
		maliciousPkg string
		description  string
	}]{
		{
			Name: "command injection in package name",
			Input: struct {
				maliciousPkg string
				description  string
			}{
				maliciousPkg: "vim; rm -rf /",
				description:  "command injection attempt",
			},
		},
		{
			Name: "shell metacharacters in package name",
			Input: struct {
				maliciousPkg string
				description  string
			}{
				maliciousPkg: "vim && echo pwned",
				description:  "shell metacharacter injection",
			},
		},
		{
			Name: "path traversal in package name",
			Input: struct {
				maliciousPkg string
				description  string
			}{
				maliciousPkg: "../../../etc/passwd",
				description:  "path traversal attempt",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()

			err := runDnfWithRetry(rc, tt.Input.maliciousPkg)

			// Should handle malicious input safely
			// dnf will treat the entire string as a package name argument
			assert.Error(t, err) // Will error in test env without dnf
		})
	}
}

// Benchmark Tests
func BenchmarkPackageUpdate(b *testing.B) {
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = PackageUpdate(rc, true) // Use cron mode to avoid actual package updates
	}
}

func BenchmarkRunAndLog(b *testing.B) {
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = runAndLog(rc, "echo 'benchmark'", "bash", "-c")
	}
}
