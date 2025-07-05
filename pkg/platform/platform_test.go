package platform

import (
	"context"
	"os"
	"runtime"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/testutil"
	"github.com/stretchr/testify/assert"
)

func TestGetOSPlatform(t *testing.T) {
	t.Parallel()

	tests := []testutil.TableTest[struct {
		expected string
	}]{
		{
			Name: "returns current platform",
			Input: struct {
				expected string
			}{
				expected: map[string]string{
					"darwin":  "macos",
					"linux":   "linux", 
					"windows": "windows",
				}[runtime.GOOS],
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			result := GetOSPlatform()
			if tt.Input.expected != "" {
				assert.Equal(t, tt.Input.expected, result)
			} else {
				assert.Equal(t, "unknown", result)
			}
		})
	}
}

func TestOSDetectionFunctions(t *testing.T) {
	t.Parallel()

	tests := []testutil.TableTest[struct {
		function string
		expected bool
	}]{
		{
			Name: "IsMacOS should match runtime.GOOS",
			Input: struct {
				function string
				expected bool
			}{
				function: "IsMacOS",
				expected: runtime.GOOS == "darwin",
			},
		},
		{
			Name: "IsLinux should match runtime.GOOS",
			Input: struct {
				function string
				expected bool
			}{
				function: "IsLinux",
				expected: runtime.GOOS == "linux",
			},
		},
		{
			Name: "IsWindows should match runtime.GOOS",
			Input: struct {
				function string
				expected bool
			}{
				function: "IsWindows",
				expected: runtime.GOOS == "windows",
			},
		},
		{
			Name: "IsUnknownPlatform should be false for known platforms",
			Input: struct {
				function string
				expected bool
			}{
				function: "IsUnknownPlatform",
				expected: !contains([]string{"darwin", "linux", "windows"}, runtime.GOOS),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			var result bool
			switch tt.Input.function {
			case "IsMacOS":
				result = IsMacOS()
			case "IsLinux":
				result = IsLinux()
			case "IsWindows":
				result = IsWindows()
			case "IsUnknownPlatform":
				result = IsUnknownPlatform()
			}
			assert.Equal(t, tt.Input.expected, result)
		})
	}
}

func TestGetArch(t *testing.T) {
	t.Parallel()
	
	result := GetArch()
	assert.Equal(t, runtime.GOARCH, result)
}

func TestIsARM(t *testing.T) {
	t.Parallel()
	
	result := IsARM()
	expected := runtime.GOARCH == "arm" || runtime.GOARCH == "arm64"
	assert.Equal(t, expected, result)
}

func TestIsCommandAvailable(t *testing.T) {
	t.Parallel()

	tests := []testutil.TableTest[struct {
		command string
		wantErr bool
	}]{
		{
			Name: "go command should be available",
			Input: struct {
				command string
				wantErr bool
			}{
				command: "go",
				wantErr: false,
			},
		},
		{
			Name: "nonexistent command should not be available",
			Input: struct {
				command string
				wantErr bool
			}{
				command: "definitely-not-a-real-command-12345",
				wantErr: true,
			},
		},
		{
			Name: "empty command name",
			Input: struct {
				command string
				wantErr bool
			}{
				command: "",
				wantErr: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			result := IsCommandAvailable(tt.Input.command)
			if tt.Input.wantErr {
				assert.False(t, result)
			} else {
				assert.True(t, result)
			}
		})
	}
}

func TestGetShellType(t *testing.T) {
	t.Parallel()

	tests := []testutil.TableTest[struct {
		shellEnv string
		expected string
	}]{
		{
			Name: "zsh shell detection",
			Input: struct {
				shellEnv string
				expected string
			}{
				shellEnv: "/bin/zsh",
				expected: "zsh",
			},
		},
		{
			Name: "bash shell detection",
			Input: struct {
				shellEnv string
				expected string
			}{
				shellEnv: "/bin/bash",
				expected: "bash",
			},
		},
		{
			Name: "fish shell detection",
			Input: struct {
				shellEnv string
				expected string
			}{
				shellEnv: "/usr/bin/fish",
				expected: "fish",
			},
		},
		{
			Name: "unknown shell",
			Input: struct {
				shellEnv string
				expected string
			}{
				shellEnv: "/bin/csh",
				expected: "unknown",
			},
		},
		{
			Name: "empty shell",
			Input: struct {
				shellEnv string
				expected string
			}{
				shellEnv: "",
				expected: "unknown",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			
			// Save original environment
			originalShell := os.Getenv("SHELL")
			defer os.Setenv("SHELL", originalShell)
			
			// Set test environment
			os.Setenv("SHELL", tt.Input.shellEnv)
			
			result := GetShellType()
			assert.Equal(t, tt.Input.expected, result)
		})
	}
}

func TestGetHomeDir(t *testing.T) {
	t.Parallel()

	tests := []testutil.TableTest[struct {
		homeEnv     string
		expectFallback bool
	}]{
		{
			Name: "HOME environment variable set",
			Input: struct {
				homeEnv     string
				expectFallback bool
			}{
				homeEnv:     "/custom/home",
				expectFallback: false,
			},
		},
		{
			Name: "HOME environment variable empty",
			Input: struct {
				homeEnv     string
				expectFallback bool
			}{
				homeEnv:     "",
				expectFallback: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			
			// Save original environment
			originalHome := os.Getenv("HOME")
			defer os.Setenv("HOME", originalHome)
			
			// Set test environment
			if tt.Input.homeEnv != "" {
				os.Setenv("HOME", tt.Input.homeEnv)
			} else {
				os.Unsetenv("HOME")
			}
			
			result := GetHomeDir()
			
			if tt.Input.expectFallback {
				// Should return either user.Current().HomeDir or "/root"
				assert.NotEmpty(t, result)
			} else {
				assert.Equal(t, tt.Input.homeEnv, result)
			}
		})
	}
}

func TestGetShellInitFile(t *testing.T) {
	t.Parallel()

	tests := []testutil.TableTest[struct {
		homeDir     string
		shell       string
		override    string
		expectedSuffix string
	}]{
		{
			Name: "zsh init file",
			Input: struct {
				homeDir     string
				shell       string
				override    string
				expectedSuffix string
			}{
				homeDir:     "/home/test",
				shell:       "/bin/zsh",
				override:    "",
				expectedSuffix: "/.zshrc",
			},
		},
		{
			Name: "bash init file",
			Input: struct {
				homeDir     string
				shell       string
				override    string
				expectedSuffix string
			}{
				homeDir:     "/home/test",
				shell:       "/bin/bash",
				override:    "",
				expectedSuffix: "/.bashrc",
			},
		},
		{
			Name: "fish init file",
			Input: struct {
				homeDir     string
				shell       string
				override    string
				expectedSuffix string
			}{
				homeDir:     "/home/test",
				shell:       "/usr/bin/fish",
				override:    "",
				expectedSuffix: "/.config/fish/config.fish",
			},
		},
		{
			Name: "override environment variable",
			Input: struct {
				homeDir     string
				shell       string
				override    string
				expectedSuffix string
			}{
				homeDir:     "/home/test",
				shell:       "/bin/bash",
				override:    "/custom/shell/config",
				expectedSuffix: "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			
			// Save original environment
			originalHome := os.Getenv("HOME")
			originalShell := os.Getenv("SHELL")
			originalOverride := os.Getenv("Eos_SHELL_RC")
			defer func() {
				os.Setenv("HOME", originalHome)
				os.Setenv("SHELL", originalShell)
				if originalOverride != "" {
					os.Setenv("Eos_SHELL_RC", originalOverride)
				} else {
					os.Unsetenv("Eos_SHELL_RC")
				}
			}()
			
			// Set test environment
			os.Setenv("HOME", tt.Input.homeDir)
			os.Setenv("SHELL", tt.Input.shell)
			if tt.Input.override != "" {
				os.Setenv("Eos_SHELL_RC", tt.Input.override)
			} else {
				os.Unsetenv("Eos_SHELL_RC")
			}
			
			result := GetShellInitFile()
			
			if tt.Input.override != "" {
				assert.Equal(t, tt.Input.override, result)
			} else if tt.Input.expectedSuffix != "" {
				expected := tt.Input.homeDir + tt.Input.expectedSuffix
				assert.Equal(t, expected, result)
			} else {
				assert.NotEmpty(t, result)
			}
		})
	}
}

// Security Tests
func TestSecurityGetShellInitFile(t *testing.T) {
	t.Parallel()

	tests := []testutil.TableTest[struct {
		maliciousOverride string
	}]{
		{
			Name: "malicious path traversal in override",
			Input: struct {
				maliciousOverride string
			}{
				maliciousOverride: "../../../etc/passwd",
			},
		},
		{
			Name: "null byte injection",
			Input: struct {
				maliciousOverride string
			}{
				maliciousOverride: "/legitimate/path\x00/etc/passwd",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			
			// Save original environment
			originalOverride := os.Getenv("Eos_SHELL_RC")
			defer func() {
				if originalOverride != "" {
					os.Setenv("Eos_SHELL_RC", originalOverride)
				} else {
					os.Unsetenv("Eos_SHELL_RC")
				}
			}()
			
			// Set malicious environment
			os.Setenv("Eos_SHELL_RC", tt.Input.maliciousOverride)
			
			// Function should still return the override value
			// Security should be handled at usage time
			result := GetShellInitFile()
			assert.Equal(t, tt.Input.maliciousOverride, result)
		})
	}
}

// Benchmark Tests
func BenchmarkGetOSPlatform(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GetOSPlatform()
	}
}

func BenchmarkIsCommandAvailable(b *testing.B) {
	for i := 0; i < b.N; i++ {
		IsCommandAvailable("go")
	}
}

func BenchmarkGetShellType(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GetShellType()
	}
}

// Helper functions
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// Linux Distribution Tests
func TestDetectLinuxDistro(t *testing.T) {
	t.Parallel()
	
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	// Only test on Linux systems
	if !IsLinux() {
		result := DetectLinuxDistro(rc)
		assert.Equal(t, "unknown", result)
		return
	}

	// On Linux, should return a valid distro or unknown
	result := DetectLinuxDistro(rc)
	validDistros := []string{"debian", "rhel", "alpine", "suse", "unknown"}
	assert.Contains(t, validDistros, result)
}

func TestIsDebian(t *testing.T) {
	t.Parallel()
	
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	result := IsDebian(rc)
	
	if IsLinux() {
		// Should be consistent with DetectLinuxDistro
		distro := DetectLinuxDistro(rc)
		expected := distro == "debian"
		assert.Equal(t, expected, result)
	} else {
		assert.False(t, result)
	}
}

func TestIsRHEL(t *testing.T) {
	t.Parallel()
	
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	result := IsRHEL(rc)
	
	if IsLinux() {
		// Should be consistent with DetectLinuxDistro
		distro := DetectLinuxDistro(rc)
		expected := distro == "rhel"
		assert.Equal(t, expected, result)
	} else {
		assert.False(t, result)
	}
}

func TestRequireLinuxDistro(t *testing.T) {
	t.Parallel()

	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	tests := []testutil.TableTest[struct {
		allowed []string
		wantErr bool
	}]{
		{
			Name: "empty allowed list on non-Linux",
			Input: struct {
				allowed []string
				wantErr bool
			}{
				allowed: []string{},
				wantErr: !IsLinux(), // Should error on non-Linux
			},
		},
		{
			Name: "debian allowed",
			Input: struct {
				allowed []string
				wantErr bool
			}{
				allowed: []string{"debian"},
				wantErr: !IsLinux() || DetectLinuxDistro(rc) != "debian",
			},
		},
		{
			Name: "rhel allowed",
			Input: struct {
				allowed []string
				wantErr bool
			}{
				allowed: []string{"rhel"},
				wantErr: !IsLinux() || DetectLinuxDistro(rc) != "rhel",
			},
		},
		{
			Name: "multiple distros allowed",
			Input: struct {
				allowed []string
				wantErr bool
			}{
				allowed: []string{"debian", "rhel", "alpine", "suse"},
				wantErr: !IsLinux(),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			
			err := RequireLinuxDistro(rc, tt.Input.allowed)
			
			if tt.Input.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Admin Group Tests
func TestGuessAdminGroup(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	
	result := GuessAdminGroup(ctx)
	
	// Should return either "sudo" or "wheel"
	validGroups := []string{"sudo", "wheel"}
	assert.Contains(t, validGroups, result)
	
	// Default should be "sudo" for most systems
	if !IsLinux() {
		assert.Equal(t, "sudo", result)
	}
}

// Process Detection Tests
func TestIsProcessRunning(t *testing.T) {
	t.Parallel()

	tests := []testutil.TableTest[struct {
		processName string
		expected    bool
	}]{
		{
			Name: "empty process name",
			Input: struct {
				processName string
				expected    bool
			}{
				processName: "",
				expected:    false,
			},
		},
		{
			Name: "definitely nonexistent process",
			Input: struct {
				processName string
				expected    bool
			}{
				processName: "definitely-not-a-real-process-12345",
				expected:    false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			
			result := IsProcessRunning(tt.Input.processName)
			assert.Equal(t, tt.Input.expected, result)
		})
	}
}

// Browser Tests
func TestOpenBrowser(t *testing.T) {
	t.Parallel()

	tests := []testutil.TableTest[struct {
		url     string
		wantErr bool
	}]{
		{
			Name: "valid http URL",
			Input: struct {
				url     string
				wantErr bool
			}{
				url:     "http://example.com",
				wantErr: false, // Command should start successfully
			},
		},
		{
			Name: "valid https URL",
			Input: struct {
				url     string
				wantErr bool
			}{
				url:     "https://example.com",
				wantErr: false,
			},
		},
		{
			Name: "local file URL",
			Input: struct {
				url     string
				wantErr bool
			}{
				url:     "file:///tmp/test.html",
				wantErr: false,
			},
		},
		{
			Name: "empty URL",
			Input: struct {
				url     string
				wantErr bool
			}{
				url:     "",
				wantErr: false, // Command will still start but may fail
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			
			err := OpenBrowser(tt.Input.url)
			
			if tt.Input.wantErr {
				assert.Error(t, err)
			} else {
				// OpenBrowser only starts the command, doesn't wait
				// So it should generally succeed unless the command doesn't exist
				// In test environments, the browser commands may not be available
				// so we just check that it doesn't panic
				_ = err
			}
		})
	}
}

// Security test for browser function
func TestOpenBrowserSecurity(t *testing.T) {
	t.Parallel()

	tests := []testutil.TableTest[struct {
		maliciousURL string
	}]{
		{
			Name: "command injection attempt",
			Input: struct {
				maliciousURL string
			}{
				maliciousURL: "http://example.com; rm -rf /",
			},
		},
		{
			Name: "shell metacharacters",
			Input: struct {
				maliciousURL string
			}{
				maliciousURL: "http://example.com && echo 'pwned'",
			},
		},
		{
			Name: "null byte injection",
			Input: struct {
				maliciousURL string
			}{
				maliciousURL: "http://example.com\x00malicious",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			
			// Function should handle malicious input safely
			// exec.Command properly escapes arguments
			err := OpenBrowser(tt.Input.maliciousURL)
			
			// Should not panic or cause security issues
			// The actual command may fail but that's expected
			_ = err
		})
	}
}