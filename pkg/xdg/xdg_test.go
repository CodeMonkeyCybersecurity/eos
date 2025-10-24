// pkg/xdg/xdg_test.go - Comprehensive tests for XDG directory handling
package xdg

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestGetEnvOrDefault tests environment variable handling
func TestGetEnvOrDefault(t *testing.T) {
	tests := []struct {
		name         string
		envVar       string
		envValue     string
		fallback     string
		expected     string
		shouldSetEnv bool
	}{
		{
			name:         "env_var_set",
			envVar:       "TEST_XDG_VAR",
			envValue:     "/custom/path",
			fallback:     "/default/path",
			expected:     "/custom/path",
			shouldSetEnv: true,
		},
		{
			name:         "env_var_not_set",
			envVar:       "UNSET_XDG_VAR",
			envValue:     "",
			fallback:     "/default/path",
			expected:     "/default/path",
			shouldSetEnv: false,
		},
		{
			name:         "empty_env_var",
			envVar:       "EMPTY_XDG_VAR",
			envValue:     "",
			fallback:     "/fallback",
			expected:     "/fallback",
			shouldSetEnv: true,
		},
		{
			name:         "whitespace_env_var",
			envVar:       "WHITESPACE_XDG_VAR",
			envValue:     "   ",
			fallback:     "/fallback",
			expected:     "   ", // Returns whitespace as-is
			shouldSetEnv: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clean up any existing env var
			_ = os.Unsetenv(tt.envVar)
			defer os.Unsetenv(tt.envVar)

			if tt.shouldSetEnv {
				_ = os.Setenv(tt.envVar, tt.envValue)
			}

			result := GetEnvOrDefault(tt.envVar, tt.fallback)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestXDGConfigPath tests XDG config directory resolution
func TestXDGConfigPath(t *testing.T) {
	// Save original env vars
	origConfigHome := os.Getenv("XDG_CONFIG_HOME")
	origHome := os.Getenv("HOME")
	defer func() {
		_ = os.Setenv("XDG_CONFIG_HOME", origConfigHome)
		_ = os.Setenv("HOME", origHome)
	}()

	tests := []struct {
		name          string
		xdgConfigHome string
		homeDir       string
		app           string
		file          string
		expectedPath  string
		skipOnWindows bool
	}{
		{
			name:          "custom_xdg_config_home",
			xdgConfigHome: "/custom/config",
			homeDir:       "/home/user",
			app:           "myapp",
			file:          "config.json",
			expectedPath:  "/custom/config/myapp/config.json",
		},
		{
			name:          "default_config_location",
			xdgConfigHome: "",
			homeDir:       "/home/user",
			app:           "testapp",
			file:          "settings.toml",
			expectedPath:  "/home/user/.config/testapp/settings.toml",
			skipOnWindows: true,
		},
		{
			name:          "empty_app_name",
			xdgConfigHome: "/config",
			homeDir:       "/home/user",
			app:           "",
			file:          "file.conf",
			expectedPath:  "/config/file.conf",
		},
		{
			name:          "empty_file_name",
			xdgConfigHome: "/config",
			homeDir:       "/home/user",
			app:           "app",
			file:          "",
			expectedPath:  "/config/app",
		},
		{
			name:          "path_with_subdirs",
			xdgConfigHome: "/config",
			homeDir:       "/home/user",
			app:           "complex/app",
			file:          "sub/dir/config.yml",
			expectedPath:  "/config/complex/app/sub/dir/config.yml",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.skipOnWindows && runtime.GOOS == "windows" {
				t.Skip("Skipping test on Windows")
			}

			_ = os.Setenv("XDG_CONFIG_HOME", tt.xdgConfigHome)
			_ = os.Setenv("HOME", tt.homeDir)

			result := XDGConfigPath(tt.app, tt.file)

			// Handle Windows path separators
			if runtime.GOOS == "windows" {
				result = filepath.ToSlash(result)
				tt.expectedPath = filepath.ToSlash(tt.expectedPath)
			}

			assert.Equal(t, tt.expectedPath, result)
		})
	}
}

// TestXDGDataPath tests XDG data directory resolution
func TestXDGDataPath(t *testing.T) {
	origDataHome := os.Getenv("XDG_DATA_HOME")
	origHome := os.Getenv("HOME")
	defer func() {
		_ = os.Setenv("XDG_DATA_HOME", origDataHome)
		_ = os.Setenv("HOME", origHome)
	}()

	tests := []struct {
		name         string
		xdgDataHome  string
		homeDir      string
		app          string
		file         string
		expectedPath string
	}{
		{
			name:         "custom_xdg_data_home",
			xdgDataHome:  "/custom/data",
			homeDir:      "/home/user",
			app:          "myapp",
			file:         "database.db",
			expectedPath: "/custom/data/myapp/database.db",
		},
		{
			name:         "default_data_location",
			xdgDataHome:  "",
			homeDir:      "/home/user",
			app:          "testapp",
			file:         "storage.dat",
			expectedPath: "/home/user/.local/share/testapp/storage.dat",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = os.Setenv("XDG_DATA_HOME", tt.xdgDataHome)
			_ = os.Setenv("HOME", tt.homeDir)

			result := XDGDataPath(tt.app, tt.file)

			// Handle Windows path separators
			if runtime.GOOS == "windows" {
				result = filepath.ToSlash(result)
				tt.expectedPath = filepath.ToSlash(tt.expectedPath)
			}

			assert.Equal(t, tt.expectedPath, result)
		})
	}
}

// TestXDGCachePath tests XDG cache directory resolution
func TestXDGCachePath(t *testing.T) {
	origCacheHome := os.Getenv("XDG_CACHE_HOME")
	origHome := os.Getenv("HOME")
	defer func() {
		_ = os.Setenv("XDG_CACHE_HOME", origCacheHome)
		_ = os.Setenv("HOME", origHome)
	}()

	tests := []struct {
		name         string
		xdgCacheHome string
		homeDir      string
		app          string
		file         string
		expectedPath string
	}{
		{
			name:         "custom_xdg_cache_home",
			xdgCacheHome: "/custom/cache",
			homeDir:      "/home/user",
			app:          "myapp",
			file:         "temp.cache",
			expectedPath: "/custom/cache/myapp/temp.cache",
		},
		{
			name:         "default_cache_location",
			xdgCacheHome: "",
			homeDir:      "/home/user",
			app:          "testapp",
			file:         "downloads.cache",
			expectedPath: "/home/user/.cache/testapp/downloads.cache",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = os.Setenv("XDG_CACHE_HOME", tt.xdgCacheHome)
			_ = os.Setenv("HOME", tt.homeDir)

			result := XDGCachePath(tt.app, tt.file)

			// Handle Windows path separators
			if runtime.GOOS == "windows" {
				result = filepath.ToSlash(result)
				tt.expectedPath = filepath.ToSlash(tt.expectedPath)
			}

			assert.Equal(t, tt.expectedPath, result)
		})
	}
}

// TestXDGStatePath tests XDG state directory resolution
func TestXDGStatePath(t *testing.T) {
	origStateHome := os.Getenv("XDG_STATE_HOME")
	origHome := os.Getenv("HOME")
	defer func() {
		_ = os.Setenv("XDG_STATE_HOME", origStateHome)
		_ = os.Setenv("HOME", origHome)
	}()

	tests := []struct {
		name         string
		xdgStateHome string
		homeDir      string
		app          string
		file         string
		expectedPath string
	}{
		{
			name:         "custom_xdg_state_home",
			xdgStateHome: "/custom/state",
			homeDir:      "/home/user",
			app:          "myapp",
			file:         "state.json",
			expectedPath: "/custom/state/myapp/state.json",
		},
		{
			name:         "default_state_location",
			xdgStateHome: "",
			homeDir:      "/home/user",
			app:          "testapp",
			file:         "history.log",
			expectedPath: "/home/user/.local/state/testapp/history.log",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = os.Setenv("XDG_STATE_HOME", tt.xdgStateHome)
			_ = os.Setenv("HOME", tt.homeDir)

			result := XDGStatePath(tt.app, tt.file)

			// Handle Windows path separators
			if runtime.GOOS == "windows" {
				result = filepath.ToSlash(result)
				tt.expectedPath = filepath.ToSlash(tt.expectedPath)
			}

			assert.Equal(t, tt.expectedPath, result)
		})
	}
}

// TestXDGRuntimePath tests XDG runtime directory resolution
func TestXDGRuntimePath(t *testing.T) {
	origRuntimeDir := os.Getenv("XDG_RUNTIME_DIR")
	defer func() {
		_ = os.Setenv("XDG_RUNTIME_DIR", origRuntimeDir)
	}()

	tests := []struct {
		name          string
		xdgRuntimeDir string
		app           string
		file          string
		expectedPath  string
		expectError   bool
		errorContains string
	}{
		{
			name:          "valid_runtime_dir",
			xdgRuntimeDir: "/run/user/1000",
			app:           "myapp",
			file:          "socket",
			expectedPath:  "/run/user/1000/myapp/socket",
			expectError:   false,
		},
		{
			name:          "runtime_dir_not_set",
			xdgRuntimeDir: "",
			app:           "myapp",
			file:          "pid",
			expectedPath:  "",
			expectError:   true,
			errorContains: "XDG_RUNTIME_DIR not set",
		},
		{
			name:          "runtime_with_complex_path",
			xdgRuntimeDir: "/var/run/user/1000",
			app:           "complex/app",
			file:          "sub/socket.sock",
			expectedPath:  "/var/run/user/1000/complex/app/sub/socket.sock",
			expectError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = os.Setenv("XDG_RUNTIME_DIR", tt.xdgRuntimeDir)

			result, err := XDGRuntimePath(tt.app, tt.file)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
				assert.Empty(t, result)
			} else {
				assert.NoError(t, err)

				// Handle Windows path separators
				if runtime.GOOS == "windows" {
					result = filepath.ToSlash(result)
					tt.expectedPath = filepath.ToSlash(tt.expectedPath)
				}

				assert.Equal(t, tt.expectedPath, result)
			}
		})
	}
}

// TestPathTraversalPrevention tests that path traversal is handled safely
func TestPathTraversalPrevention(t *testing.T) {
	// Set up test environment
	_ = os.Setenv("XDG_CONFIG_HOME", "/safe/config")
	defer os.Unsetenv("XDG_CONFIG_HOME")

	tests := []struct {
		name     string
		app      string
		file     string
		testFunc func(string, string) string
	}{
		{
			name:     "config_path_traversal",
			app:      "../../../etc",
			file:     "passwd",
			testFunc: XDGConfigPath,
		},
		{
			name:     "data_path_traversal",
			app:      "app",
			file:     "../../../../../../etc/shadow",
			testFunc: XDGDataPath,
		},
		{
			name:     "cache_path_traversal",
			app:      ".",
			file:     "../sensitive/data",
			testFunc: XDGCachePath,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.testFunc(tt.app, tt.file)

			// The function should return the path as-is (no sanitization)
			// This test documents the current behavior - path traversal is NOT prevented
			assert.Contains(t, result, "..")

			// This is a security issue that should be addressed
			t.Log("WARNING: Path traversal is not prevented in XDG path functions")
		})
	}
}

// TestConcurrentAccess tests thread safety of XDG functions
func TestConcurrentAccess(t *testing.T) {
	// Set up environment
	_ = os.Setenv("XDG_CONFIG_HOME", "/concurrent/config")
	_ = os.Setenv("HOME", "/home/concurrent")
	defer func() {
		_ = os.Unsetenv("XDG_CONFIG_HOME")
		_ = os.Unsetenv("HOME")
	}()

	const goroutines = 50

	// Test concurrent reads
	t.Run("concurrent_path_resolution", func(t *testing.T) {
		results := make([]string, goroutines)
		done := make(chan bool, goroutines)

		for i := 0; i < goroutines; i++ {
			go func(idx int) {
				results[idx] = XDGConfigPath("testapp", "config.json")
				done <- true
			}(i)
		}

		// Wait for all goroutines
		for i := 0; i < goroutines; i++ {
			<-done
		}

		// All results should be identical
		expected := results[0]
		for i := 1; i < goroutines; i++ {
			assert.Equal(t, expected, results[i])
		}
	})

	// Test concurrent environment changes
	t.Run("concurrent_env_changes", func(t *testing.T) {
		done := make(chan bool, goroutines)

		for i := 0; i < goroutines; i++ {
			go func(idx int) {
				if idx%2 == 0 {
					_ = os.Setenv("XDG_CONFIG_HOME", "/changed/config")
				} else {
					_ = XDGConfigPath("app", "file")
				}
				done <- true
			}(i)
		}

		// Wait for all goroutines
		for i := 0; i < goroutines; i++ {
			<-done
		}

		// No assertion - just ensure no panic/race
	})
}

// TestEdgeCases tests various edge cases
func TestEdgeCases(t *testing.T) {
	t.Run("missing_home_env", func(t *testing.T) {
		// Save and unset HOME
		origHome := os.Getenv("HOME")
		_ = os.Unsetenv("HOME")
		_ = os.Unsetenv("XDG_CONFIG_HOME")
		defer func() { _ = os.Setenv("HOME", origHome) }()

		// Should still work but with empty base
		result := XDGConfigPath("app", "config")
		assert.Contains(t, result, filepath.Join("", ".config", "app", "config"))
	})

	t.Run("special_characters_in_paths", func(t *testing.T) {
		_ = os.Setenv("XDG_CONFIG_HOME", "/config")
		defer os.Unsetenv("XDG_CONFIG_HOME")

		specialCases := []struct {
			app  string
			file string
		}{
			{app: "app with spaces", file: "file with spaces.txt"},
			{app: "app-with-dashes", file: "file-name.conf"},
			{app: "app_with_underscores", file: "file_name.yml"},
			{app: "app.with.dots", file: "file.with.dots.json"},
			{app: "app@special", file: "file#special!.dat"},
		}

		for _, sc := range specialCases {
			result := XDGConfigPath(sc.app, sc.file)
			// Should handle special characters without modification
			assert.Contains(t, result, sc.app)
			assert.Contains(t, result, sc.file)
		}
	})

	t.Run("very_long_paths", func(t *testing.T) {
		_ = os.Setenv("XDG_CONFIG_HOME", "/config")
		defer os.Unsetenv("XDG_CONFIG_HOME")

		// Test with very long app and file names
		longApp := strings.Repeat("a", 255)
		longFile := strings.Repeat("b", 255) + ".conf"

		result := XDGConfigPath(longApp, longFile)
		assert.Contains(t, result, longApp)
		assert.Contains(t, result, longFile)

		// Note: The function doesn't validate path length limits
		t.Log("WARNING: Path length limits are not enforced")
	})
}

// BenchmarkXDGPaths benchmarks path resolution performance
func BenchmarkXDGPaths(b *testing.B) {
	_ = os.Setenv("XDG_CONFIG_HOME", "/bench/config")
	_ = os.Setenv("HOME", "/home/bench")
	defer func() {
		_ = os.Unsetenv("XDG_CONFIG_HOME")
		_ = os.Unsetenv("HOME")
	}()

	b.Run("ConfigPath", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = XDGConfigPath("benchapp", "config.json")
		}
	})

	b.Run("DataPath", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = XDGDataPath("benchapp", "data.db")
		}
	})

	b.Run("RuntimePath", func(b *testing.B) {
		_ = os.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
		defer os.Unsetenv("XDG_RUNTIME_DIR")

		for i := 0; i < b.N; i++ {
			_, _ = XDGRuntimePath("benchapp", "socket")
		}
	})
}
