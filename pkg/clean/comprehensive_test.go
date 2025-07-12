package clean

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSanitizeName_BasicFunctionality(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "normal filename",
			input:    "document.txt",
			expected: "document.txt",
		},
		{
			name:     "filename with forbidden chars",
			input:    "file<name>.txt",
			expected: "file_name_.txt",
		},
		{
			name:     "filename with colon",
			input:    "file:name.txt",
			expected: "file_name.txt",
		},
		{
			name:     "filename with quotes",
			input:    `file"name".txt`,
			expected: "file_name_.txt",
		},
		{
			name:     "filename with forward slash",
			input:    "file/name.txt",
			expected: "file_name.txt",
		},
		{
			name:     "filename with backslash",
			input:    "file\\name.txt",
			expected: "file_name.txt",
		},
		{
			name:     "filename with pipe",
			input:    "file|name.txt",
			expected: "file_name.txt",
		},
		{
			name:     "filename with question mark",
			input:    "file?name.txt",
			expected: "file_name.txt",
		},
		{
			name:     "filename with asterisk",
			input:    "file*name.txt",
			expected: "file_name.txt",
		},
		{
			name:     "multiple forbidden chars",
			input:    "file<>:\"/\\|?*.txt",
			expected: "file_________.txt",
		},
		{
			name:     "trailing spaces",
			input:    "filename.txt   ",
			expected: "filename.txt",
		},
		{
			name:     "trailing dots",
			input:    "filename...",
			expected: "filename",
		},
		{
			name:     "trailing spaces and dots",
			input:    "filename ... ",
			expected: "filename",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "_",
		},
		{
			name:     "only forbidden chars",
			input:    "<>:|?*",
			expected: "______",
		},
		{
			name:     "only spaces",
			input:    "   ",
			expected: "_",
		},
		{
			name:     "only dots",
			input:    "...",
			expected: "_",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeName(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSanitizeName_ReservedNames(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "CON device",
			input:    "CON",
			expected: "CON_file",
		},
		{
			name:     "con lowercase",
			input:    "con",
			expected: "con_file",
		},
		{
			name:     "PRN device",
			input:    "PRN",
			expected: "PRN_file",
		},
		{
			name:     "AUX device",
			input:    "AUX",
			expected: "AUX_file",
		},
		{
			name:     "NUL device",
			input:    "NUL",
			expected: "NUL_file",
		},
		{
			name:     "COM1 port",
			input:    "COM1",
			expected: "COM1_file",
		},
		{
			name:     "COM9 port",
			input:    "COM9",
			expected: "COM9_file",
		},
		{
			name:     "LPT1 port",
			input:    "LPT1",
			expected: "LPT1_file",
		},
		{
			name:     "LPT9 port",
			input:    "LPT9",
			expected: "LPT9_file",
		},
		{
			name:     "CON with extension",
			input:    "CON.txt",
			expected: "CON.txt", // Extension makes it safe
		},
		{
			name:     "PRN with extension",
			input:    "PRN.log",
			expected: "PRN.log",
		},
		{
			name:     "CON with spaces",
			input:    "CON   ",
			expected: "CON_file",
		},
		{
			name:     "CON with dots",
			input:    "CON...",
			expected: "CON_file",
		},
		{
			name:     "Not reserved - CONX",
			input:    "CONX",
			expected: "CONX",
		},
		{
			name:     "Not reserved - CONN",
			input:    "CONN",
			expected: "CONN",
		},
		{
			name:     "Not reserved - 1CON",
			input:    "1CON",
			expected: "1CON",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeName(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSanitizeName_Idempotency(t *testing.T) {
	// Test that sanitizing a name twice gives the same result
	inputs := []string{
		"normal.txt",
		"file<>name.txt",
		"CON",
		"PRN.txt",
		"   spaces   ",
		"dots...",
		"<>:\"/\\|?*",
		"",
	}

	for _, input := range inputs {
		first := SanitizeName(input)
		second := SanitizeName(first)
		assert.Equal(t, first, second, "Sanitization should be idempotent for input: %q", input)
	}
}

func TestForbiddenRegexp(t *testing.T) {
	// Test the forbidden regexp directly
	testCases := []struct {
		char     string
		expected bool
	}{
		{"<", true},
		{">", true},
		{":", true},
		{"\"", true},
		{"/", true},
		{"\\", true},
		{"|", true},
		{"?", true},
		{"*", true},
		{"a", false},
		{"1", false},
		{"-", false},
		{"_", false},
		{".", false},
		{" ", false},
	}

	for _, tc := range testCases {
		matches := forbidden.MatchString(tc.char)
		assert.Equal(t, tc.expected, matches, "Character %q", tc.char)
	}
}

func TestReservedMap(t *testing.T) {
	// Verify all expected reserved names are in the map
	expectedReserved := []string{
		"CON", "PRN", "AUX", "NUL",
		"COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
		"LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
	}

	for _, name := range expectedReserved {
		assert.True(t, reserved[name], "Expected %q to be reserved", name)
	}

	// Verify count
	assert.Equal(t, 22, len(reserved), "Expected 22 reserved names")

	// Verify non-reserved names
	notReserved := []string{"COM", "LPT", "COM10", "LPT10", "CONN", "NULX"}
	for _, name := range notReserved {
		assert.False(t, reserved[name], "Expected %q to NOT be reserved", name)
	}
}

func TestRenameIfNeeded(t *testing.T) {
	// Create a temporary directory for testing
	tempDir := t.TempDir()

	tests := []struct {
		name          string
		filename      string
		shouldRename  bool
		expectedName  string
	}{
		{
			name:          "normal file",
			filename:      "normal.txt",
			shouldRename:  false,
			expectedName:  "normal.txt",
		},
		{
			name:          "file with forbidden chars",
			filename:      "file<name>.txt",
			shouldRename:  true,
			expectedName:  "file_name_.txt",
		},
		{
			name:          "reserved name",
			filename:      "CON",
			shouldRename:  true,
			expectedName:  "CON_file",
		},
		{
			name:          "reserved with extension",
			filename:      "PRN.txt",
			shouldRename:  false,
			expectedName:  "PRN.txt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test file
			oldPath := filepath.Join(tempDir, tt.filename)
			err := os.WriteFile(oldPath, []byte("test"), 0644)
			require.NoError(t, err)

			// Capture stdout to check output
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			// Run RenameIfNeeded
			err = RenameIfNeeded(oldPath)
			require.NoError(t, err)

			// Restore stdout
			_ = w.Close()
			os.Stdout = oldStdout
			var output strings.Builder
			_, _ = fmt.Fscan(r, &output)

			// Check if file was renamed
			expectedPath := filepath.Join(tempDir, tt.expectedName)
			
			if tt.shouldRename {
				// File should be renamed
				_, err = os.Stat(expectedPath)
				assert.NoError(t, err, "Renamed file should exist")
				
				// Original should not exist if name changed
				if tt.filename != tt.expectedName {
					_, err = os.Stat(oldPath)
					assert.True(t, os.IsNotExist(err), "Original file should not exist")
				}
			} else {
				// File should not be renamed
				_, err = os.Stat(oldPath)
				assert.NoError(t, err, "Original file should still exist")
			}

			// Clean up
			_ = os.Remove(oldPath)
			_ = os.Remove(expectedPath)
		})
	}
}

func TestWalkAndSanitize_ErrorHandling(t *testing.T) {
	tests := []struct {
		name      string
		root      string
		wantError bool
	}{
		{
			name:      "non-existent directory",
			root:      "/non/existent/path",
			wantError: true,
		},
		{
			name:      "empty path",
			root:      "",
			wantError: true,
		},
		{
			name:      "current directory",
			root:      ".",
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := WalkAndSanitize(tt.root)
			if tt.wantError {
				assert.Error(t, err)
			}
			// For current directory, it might succeed or fail depending on permissions
			// We just check it doesn't panic
		})
	}
}

func TestUsage(t *testing.T) {
	// Usage calls os.Exit(1), so we can't test it directly
	// We'll just verify the function exists and document its behavior
	t.Skip("Usage() calls os.Exit(1) and cannot be tested directly")
}

func TestSanitizeName_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "very long filename",
			input:    strings.Repeat("a", 300),
			expected: strings.Repeat("a", 300), // No truncation in current implementation
		},
		{
			name:     "unicode characters",
			input:    "файл.txt",
			expected: "файл.txt",
		},
		{
			name:     "emoji",
			input:    "📁folder.txt",
			expected: "📁folder.txt",
		},
		{
			name:     "mixed case reserved",
			input:    "CoN",
			expected: "CoN_file",
		},
		{
			name:     "reserved with forbidden chars",
			input:    "CON<>",
			expected: "CON__",
		},
		{
			name:     "multiple extensions",
			input:    "file.tar.gz",
			expected: "file.tar.gz",
		},
		{
			name:     "hidden file",
			input:    ".hidden",
			expected: ".hidden",
		},
		{
			name:     "only extension",
			input:    ".txt",
			expected: ".txt",
		},
		{
			name:     "spaces between words",
			input:    "my document.txt",
			expected: "my document.txt",
		},
		{
			name:     "tabs and newlines",
			input:    "file\tname\n.txt",
			expected: "file\tname\n.txt", // Not currently sanitized
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeName(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestPathOperations(t *testing.T) {
	tests := []struct {
		name         string
		path         string
		expectedDir  string
		expectedBase string
	}{
		{
			name:         "absolute path",
			path:         "/home/user/file.txt",
			expectedDir:  "/home/user",
			expectedBase: "file.txt",
		},
		{
			name:         "relative path",
			path:         "folder/file.txt",
			expectedDir:  "folder",
			expectedBase: "file.txt",
		},
		{
			name:         "root file",
			path:         "/file.txt",
			expectedDir:  "/",
			expectedBase: "file.txt",
		},
		{
			name:         "current directory",
			path:         "file.txt",
			expectedDir:  ".",
			expectedBase: "file.txt",
		},
		{
			name:         "Windows path",
			path:         `C:\Users\file.txt`,
			expectedDir:  `C:\Users\file.txt`, // On unix, backslashes aren't treated as separators
			expectedBase: `C:\Users\file.txt`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := filepath.Dir(tt.path)
			base := filepath.Base(tt.path)
			
			assert.Equal(t, tt.expectedDir, dir)
			assert.Equal(t, tt.expectedBase, base)
			
			// Test how it would work in RenameIfNeeded
			sanitized := SanitizeName(base)
			newPath := filepath.Join(dir, sanitized)
			
			// Verify path construction
			// Skip platform-specific check for Windows paths on unix
			if !strings.Contains(tt.path, `\`) {
				assert.True(t, strings.HasPrefix(newPath, dir))
			}
		})
	}
}