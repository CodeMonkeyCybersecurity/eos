// pkg/security/input_sanitizer_test.go

package security

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestInputSanitizer_CSIVulnerability(t *testing.T) {
	sanitizer := NewInputSanitizer()

	// Test the critical CSI vulnerability (0x9b)
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "standalone CSI character",
			input:    string(rune(0x9b)),
			expected: "",
		},
		{
			name:     "CSI with text",
			input:    "hello" + string(rune(0x9b)) + "world",
			expected: "helloworld",
		},
		{
			name:     "multiple CSI characters",
			input:    string(rune(0x9b)) + string(rune(0x9b)) + "test" + string(rune(0x9b)),
			expected: "test",
		},
		{
			name:     "CSI in ANSI sequence",
			input:    string(rune(0x9b)) + "[31mred text",
			expected: "[31mred text", // CSI removed but content preserved
		},
		{
			name:     "ESC sequences",
			input:    "\x1b[31mred\x1b[0m normal",
			expected: "red normal",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := sanitizer.SanitizeInput(tc.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, result)
			}

			// Ensure no CSI characters remain
			if strings.ContainsRune(result, CSI) {
				t.Errorf("CSI character still present in result: %q", result)
			}
		})
	}
}

func TestInputSanitizer_UTF8Validation(t *testing.T) {
	sanitizer := NewInputSanitizer()

	testCases := []struct {
		name      string
		input     string
		expectErr bool
		checkUTF8 bool
	}{
		{
			name:      "valid UTF-8",
			input:     "Hello, 世界! ",
			expectErr: false,
			checkUTF8: true,
		},
		{
			name:      "invalid UTF-8 sequence",
			input:     "Hello\xff\xfeWorld",
			expectErr: false, // Should be fixed, not error
			checkUTF8: true,
		},
		{
			name:      "truncated UTF-8",
			input:     "Hello\xc2", // Incomplete 2-byte sequence
			expectErr: false,
			checkUTF8: true,
		},
		{
			name:      "overlong encoding",
			input:     "Hello\xc0\x80World", // Overlong encoding of null
			expectErr: false,
			checkUTF8: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := sanitizer.SanitizeInput(tc.input)

			if tc.expectErr && err == nil {
				t.Errorf("expected error but got none")
			}
			if !tc.expectErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			if tc.checkUTF8 && !utf8.ValidString(result) {
				t.Errorf("result is not valid UTF-8: %q", result)
			}
		})
	}
}

func TestInputSanitizer_ControlCharacters(t *testing.T) {
	sanitizer := NewInputSanitizer()

	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "null bytes",
			input:    "hello\x00world",
			expected: "helloworld",
		},
		{
			name:     "bell character",
			input:    "alert\x07sound",
			expected: "alertsound",
		},
		{
			name:     "backspace",
			input:    "test\x08ing",
			expected: "testing",
		},
		{
			name:     "form feed",
			input:    "page\x0cbreak",
			expected: "pagebreak",
		},
		{
			name:     "vertical tab",
			input:    "vertical\x0btab",
			expected: "verticaltab",
		},
		{
			name:     "preserve newlines and tabs",
			input:    "line1\nline2\tcolumn2",
			expected: "line1\nline2\tcolumn2",
		},
		{
			name:     "DEL character",
			input:    "test\x7fdelete",
			expected: "testdelete",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := sanitizer.SanitizeInput(tc.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, result)
			}
		})
	}
}

func TestInputSanitizer_ANSISequences(t *testing.T) {
	sanitizer := NewInputSanitizer()

	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "color codes",
			input:    "\x1b[31mRed text\x1b[0m",
			expected: "Red text",
		},
		{
			name:     "cursor movement",
			input:    "\x1b[2Jclear screen\x1b[H",
			expected: "clear screen",
		},
		{
			name:     "complex ANSI",
			input:    "\x1b[1;31;40mBold red on black\x1b[0m",
			expected: "Bold red on black",
		},
		{
			name:     "operating system command",
			input:    "\x1b]0;Terminal Title\x07",
			expected: "", // Security: OSC sequences completely removed
		},
		{
			name:     "device control string",
			input:    "\x1bP+q544e\x1b\\",
			expected: "", // Security: DCS sequences completely removed
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := sanitizer.SanitizeInput(tc.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, result)
			}
		})
	}
}

func TestInputSanitizer_LengthLimits(t *testing.T) {
	sanitizer := NewInputSanitizer()

	// Test maximum length enforcement
	longInput := strings.Repeat("A", MaxInputLength+1)
	_, err := sanitizer.SanitizeInput(longInput)
	if err == nil {
		t.Errorf("expected error for input exceeding max length")
	}

	// Test at the limit
	limitInput := strings.Repeat("A", MaxInputLength)
	result, err := sanitizer.SanitizeInput(limitInput)
	if err != nil {
		t.Errorf("unexpected error for input at max length: %v", err)
	}
	if len(result) != MaxInputLength {
		t.Errorf("expected length %d, got %d", MaxInputLength, len(result))
	}
}

func TestInputSanitizer_ArgumentValidation(t *testing.T) {
	sanitizer := NewInputSanitizer()

	// Test too many arguments
	tooManyArgs := make([]string, MaxArgumentCount+1)
	for i := range tooManyArgs {
		tooManyArgs[i] = "arg"
	}

	_, err := sanitizer.SanitizeArguments(tooManyArgs)
	if err == nil {
		t.Errorf("expected error for too many arguments")
	}

	// Test normal arguments with dangerous content
	dangerousArgs := []string{
		"normal",
		"with\x9bCSI",
		"with\x1b[31mcolor",
		"with\x00null",
	}

	cleaned, err := sanitizer.SanitizeArguments(dangerousArgs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := []string{
		"normal",
		"withCSI", // CSI character removed
		"withcolor",
		"withnull",
	}

	for i, arg := range cleaned {
		if arg != expected[i] {
			t.Errorf("argument %d: expected %q, got %q", i, expected[i], arg)
		}
	}
}

func TestInputSanitizer_StrictMode(t *testing.T) {
	sanitizer := NewStrictSanitizer()

	testCases := []struct {
		name      string
		input     string
		expectErr bool
	}{
		{
			name:      "command injection attempt",
			input:     "innocent; rm -rf /",
			expectErr: true,
		},
		{
			name:      "shell evaluation",
			input:     "$(whoami)",
			expectErr: true,
		},
		{
			name:      "backtick command",
			input:     "`id`",
			expectErr: true,
		},
		{
			name:      "environment variable",
			input:     "${HOME}",
			expectErr: true,
		},
		{
			name:      "logical operators",
			input:     "cmd1 && cmd2",
			expectErr: true,
		},
		{
			name:      "normal text",
			input:     "hello world",
			expectErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := sanitizer.SanitizeInput(tc.input)

			if tc.expectErr && err == nil {
				t.Errorf("expected error for dangerous input: %q", tc.input)
			}
			if !tc.expectErr && err != nil {
				t.Errorf("unexpected error for safe input %q: %v", tc.input, err)
			}
		})
	}
}

func TestInputSanitizer_UnicodeNormalization(t *testing.T) {
	sanitizer := NewInputSanitizer()

	// Test Unicode normalization to prevent homograph attacks
	testCases := []struct {
		name  string
		input string
	}{
		{
			name:  "combining characters",
			input: "e\u0301", // e + combining acute accent
		},
		{
			name:  "precomposed character",
			input: "\u00e9", // é (precomposed)
		},
	}

	var results []string
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := sanitizer.SanitizeInput(tc.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			results = append(results, result)
		})
	}

	// After normalization, both should be the same
	if len(results) == 2 && results[0] != results[1] {
		t.Errorf("Unicode normalization failed: %q != %q", results[0], results[1])
	}
}

func TestEscapeOutput(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "safe output",
			input:    "normal output",
			expected: "normal output",
		},
		{
			name:     "output with CSI",
			input:    "dangerous\x9boutput",
			expected: "dangerousoutput",
		},
		{
			name:     "output with ANSI",
			input:    "\x1b[31merror\x1b[0m",
			expected: "error",
		},
		{
			name:     "empty output",
			input:    "",
			expected: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := EscapeOutput(tc.input)
			if result != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, result)
			}
		})
	}
}

func TestEscapeForLogging(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "newlines escaped",
			input:    "line1\nline2",
			expected: "line1\\nline2",
		},
		{
			name:     "carriage returns escaped",
			input:    "line1\rline2",
			expected: "line1\\rline2",
		},
		{
			name:     "tabs escaped",
			input:    "col1\tcol2",
			expected: "col1\\tcol2",
		},
		{
			name:     "control characters removed",
			input:    "test\x00\x07data",
			expected: "testdata",
		},
		{
			name:     "long input truncated",
			input:    strings.Repeat("A", 600),
			expected: strings.Repeat("A", 500) + "...[TRUNCATED]",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := EscapeForLogging(tc.input)
			if result != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, result)
			}
		})
	}
}

func TestValidateCommandName(t *testing.T) {
	testCases := []struct {
		name      string
		input     string
		expectErr bool
	}{
		{
			name:      "valid command",
			input:     "create",
			expectErr: false,
		},
		{
			name:      "command with dash",
			input:     "sub-command",
			expectErr: false,
		},
		{
			name:      "command with underscore",
			input:     "sub_command",
			expectErr: false,
		},
		{
			name:      "empty command",
			input:     "",
			expectErr: true,
		},
		{
			name:      "command with space",
			input:     "bad command",
			expectErr: true,
		},
		{
			name:      "command with special chars",
			input:     "bad$command",
			expectErr: true,
		},
		{
			name:      "too long command",
			input:     strings.Repeat("a", 101),
			expectErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateCommandName(tc.input)

			if tc.expectErr && err == nil {
				t.Errorf("expected error for command name: %q", tc.input)
			}
			if !tc.expectErr && err != nil {
				t.Errorf("unexpected error for command name %q: %v", tc.input, err)
			}
		})
	}
}

func TestValidateFlagName(t *testing.T) {
	testCases := []struct {
		name      string
		input     string
		expectErr bool
	}{
		{
			name:      "valid flag",
			input:     "verbose",
			expectErr: false,
		},
		{
			name:      "flag with dash",
			input:     "dry-run",
			expectErr: false,
		},
		{
			name:      "empty flag",
			input:     "",
			expectErr: true,
		},
		{
			name:      "flag starting with number",
			input:     "2verbose",
			expectErr: true,
		},
		{
			name:      "flag with underscore",
			input:     "bad_flag",
			expectErr: true,
		},
		{
			name:      "too long flag",
			input:     strings.Repeat("a", 51),
			expectErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateFlagName(tc.input)

			if tc.expectErr && err == nil {
				t.Errorf("expected error for flag name: %q", tc.input)
			}
			if !tc.expectErr && err != nil {
				t.Errorf("unexpected error for flag name %q: %v", tc.input, err)
			}
		})
	}
}

// Benchmark tests for performance
func BenchmarkSanitizeInput(b *testing.B) {
	sanitizer := NewInputSanitizer()
	input := "normal text with some\x1b[31mcolors\x1b[0m and unicode: "

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = sanitizer.SanitizeInput(input)
	}
}

func BenchmarkSanitizeInputWithCSI(b *testing.B) {
	sanitizer := NewInputSanitizer()
	input := "text with CSI" + string(rune(0x9b)) + "characters"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = sanitizer.SanitizeInput(input)
	}
}

func BenchmarkEscapeOutput(b *testing.B) {
	input := "output with\x1b[31mcolor\x1b[0m and CSI" + string(rune(0x9b))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = EscapeOutput(input)
	}
}
