// pkg/security/input_sanitizer_fuzz_test.go

package security

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzInputSanitizer tests the input sanitizer with fuzzing data
func FuzzInputSanitizer(f *testing.F) {
	// Seed with known dangerous inputs from fuzz testing results
	f.Add(string(rune(0x9b)))                    // CSI character
	f.Add("\x1b[31mtext\x1b[0m")                 // ANSI escape sequences
	f.Add("hello\x00world")                      // Null bytes
	f.Add("test\xff\xfedata")                    // Invalid UTF-8
	f.Add("\x1b]0;title\x07")                    // Operating system command
	f.Add("$(rm -rf /)")                         // Command injection
	f.Add("`whoami`")                            // Backtick command
	f.Add("normal text")                         // Normal input
	f.Add("")                                    // Empty input
	f.Add("emoji🌍test")                         // Unicode emoji
	f.Add("café")                                // Non-ASCII characters
	f.Add("\x1bP+q544e\x1b\\")                   // Device control string
	f.Add("\x9b[31m")                            // CSI with ANSI
	f.Add("line1\nline2\ttab")                   // Newlines and tabs
	f.Add("\x07\x08\x0C\x7F")                    // Various control chars
	f.Add("e\u0301")                             // Combining characters
	f.Add("\uFFFD")                              // Replacement character
	f.Add("\x1b_test\x1b\\")                     // Application program command
	f.Add("\x1b^privacy\x1b\\")                  // Privacy message
	f.Add("mixed\x9b\x1b[32mdata\x00end")        // Mixed dangerous content
	
	f.Fuzz(func(t *testing.T, input string) {
		// Ensure fuzz testing doesn't crash the sanitizer
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("InputSanitizer panicked with input %q: %v", input, r)
			}
		}()
		
		sanitizer := NewInputSanitizer()
		
		// Test normal sanitization
		result, err := sanitizer.SanitizeInput(input)
		
		// The sanitizer should never panic, even with malicious input
		if err != nil {
			// Errors are acceptable for malformed input, but no panics
			return
		}
		
		// Validate that the result is safe
		if !utf8.ValidString(result) {
			t.Errorf("Sanitizer produced invalid UTF-8: input=%q, result=%q", input, result)
		}
		
		// Ensure no CSI characters remain
		for _, r := range result {
			if r == CSI {
				t.Errorf("CSI character found in sanitized output: input=%q, result=%q", input, result)
			}
		}
		
		// Ensure no dangerous control characters remain (except \n and \t)
		for _, r := range result {
			if r < 32 && r != '\n' && r != '\t' {
				t.Errorf("Dangerous control character found: input=%q, result=%q, char=0x%02x", input, result, r)
			}
			if r >= 127 && r <= 159 && r != ReplacementChar {
				t.Errorf("Dangerous C1 control character found: input=%q, result=%q, char=0x%02x", input, result, r)
			}
		}
		
		// Test that IsSecureInput works correctly
		isSecure := sanitizer.IsSecureInput(result)
		if !isSecure && result != "" {
			// The sanitized result should generally be secure
			// (unless it was already too long or had other issues)
			if len(result) <= MaxInputLength {
				t.Errorf("Sanitized input marked as insecure: input=%q, result=%q", input, result)
			}
		}
	})
}

// FuzzInputSanitizerStrict tests the strict sanitizer with fuzzing data
func FuzzInputSanitizerStrict(f *testing.F) {
	// Seed with potentially dangerous inputs
	f.Add("innocent; rm -rf /")
	f.Add("$(whoami)")
	f.Add("`id`")
	f.Add("${HOME}")
	f.Add("cmd1 && cmd2")
	f.Add("cmd1 || cmd2")
	f.Add("exec('/bin/sh')")
	f.Add("eval('code')")
	f.Add("system('command')")
	f.Add("normal text")
	f.Add("")
	
	f.Fuzz(func(t *testing.T, input string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("StrictSanitizer panicked with input %q: %v", input, r)
			}
		}()
		
		sanitizer := NewStrictSanitizer()
		
		// Test strict sanitization
		result, err := sanitizer.SanitizeInput(input)
		
		// Strict sanitizer may reject more inputs, which is fine
		if err != nil {
			// Errors are expected for dangerous input in strict mode
			return
		}
		
		// If it passes strict sanitization, it should be very safe
		if !utf8.ValidString(result) {
			t.Errorf("Strict sanitizer produced invalid UTF-8: input=%q, result=%q", input, result)
		}
		
		// No dangerous patterns should remain in strict mode
		dangerousPatterns := []string{
			"$(", "`", "${", "||", "&&", ";",
			"exec", "eval", "system",
		}
		
		for _, pattern := range dangerousPatterns {
			if len(result) > 0 && containsIgnoreCase(result, pattern) {
				t.Errorf("Dangerous pattern %q found in strict sanitized output: input=%q, result=%q", 
					pattern, input, result)
			}
		}
	})
}

// FuzzEscapeOutput tests output escaping with fuzzing data
func FuzzEscapeOutput(f *testing.F) {
	// Seed with various output scenarios
	f.Add("normal output")
	f.Add("error: \x1b[31mfailed\x1b[0m")
	f.Add("output\x9bwith CSI")
	f.Add("multiline\noutput\nhere")
	f.Add("")
	f.Add("unicode: 🌍 test")
	f.Add("control\x00chars\x07here")
	
	f.Fuzz(func(t *testing.T, input string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("EscapeOutput panicked with input %q: %v", input, r)
			}
		}()
		
		result := EscapeOutput(input)
		
		// Result should always be valid UTF-8
		if !utf8.ValidString(result) {
			t.Errorf("EscapeOutput produced invalid UTF-8: input=%q, result=%q", input, result)
		}
		
		// No CSI characters should remain
		for _, r := range result {
			if r == CSI {
				t.Errorf("CSI character found in escaped output: input=%q, result=%q", input, result)
			}
		}
	})
}

// FuzzEscapeForLogging tests log escaping with fuzzing data
func FuzzEscapeForLogging(f *testing.F) {
	// Seed with log injection attempts
	f.Add("normal log entry")
	f.Add("log\ninjection\nattempt")
	f.Add("log\rreturn\rcarriage")
	f.Add("tab\tseparated\tvalues")
	f.Add("control\x00\x07chars")
	f.Add("")
	f.Add("very long log entry that should be truncated at some point to prevent log flooding attacks")
	
	f.Fuzz(func(t *testing.T, input string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("EscapeForLogging panicked with input %q: %v", input, r)
			}
		}()
		
		result := EscapeForLogging(input)
		
		// Result should not contain unescaped newlines
		if containsUnescapedNewlines(result) {
			t.Errorf("Unescaped newlines found in log output: input=%q, result=%q", input, result)
		}
		
		// Result should not be excessively long
		if len(result) > 520 { // 500 + "[TRUNCATED]" = 513, some margin
			t.Errorf("Log output too long: input=%q, result=%q, length=%d", input, result, len(result))
		}
		
		// Should be valid UTF-8
		if !utf8.ValidString(result) {
			t.Errorf("EscapeForLogging produced invalid UTF-8: input=%q, result=%q", input, result)
		}
	})
}

// FuzzValidateCommandName tests command name validation with fuzzing data
func FuzzValidateCommandName(f *testing.F) {
	// Seed with various command name scenarios
	f.Add("create")
	f.Add("sub-command")
	f.Add("sub_command")
	f.Add("")
	f.Add("bad command")
	f.Add("bad$command")
	f.Add("123command")
	f.Add("command123")
	f.Add("a")
	
	f.Fuzz(func(t *testing.T, input string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("ValidateCommandName panicked with input %q: %v", input, r)
			}
		}()
		
		err := ValidateCommandName(input)
		
		// Function should never panic, even with invalid input
		// Error is acceptable for invalid command names
		_ = err
	})
}

// FuzzValidateFlagName tests flag name validation with fuzzing data
func FuzzValidateFlagName(f *testing.F) {
	// Seed with various flag name scenarios
	f.Add("verbose")
	f.Add("dry-run")
	f.Add("")
	f.Add("2verbose")
	f.Add("bad_flag")
	f.Add("flag-with-dashes")
	f.Add("v")
	
	f.Fuzz(func(t *testing.T, input string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("ValidateFlagName panicked with input %q: %v", input, r)
			}
		}()
		
		err := ValidateFlagName(input)
		
		// Function should never panic, even with invalid input
		// Error is acceptable for invalid flag names
		_ = err
	})
}

// FuzzSanitizeArguments tests argument sanitization with fuzzing data
func FuzzSanitizeArguments(f *testing.F) {
	// Seed with various argument scenarios (using individual string parameters)
	f.Add("arg1", "arg2", "arg3")
	f.Add("normal", "", "")
	f.Add("", "", "")
	f.Add("arg\x9bwith", "csi\x00chars", "")
	f.Add("\x1b[31mcolored\x1b[0m", "args", "")
	
	// Note: We can't directly fuzz []string, so we'll work with the individual elements
	f.Fuzz(func(t *testing.T, arg1, arg2, arg3 string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("SanitizeArguments panicked with args [%q, %q, %q]: %v", arg1, arg2, arg3, r)
			}
		}()
		
		sanitizer := NewInputSanitizer()
		
		// Build args array, skipping empty strings to avoid massive arrays
		var args []string
		if arg1 != "" {
			args = append(args, arg1)
		}
		if arg2 != "" {
			args = append(args, arg2)
		}
		if arg3 != "" {
			args = append(args, arg3)
		}
		
		// Don't test with too many arguments to avoid timeout
		if len(args) > 10 {
			return
		}
		
		result, err := sanitizer.SanitizeArguments(args)
		
		if err != nil {
			// Errors are acceptable for invalid arguments
			return
		}
		
		// All results should be safe
		for i, arg := range result {
			if !utf8.ValidString(arg) {
				t.Errorf("Sanitized argument %d is invalid UTF-8: original=%q, sanitized=%q", i, args[i], arg)
			}
			
			// No CSI characters
			for _, r := range arg {
				if r == CSI {
					t.Errorf("CSI character found in sanitized argument %d: original=%q, sanitized=%q", i, args[i], arg)
				}
			}
		}
	})
}

// Helper functions for fuzz tests

func containsIgnoreCase(s, substr string) bool {
	s = strings.ToLower(s)
	substr = strings.ToLower(substr)
	return strings.Contains(s, substr)
}

func containsUnescapedNewlines(s string) bool {
	for i, r := range s {
		if r == '\n' {
			// Check if it's escaped (preceded by \)
			if i == 0 || rune(s[i-1]) != '\\' {
				return true
			}
		}
	}
	return false
}