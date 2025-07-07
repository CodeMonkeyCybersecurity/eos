// pkg/security/corpus_fuzz_test.go
// Comprehensive fuzz testing using real-world security corpus

package security

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"go.uber.org/zap"
)

// FuzzWithSecurityCorpus runs fuzzing using our comprehensive security corpus as seeds
func FuzzWithSecurityCorpus(f *testing.F) {
	corpus := GetSecurityCorpus()
	
	// Seed with all attack vectors from our corpus
	allAttacks := [][]string{
		corpus.CSIAttacks,
		corpus.ANSIAttacks,
		corpus.UTF8Attacks,
		corpus.TerminalExploits,
		corpus.LogInjectionAttacks,
		corpus.ComplexAttacks,
		corpus.ParserConfusionAttacks,
		corpus.CVEPatterns,
	}
	
	// Add all corpus attacks as seeds
	for _, attackGroup := range allAttacks {
		for _, attack := range attackGroup {
			f.Add(attack)
		}
	}
	
	// Add some additional edge cases
	f.Add("") // Empty string
	f.Add("normal text") // Clean input
	f.Add(strings.Repeat("A", MaxInputLength)) // Maximum length clean
	f.Add(strings.Repeat(string(rune(0x9b)), 1000)) // CSI bomb
	
	f.Fuzz(func(t *testing.T, input string) {
		// Test both sanitizers
		sanitizers := []*InputSanitizer{
			NewInputSanitizer(),
			NewStrictSanitizer(),
		}
		
		for i, sanitizer := range sanitizers {
			sanitizerName := "Normal"
			if i == 1 {
				sanitizerName = "Strict"
			}
			
			// Ensure no panics
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s sanitizer panicked with input %q: %v", sanitizerName, input, r)
				}
			}()
			
			result, err := sanitizer.SanitizeInput(input)
			
			// Strict sanitizer may reject dangerous inputs
			if i == 1 && err != nil {
				// Validate that errors are appropriate for strict mode
				if len(input) > sanitizer.maxLength {
					// Length error is expected
					continue
				}
				if containsDangerousPatterns(input) {
					// Dangerous pattern rejection is expected in strict mode
					continue
				}
				// Other errors should be investigated
				t.Logf("Strict sanitizer error (may be expected): %v for input %q", err, input)
				continue
			}
			
			if err != nil {
				// Regular sanitizer should handle most inputs
				t.Errorf("%s sanitizer failed with input %q: %v", sanitizerName, input, err)
				continue
			}
			
			// Validate sanitized output
			validateSanitizedOutput(t, input, result, sanitizerName)
		}
	})
}

// FuzzSecureOutput tests the secure output system with malicious data
func FuzzSecureOutput(f *testing.F) {
	corpus := GetSecurityCorpus()
	
	// Seed with attack vectors
	for _, attackGroup := range [][]string{
		corpus.CSIAttacks,
		corpus.ANSIAttacks,
		corpus.UTF8Attacks,
		corpus.LogInjectionAttacks,
	} {
		for _, attack := range attackGroup {
			f.Add(attack, attack, attack) // message, field1, field2
		}
	}
	
	f.Fuzz(func(t *testing.T, message, field1, field2 string) {
		ctx := context.Background()
		output := NewSecureOutput(ctx)
		
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("SecureOutput panicked with message=%q, field1=%q, field2=%q: %v", 
					message, field1, field2, r)
			}
		}()
		
		// Test various output methods
		output.Info(message, zap.String("field1", field1), zap.String("field2", field2))
		output.Success(message, zap.String("data", field1))
		output.Warning(message, zap.Any("info", field2))
		output.Error(message, fmt.Errorf("error: %s", field1), zap.String("context", field2))
		
		// Test with structured data
		data := map[string]interface{}{
			"key1": field1,
			"key2": field2,
			"nested": map[string]string{
				"subkey": message,
			},
		}
		output.Result("fuzz_test", data)
		
		// Test list output
		items := []string{message, field1, field2}
		output.List("Fuzz Test Items", items)
		
		// Test table output
		headers := []string{"Header1", "Header2"}
		rows := [][]string{{message, field1}, {field2, message}}
		output.Table("Fuzz Test Table", headers, rows)
	})
}

// FuzzArgumentSanitization tests command argument sanitization
func FuzzArgumentSanitization(f *testing.F) {
	corpus := GetSecurityCorpus()
	
	// Seed with dangerous arguments
	for _, attackGroup := range [][]string{
		corpus.CSIAttacks,
		corpus.ANSIAttacks,
		corpus.UTF8Attacks,
		corpus.TerminalExploits,
	} {
		for _, attack := range attackGroup {
			f.Add(attack, attack, attack) // Three arguments
		}
	}
	
	f.Fuzz(func(t *testing.T, arg1, arg2, arg3 string) {
		sanitizer := NewInputSanitizer()
		
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Argument sanitization panicked with args [%q, %q, %q]: %v", 
					arg1, arg2, arg3, r)
			}
		}()
		
		// Build argument list (skip empty to avoid massive arrays)
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
		
		// Limit argument count for performance
		if len(args) > MaxArgumentCount {
			return
		}
		
		result, err := sanitizer.SanitizeArguments(args)
		if err != nil {
			// Check if error is expected
			if len(args) > sanitizer.maxArguments {
				return // Expected error
			}
			// Check if any argument is too long
			for _, arg := range args {
				if len(arg) > sanitizer.maxLength {
					return // Expected error
				}
			}
			t.Errorf("Unexpected argument sanitization error: %v", err)
			return
		}
		
		// Validate all results
		if len(result) != len(args) {
			t.Errorf("Result length mismatch: expected %d, got %d", len(args), len(result))
			return
		}
		
		for i, sanitizedArg := range result {
			validateSanitizedOutput(t, args[i], sanitizedArg, fmt.Sprintf("Argument_%d", i))
		}
	})
}

// FuzzEscapeFunctions tests individual escape functions
func FuzzEscapeFunctions(f *testing.F) {
	corpus := GetSecurityCorpus()
	
	// Seed with all attack types
	for _, attackGroup := range [][]string{
		corpus.CSIAttacks,
		corpus.ANSIAttacks,
		corpus.UTF8Attacks,
		corpus.LogInjectionAttacks,
	} {
		for _, attack := range attackGroup {
			f.Add(attack)
		}
	}
	
	f.Fuzz(func(t *testing.T, input string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Escape function panicked with input %q: %v", input, r)
			}
		}()
		
		// Test EscapeOutput
		escaped := EscapeOutput(input)
		if !utf8.ValidString(escaped) {
			t.Errorf("EscapeOutput produced invalid UTF-8: input=%q, output=%q", input, escaped)
		}
		if strings.ContainsRune(escaped, CSI) {
			t.Errorf("EscapeOutput left CSI character: input=%q, output=%q", input, escaped)
		}
		
		// Test EscapeForLogging
		logEscaped := EscapeForLogging(input)
		if !utf8.ValidString(logEscaped) {
			t.Errorf("EscapeForLogging produced invalid UTF-8: input=%q, output=%q", input, logEscaped)
		}
		if strings.Contains(logEscaped, "\n") && !strings.Contains(logEscaped, "\\n") {
			t.Errorf("EscapeForLogging left unescaped newline: input=%q, output=%q", input, logEscaped)
		}
		if len(logEscaped) > 520 { // 500 + some margin for [TRUNCATED]
			t.Errorf("EscapeForLogging output too long: %d characters", len(logEscaped))
		}
	})
}

// FuzzValidationFunctions tests command and flag name validation
func FuzzValidationFunctions(f *testing.F) {
	corpus := GetSecurityCorpus()
	
	// Seed with attack vectors that might affect validation
	for _, attackGroup := range [][]string{
		corpus.CSIAttacks,
		corpus.UTF8Attacks,
		corpus.ParserConfusionAttacks,
	} {
		for _, attack := range attackGroup {
			f.Add(attack)
		}
	}
	
	// Add some valid names as seeds
	f.Add("valid-command")
	f.Add("valid_command")
	f.Add("command123")
	f.Add("valid-flag")
	f.Add("f")
	f.Add("")
	
	f.Fuzz(func(t *testing.T, input string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Validation function panicked with input %q: %v", input, r)
			}
		}()
		
		// Test ValidateCommandName
		err1 := ValidateCommandName(input)
		// No specific validation of result - just ensure no panic
		_ = err1
		
		// Test ValidateFlagName  
		err2 := ValidateFlagName(input)
		// No specific validation of result - just ensure no panic
		_ = err2
	})
}

// FuzzCombinedOperations tests complex workflows combining multiple operations
func FuzzCombinedOperations(f *testing.F) {
	corpus := GetSecurityCorpus()
	
	// Seed with complex attacks
	for _, attack := range corpus.ComplexAttacks {
		f.Add(attack)
	}
	for _, attack := range corpus.CVEPatterns {
		f.Add(attack)
	}
	
	f.Fuzz(func(t *testing.T, input string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Combined operations panicked with input %q: %v", input, r)
			}
		}()
		
		// Complex workflow: sanitize input, validate names, generate output
		sanitizer := NewInputSanitizer()
		ctx := context.Background()
		output := NewSecureOutput(ctx)
		
		// Step 1: Sanitize the input
		sanitized, err := sanitizer.SanitizeInput(input)
		if err != nil {
			// Expected for some inputs
			return
		}
		
		// Step 2: Use sanitized input in various ways
		if len(sanitized) > 0 {
			// Try as command name
			_ = ValidateCommandName(sanitized)
			
			// Try as flag name
			_ = ValidateFlagName(sanitized)
			
			// Use in output
			output.Info("Processed input", zap.String("original", input), zap.String("sanitized", sanitized))
			
			// Use in complex data structure
			data := map[string]interface{}{
				"input":     input,
				"sanitized": sanitized,
				"length":    len(sanitized),
			}
			output.Result("combined_operation", data)
		}
	})
}

// Helper functions

func validateSanitizedOutput(t *testing.T, original, sanitized, context string) {
	// Must be valid UTF-8
	if !utf8.ValidString(sanitized) {
		t.Errorf("%s: sanitized output is invalid UTF-8: original=%q, sanitized=%q", 
			context, original, sanitized)
	}
	
	// Must not contain CSI characters
	if strings.ContainsRune(sanitized, CSI) {
		t.Errorf("%s: CSI character found in sanitized output: original=%q, sanitized=%q", 
			context, original, sanitized)
	}
	
	// Must not contain dangerous control characters (except \n and \t)
	for i, r := range sanitized {
		if r < 32 && r != '\n' && r != '\t' {
			t.Errorf("%s: dangerous control character 0x%02x at position %d: original=%q, sanitized=%q", 
				context, r, i, original, sanitized)
		}
		if r >= 127 && r <= 159 && r != ReplacementChar {
			t.Errorf("%s: dangerous C1 control character 0x%02x at position %d: original=%q, sanitized=%q", 
				context, r, i, original, sanitized)
		}
	}
}

func containsDangerousPatterns(input string) bool {
	dangerousPatterns := []string{
		"$(", "`", "${", "||", "&&", ";",
		"exec", "eval", "system", "rm -rf", "curl",
	}
	
	lowerInput := strings.ToLower(input)
	for _, pattern := range dangerousPatterns {
		if strings.Contains(lowerInput, pattern) {
			return true
		}
	}
	
	return false
}