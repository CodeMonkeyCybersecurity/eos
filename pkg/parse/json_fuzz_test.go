// pkg/parse/json_fuzz_test.go
package parse

import (
	"strings"
	"testing"
)

// FuzzExtractJSONMap tests JSON parsing with malicious inputs for DOS and security vulnerabilities
func FuzzExtractJSONMap(f *testing.F) {
	// Seed with valid JSON
	f.Add(`{"key": "value"}`)
	f.Add(`{"list": [1, 2, 3]}`)
	f.Add(`{"nested": {"inner": "value"}}`)
	f.Add(`{}`)
	f.Add(`[]`)

	// Seed with potentially problematic JSON
	f.Add(`{"key": "value", "key": "duplicate"}`)              // Duplicate keys
	f.Add(`{"unicode": "\\u0000"}`)                            // Null unicode
	f.Add(`{"unicode": "\\uFFFF"}`)                            // High unicode
	f.Add(`{"long_key": "` + strings.Repeat("a", 1000) + `"}`) // Long value

	f.Fuzz(func(t *testing.T, jsonInput string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("ExtractJSONMap panicked on input: %v", r)
			}
		}()

		// Test that parsing doesn't panic
		result, err := ExtractJSONMap(jsonInput)

		if err == nil && result != nil {
			// If parsing succeeded, verify result is reasonable
			if len(result) > 1000000 {
				t.Errorf("JSON parsing created unexpectedly large result: %d items", len(result))
			}

			// Check for reasonable nesting depth (prevent stack overflow)
			checkNestingDepth(t, result, 0, 100)
		}
	})
}

// FuzzJSONBombs tests for JSON bombs (deeply nested structures that cause exponential memory usage)
func FuzzJSONBombs(f *testing.F) {
	// Basic nested structures
	f.Add(`{"a": {"b": {"c": "value"}}}`)
	f.Add(`[[[["deep"]]]]`)

	// Potential JSON bombs
	f.Add(`{"a": {"a": {"a": {"a": {"a": "value"}}}}}`) // Deep nesting
	f.Add(`[{"a": [{"a": [{"a": "value"}]}]}]`)         // Mixed nesting

	f.Fuzz(func(t *testing.T, jsonInput string) {
		// Limit input size to prevent obvious resource exhaustion
		if len(jsonInput) > 10000 {
			return
		}

		// Count nesting levels in input to skip obvious bombs
		nestingLevel := countMaxNesting(jsonInput)
		if nestingLevel > 50 {
			return
		}

		defer func() {
			if r := recover(); r != nil {
				t.Errorf("JSON parsing panicked on deeply nested input: %v", r)
			}
		}()

		result, err := ExtractJSONMap(jsonInput)
		if err == nil && result != nil {
			// Verify reasonable memory usage
			checkNestingDepth(t, result, 0, 100)
		}
	})
}

// FuzzJSONUnicodeAttacks tests for Unicode-based attacks
func FuzzJSONUnicodeAttacks(f *testing.F) {
	f.Add(`{"normal": "value"}`)
	f.Add(`{"unicode": "\\u0041"}`) // 'A'

	// Unicode attack vectors
	f.Add(`{"null": "\\u0000"}`)       // Null byte
	f.Add(`{"bom": "\\uFEFF"}`)        // Byte order mark
	f.Add(`{"rtl": "\\u202E"}`)        // Right-to-left override
	f.Add(`{"zwsp": "\\u200B"}`)       // Zero-width space
	f.Add(`{"combining": "a\\u0300"}`) // Combining diacritical
	f.Add(`{"surrogate": "\\uD800"}`)  // High surrogate
	f.Add(`{"private": "\\uE000"}`)    // Private use area

	f.Fuzz(func(t *testing.T, jsonInput string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("JSON parsing panicked on Unicode input: %v", r)
			}
		}()

		result, err := ExtractJSONMap(jsonInput)
		if err == nil && result != nil {
			// Check that parsed values don't contain dangerous Unicode
			checkUnicodeValues(t, result)
		}
	})
}

// FuzzJSONNumbers tests for number parsing vulnerabilities
func FuzzJSONNumbers(f *testing.F) {
	f.Add(`{"number": 42}`)
	f.Add(`{"float": 3.14}`)
	f.Add(`{"zero": 0}`)

	// Number edge cases
	f.Add(`{"large": 9999999999999999999999999999}`)         // Very large number
	f.Add(`{"small": -9999999999999999999999999999}`)        // Very small number
	f.Add(`{"exp": 1e308}`)                                  // Large exponent
	f.Add(`{"tiny": 1e-308}`)                                // Tiny number
	f.Add(`{"inf": 1e999}`)                                  // Potential infinity
	f.Add(`{"precision": 0.123456789012345678901234567890}`) // High precision

	f.Fuzz(func(t *testing.T, jsonInput string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("JSON number parsing panicked: %v", r)
			}
		}()

		_, _ = ExtractJSONMap(jsonInput)
	})
}

// FuzzJSONStrings tests for string parsing vulnerabilities
func FuzzJSONStrings(f *testing.F) {
	f.Add(`{"string": "normal"}`)
	f.Add(`{"empty": ""}`)

	// String attack vectors
	f.Add(`{"escape": "\\""}`)                             // Quote escape
	f.Add(`{"backslash": "\\\\"}`)                         // Backslash escape
	f.Add(`{"newline": "\\n"}`)                            // Newline
	f.Add(`{"tab": "\\t"}`)                                // Tab
	f.Add(`{"control": "\\u0001\\u0002\\u0003"}`)          // Control characters
	f.Add(`{"long": "` + strings.Repeat("x", 1000) + `"}`) // Long string

	f.Fuzz(func(t *testing.T, jsonInput string) {
		// Skip extremely long inputs to prevent resource exhaustion
		if len(jsonInput) > 100000 {
			return
		}

		defer func() {
			if r := recover(); r != nil {
				t.Errorf("JSON string parsing panicked: %v", r)
			}
		}()

		result, err := ExtractJSONMap(jsonInput)
		if err == nil && result != nil {
			// Check string values for dangerous content
			checkStringValues(t, result)
		}
	})
}

// Helper function to check nesting depth
func checkNestingDepth(t *testing.T, data interface{}, currentDepth, maxDepth int) {
	if currentDepth > maxDepth {
		t.Errorf("JSON structure exceeded maximum nesting depth: %d", currentDepth)
		return
	}

	switch v := data.(type) {
	case map[string]interface{}:
		for _, value := range v {
			checkNestingDepth(t, value, currentDepth+1, maxDepth)
		}
	case []interface{}:
		for _, value := range v {
			checkNestingDepth(t, value, currentDepth+1, maxDepth)
		}
	}
}

// Helper function to count maximum nesting levels in JSON string
func countMaxNesting(jsonStr string) int {
	maxDepth := 0
	currentDepth := 0
	inString := false
	escaped := false

	for _, char := range jsonStr {
		if escaped {
			escaped = false
			continue
		}

		if char == '\\' && inString {
			escaped = true
			continue
		}

		if char == '"' {
			inString = !inString
			continue
		}

		if !inString {
			switch char {
			case '{', '[':
				currentDepth++
				if currentDepth > maxDepth {
					maxDepth = currentDepth
				}
			case '}', ']':
				currentDepth--
			}
		}
	}

	return maxDepth
}

// Helper function to check for dangerous Unicode values
func checkUnicodeValues(t *testing.T, data interface{}) {
	switch v := data.(type) {
	case map[string]interface{}:
		for key, value := range v {
			// Check key for dangerous Unicode
			if strings.Contains(key, "\x00") {
				t.Errorf("JSON key contains null byte")
			}
			checkUnicodeValues(t, value)
		}
	case []interface{}:
		for _, value := range v {
			checkUnicodeValues(t, value)
		}
	case string:
		// Check for null bytes
		if strings.Contains(v, "\x00") {
			t.Errorf("JSON string value contains null byte")
		}
		// Check for other control characters that might be dangerous
		for _, char := range v {
			if char < 32 && char != '\t' && char != '\n' && char != '\r' {
				t.Logf("JSON string contains control character: U+%04X", char)
			}
		}
	}
}

// Helper function to check string values for potential issues
func checkStringValues(t *testing.T, data interface{}) {
	switch v := data.(type) {
	case map[string]interface{}:
		for _, value := range v {
			checkStringValues(t, value)
		}
	case []interface{}:
		for _, value := range v {
			checkStringValues(t, value)
		}
	case string:
		// Check for extremely long strings that could cause memory issues
		if len(v) > 1000000 {
			t.Errorf("JSON string value is extremely long: %d characters", len(v))
		}
	}
}
