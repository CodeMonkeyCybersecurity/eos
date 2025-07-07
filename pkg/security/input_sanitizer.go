// pkg/security/input_sanitizer.go

package security

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

const (
	// MaxInputLength defines the maximum allowed length for any input
	MaxInputLength = 1024 * 64 // 64KB reasonable limit for CLI inputs
	
	// MaxArgumentCount defines maximum number of arguments
	MaxArgumentCount = 1000
	
	// Control sequence indicators that should be stripped
	CSI = '\x9b'  // Control Sequence Introducer - critical vulnerability
	ESC = '\x1b'  // Escape character
	
	// Unicode replacement character for invalid sequences
	ReplacementChar = '\uFFFD'
)

var (
	// ansiRegex matches ANSI escape sequences including CSI sequences
	// More comprehensive pattern to handle various ANSI sequence types
	ansiRegex = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]|\x9b[0-9;]*[A-Za-z]|\x1b\][^\\]*\x07|\x1b\][^\\]*\x1b\\|\x1bP[^\\]*\x1b\\|\x1b_[^\\]*\x1b\\|\x1b\^[^\\]*\x1b\\`)
	
	// controlCharRegex matches dangerous control characters except newline and tab
	controlCharRegex = regexp.MustCompile(`[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]`)
	
	// Additional dangerous sequences that could bypass basic filtering
	dangerousSequences = []string{
		"\x1b]",   // Operating System Command (start)
		"\x1b^",   // Privacy Message (start)
		"\x1b_",   // Application Program Command (start)
		"\x1bP",   // Device Control String (start)
		"\x1b\\",  // String Terminator
		"\x07",    // BEL terminator for OSC sequences
	}
)

// InputSanitizer provides centralized input validation and sanitization
type InputSanitizer struct {
	maxLength       int
	maxArguments    int
	allowUnicode    bool
	normalizeUTF8   bool
	strictMode      bool
}

// NewInputSanitizer creates a new input sanitizer with default settings
func NewInputSanitizer() *InputSanitizer {
	return &InputSanitizer{
		maxLength:     MaxInputLength,
		maxArguments:  MaxArgumentCount,
		allowUnicode:  true,
		normalizeUTF8: true,
		strictMode:    false,
	}
}

// NewStrictSanitizer creates a sanitizer with stricter security settings
func NewStrictSanitizer() *InputSanitizer {
	return &InputSanitizer{
		maxLength:     MaxInputLength / 4, // Smaller limit in strict mode
		maxArguments:  MaxArgumentCount / 2,
		allowUnicode:  false, // ASCII only in strict mode
		normalizeUTF8: true,
		strictMode:    true,
	}
}

// SanitizeInput performs comprehensive input sanitization
func (s *InputSanitizer) SanitizeInput(input string) (string, error) {
	if len(input) > s.maxLength {
		return "", fmt.Errorf("input exceeds maximum length of %d bytes", s.maxLength)
	}
	
	// Phase 1: Validate and fix UTF-8 encoding
	sanitized, err := s.validateAndFixUTF8(input)
	if err != nil {
		return "", fmt.Errorf("UTF-8 validation failed: %w", err)
	}
	
	// Phase 2: Strip terminal control sequences (critical security fix)
	sanitized = s.stripControlSequences(sanitized)
	
	// Phase 3: Remove dangerous control characters
	sanitized = s.removeDangerousControlChars(sanitized)
	
	// Phase 4: Normalize Unicode to prevent homograph attacks
	if s.normalizeUTF8 {
		sanitized = s.normalizeUnicode(sanitized)
	}
	
	// Phase 5: Additional validation in strict mode
	if s.strictMode {
		sanitized, err = s.strictValidation(sanitized)
		if err != nil {
			return "", fmt.Errorf("strict validation failed: %w", err)
		}
	}
	
	return sanitized, nil
}

// SanitizeArguments sanitizes a slice of command arguments
func (s *InputSanitizer) SanitizeArguments(args []string) ([]string, error) {
	if len(args) > s.maxArguments {
		return nil, fmt.Errorf("too many arguments: %d (max %d)", len(args), s.maxArguments)
	}
	
	sanitized := make([]string, len(args))
	for i, arg := range args {
		clean, err := s.SanitizeInput(arg)
		if err != nil {
			return nil, fmt.Errorf("argument %d sanitization failed: %w", i, err)
		}
		sanitized[i] = clean
	}
	
	return sanitized, nil
}

// validateAndFixUTF8 ensures input is valid UTF-8, replacing invalid sequences
func (s *InputSanitizer) validateAndFixUTF8(input string) (string, error) {
	if utf8.ValidString(input) {
		return input, nil
	}
	
	// Fix invalid UTF-8 by replacing invalid sequences
	var result strings.Builder
	result.Grow(len(input))
	
	for len(input) > 0 {
		r, size := utf8.DecodeRuneInString(input)
		if r == utf8.RuneError && size == 1 {
			// Invalid UTF-8 sequence detected
			if s.strictMode {
				return "", fmt.Errorf("invalid UTF-8 sequence detected at position %d", len(input))
			}
			// Replace with Unicode replacement character
			result.WriteRune(ReplacementChar)
		} else {
			result.WriteRune(r)
		}
		input = input[size:]
	}
	
	return result.String(), nil
}

// stripControlSequences removes ANSI escape sequences and CSI sequences
func (s *InputSanitizer) stripControlSequences(input string) string {
	// Remove standalone CSI characters first (critical vulnerability fix)
	cleaned := strings.ReplaceAll(input, string(CSI), "")
	
	// Remove ANSI escape sequences using comprehensive regex
	cleaned = ansiRegex.ReplaceAllString(cleaned, "")
	
	// Remove any remaining dangerous sequence starters
	for _, seq := range dangerousSequences {
		cleaned = strings.ReplaceAll(cleaned, seq, "")
	}
	
	// Clean up any remaining escape sequences that might have been malformed
	cleaned = regexp.MustCompile(`\x1b[^\x1b]*`).ReplaceAllString(cleaned, "")
	
	return cleaned
}

// removeDangerousControlChars removes control characters while preserving newlines and tabs
func (s *InputSanitizer) removeDangerousControlChars(input string) string {
	var result strings.Builder
	result.Grow(len(input))
	
	for _, r := range input {
		// Allow newlines (0x0A) and tabs (0x09), reject other control chars
		if r == '\n' || r == '\t' {
			result.WriteRune(r)
		} else if r < 32 || (r >= 127 && r <= 159) {
			// Skip dangerous control characters
			continue
		} else if !s.allowUnicode && r > 127 {
			// In strict ASCII mode, replace non-ASCII with replacement char
			if s.strictMode {
				result.WriteRune(ReplacementChar)
			}
		} else {
			result.WriteRune(r)
		}
	}
	
	return result.String()
}

// normalizeUnicode normalizes Unicode to prevent homograph attacks
func (s *InputSanitizer) normalizeUnicode(input string) string {
	// Use NFC (Canonical Decomposition, followed by Canonical Composition)
	// This prevents homograph attacks using different Unicode representations
	return norm.NFC.String(input)
}

// strictValidation performs additional validation in strict mode
func (s *InputSanitizer) strictValidation(input string) (string, error) {
	// Check for suspicious patterns in strict mode
	
	// Detect potential injection attempts
	suspiciousPatterns := []string{
		"$(", "`", "${", "||", "&&", ";",
		"exec", "eval", "system",
	}
	
	lowercaseInput := strings.ToLower(input)
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(lowercaseInput, pattern) {
			return "", fmt.Errorf("potentially dangerous pattern detected: %s", pattern)
		}
	}
	
	// Additional length check in strict mode
	if len(input) > s.maxLength {
		return "", fmt.Errorf("input too long for strict mode: %d bytes", len(input))
	}
	
	return input, nil
}

// IsSecureInput performs a quick security check without modification
func (s *InputSanitizer) IsSecureInput(input string) bool {
	// Quick security validation without sanitization
	if len(input) > s.maxLength {
		return false
	}
	
	if !utf8.ValidString(input) {
		return false
	}
	
	// Check for CSI and dangerous control sequences
	if strings.ContainsRune(input, CSI) || strings.ContainsRune(input, ESC) {
		return false
	}
	
	// Check for other dangerous control characters
	if controlCharRegex.MatchString(input) {
		return false
	}
	
	return true
}

// EscapeOutput safely escapes output to prevent terminal manipulation
func EscapeOutput(output string) string {
	if output == "" {
		return output
	}
	
	// Create a sanitizer for output escaping
	sanitizer := NewInputSanitizer()
	
	// For output, we're more permissive but still remove dangerous sequences
	escaped, err := sanitizer.SanitizeInput(output)
	if err != nil {
		// If sanitization fails, return a safe placeholder
		return "[SANITIZED_OUTPUT]"
	}
	
	return escaped
}

// EscapeForLogging safely escapes data for logging to prevent log injection
func EscapeForLogging(data string) string {
	if data == "" {
		return data
	}
	
	// First, ensure valid UTF-8 by using the sanitizer
	sanitizer := NewInputSanitizer()
	
	// Fix UTF-8 issues first
	validUTF8, err := sanitizer.validateAndFixUTF8(data)
	if err != nil {
		// If UTF-8 fixing fails, return safe placeholder
		return "[INVALID_UTF8_DATA]"
	}
	
	// Remove control characters except newlines and tabs (we'll escape those)
	escaped := validUTF8
	for _, r := range []rune{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0B, 0x0C, 0x0E, 0x0F, 
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x7F} {
		escaped = strings.ReplaceAll(escaped, string(r), "")
	}
	
	// Remove C1 control characters (0x80-0x9F)
	for i := 0x80; i <= 0x9F; i++ {
		escaped = strings.ReplaceAll(escaped, string(rune(i)), "")
	}
	
	// Escape newlines, carriage returns, and tabs for safe logging
	escaped = strings.ReplaceAll(escaped, "\n", "\\n")
	escaped = strings.ReplaceAll(escaped, "\r", "\\r")
	escaped = strings.ReplaceAll(escaped, "\t", "\\t")
	
	// Truncate very long log entries
	const maxLogLength = 500
	if len(escaped) > maxLogLength {
		escaped = escaped[:maxLogLength] + "...[TRUNCATED]"
	}
	
	return escaped
}

// ValidateCommandName validates that a command name is safe
func ValidateCommandName(name string) error {
	if name == "" {
		return fmt.Errorf("command name cannot be empty")
	}
	
	if len(name) > 100 {
		return fmt.Errorf("command name too long: %d characters", len(name))
	}
	
	// Command names should only contain alphanumeric, dash, and underscore
	for _, r := range name {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' && r != '_' {
			return fmt.Errorf("invalid character in command name: %c", r)
		}
	}
	
	return nil
}

// ValidateFlagName validates that a flag name is safe
func ValidateFlagName(name string) error {
	if name == "" {
		return fmt.Errorf("flag name cannot be empty")
	}
	
	if len(name) > 50 {
		return fmt.Errorf("flag name too long: %d characters", len(name))
	}
	
	// Flag names should start with letter and contain only alphanumeric and dash
	if !unicode.IsLetter(rune(name[0])) {
		return fmt.Errorf("flag name must start with letter")
	}
	
	for _, r := range name {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' {
			return fmt.Errorf("invalid character in flag name: %c", r)
		}
	}
	
	return nil
}

// DefaultSanitizer provides a package-level default sanitizer instance
var DefaultSanitizer = NewInputSanitizer()

// StrictSanitizer provides a package-level strict sanitizer instance
var StrictSanitizer = NewStrictSanitizer()

// SanitizeInput is a convenience function using the default sanitizer
func SanitizeInput(input string) (string, error) {
	return DefaultSanitizer.SanitizeInput(input)
}

// SanitizeArguments is a convenience function using the default sanitizer
func SanitizeArguments(args []string) ([]string, error) {
	return DefaultSanitizer.SanitizeArguments(args)
}