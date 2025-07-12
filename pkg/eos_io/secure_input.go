package eos_io

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"golang.org/x/term"
)

const (
	// MaxInputLength defines the maximum allowed length for user input
	MaxInputLength = 4096
	
	// MaxPasswordLength defines the maximum allowed password length
	MaxPasswordLength = 256
)

var (
	// controlCharRegex matches dangerous control characters
	controlCharRegex = regexp.MustCompile(`[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]`)
	
	// ansiEscapeRegex matches ANSI escape sequences
	ansiEscapeRegex = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]|\x9b[0-9;]*[A-Za-z]`)
)

// InputValidationError represents input validation errors
type InputValidationError struct {
	Field   string
	Reason  string
	Input   string
}

func (e *InputValidationError) Error() string {
	return fmt.Sprintf("invalid input for %s: %s", e.Field, e.Reason)
}

// validateUserInput performs comprehensive input validation
func validateUserInput(input, fieldName string) error {
	// Check for empty input
	if strings.TrimSpace(input) == "" {
		return &InputValidationError{
			Field:  fieldName,
			Reason: "cannot be empty",
			Input:  input,
		}
	}
	
	// Check input length
	if len(input) > MaxInputLength {
		return &InputValidationError{
			Field:  fieldName,
			Reason: fmt.Sprintf("too long (%d chars, max %d)", len(input), MaxInputLength),
			Input:  input[:50] + "...", // Truncate for logging
		}
	}
	
	// Check for valid UTF-8
	if !utf8.ValidString(input) {
		return &InputValidationError{
			Field:  fieldName,
			Reason: "contains invalid UTF-8 sequences",
			Input:  input,
		}
	}
	
	// Check for dangerous control characters
	if controlCharRegex.MatchString(input) {
		return &InputValidationError{
			Field:  fieldName,
			Reason: "contains dangerous control characters",
			Input:  input,
		}
	}
	
	// Check for ANSI escape sequences (terminal manipulation)
	if ansiEscapeRegex.MatchString(input) {
		return &InputValidationError{
			Field:  fieldName,
			Reason: "contains ANSI escape sequences",
			Input:  input,
		}
	}
	
	// Check for null bytes
	if strings.Contains(input, "\x00") {
		return &InputValidationError{
			Field:  fieldName,
			Reason: "contains null bytes",
			Input:  input,
		}
	}
	
	return nil
}

// sanitizeUserInput removes dangerous characters from user input
func sanitizeUserInput(input string) string {
	// Remove control characters except newlines and tabs
	sanitized := controlCharRegex.ReplaceAllString(input, "")
	
	// Remove ANSI escape sequences
	sanitized = ansiEscapeRegex.ReplaceAllString(sanitized, "")
	
	// Remove null bytes
	sanitized = strings.ReplaceAll(sanitized, "\x00", "")
	
	// Remove CSI characters
	sanitized = strings.ReplaceAll(sanitized, "\x9b", "")
	
	// Ensure valid UTF-8
	if !utf8.ValidString(sanitized) {
		var result strings.Builder
		for _, r := range sanitized {
			if r != utf8.RuneError {
				result.WriteRune(r)
			}
		}
		sanitized = result.String()
	}
	
	return strings.TrimSpace(sanitized)
}

// validatePasswordInput validates password input for security
func validatePasswordInput(password, fieldName string) error {
	// Check for empty password
	if len(password) == 0 {
		return &InputValidationError{
			Field:  fieldName,
			Reason: "cannot be empty",
			Input:  "[PASSWORD]",
		}
	}
	
	// Check password length
	if len(password) > MaxPasswordLength {
		return &InputValidationError{
			Field:  fieldName,
			Reason: fmt.Sprintf("too long (%d chars, max %d)", len(password), MaxPasswordLength),
			Input:  "[PASSWORD]",
		}
	}
	
	// Check for valid UTF-8
	if !utf8.ValidString(password) {
		return &InputValidationError{
			Field:  fieldName,
			Reason: "contains invalid UTF-8 sequences",
			Input:  "[PASSWORD]",
		}
	}
	
	// Check for dangerous control characters (be more permissive for passwords)
	for _, r := range password {
		if r < 32 && r != '\t' && r != '\n' {
			return &InputValidationError{
				Field:  fieldName,
				Reason: "contains dangerous control characters",
				Input:  "[PASSWORD]",
			}
		}
		if r >= 127 && r <= 159 {
			return &InputValidationError{
				Field:  fieldName,
				Reason: "contains C1 control characters",
				Input:  "[PASSWORD]",
			}
		}
	}
	
	// Check for null bytes
	if strings.Contains(password, "\x00") {
		return &InputValidationError{
			Field:  fieldName,
			Reason: "contains null bytes",
			Input:  "[PASSWORD]",
		}
	}
	
	return nil
}

// sanitizePasswordInput sanitizes password input while preserving valid characters
func sanitizePasswordInput(password string) string {
	// For passwords, we're more conservative - reject rather than sanitize
	// if there are dangerous characters, but we can remove some safe ones
	
	// Remove null bytes
	sanitized := strings.ReplaceAll(password, "\x00", "")
	
	// Remove ANSI escape sequences
	sanitized = ansiEscapeRegex.ReplaceAllString(sanitized, "")
	
	// Remove CSI characters
	sanitized = strings.ReplaceAll(sanitized, "\x9b", "")
	
	return sanitized
}

// parseYesNoInput safely parses yes/no responses
func parseYesNoInput(input, fieldName string) (bool, error) {
	// First validate the input
	if err := validateUserInput(input, fieldName); err != nil {
		return false, err
	}
	
	// Sanitize and normalize
	sanitized := sanitizeUserInput(input)
	normalized := strings.ToLower(strings.TrimSpace(sanitized))
	
	// Parse yes/no responses
	switch normalized {
	case "y", "yes", "true", "1":
		return true, nil
	case "n", "no", "false", "0":
		return false, nil
	default:
		return false, &InputValidationError{
			Field:  fieldName,
			Reason: "must be yes/no, y/n, true/false, or 1/0",
			Input:  sanitized,
		}
	}
}

// PromptInput prompts for user input with validation and sanitization
func PromptInput(rc *RuntimeContext, prompt, fieldName string) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS - Check if we can read from terminal
	logger.Debug("Assessing user input capability", zap.String("field", fieldName))
	
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", fmt.Errorf("stdin is not a terminal")
	}
	
	// INTERVENE - Read input with validation
	fmt.Print(prompt)
	
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return "", fmt.Errorf("failed to read input: %w", err)
		}
		return "", fmt.Errorf("no input received")
	}
	
	input := scanner.Text()
	
	// EVALUATE - Validate and sanitize input
	if err := validateUserInput(input, fieldName); err != nil {
		logger.Warn("Invalid user input", zap.String("field", fieldName), zap.Error(err))
		return "", err
	}
	
	sanitized := sanitizeUserInput(input)
	
	logger.Debug("Successfully read and validated user input", 
		zap.String("field", fieldName),
		zap.Int("original_length", len(input)),
		zap.Int("sanitized_length", len(sanitized)))
	
	return sanitized, nil
}

// PromptSecurePassword prompts for a password without echoing to screen
// Migrated from cmd/create/user.go promptSecurePassword
func PromptSecurePassword(rc *RuntimeContext, prompt string) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Check if we can read from terminal
	logger.Debug("Assessing secure password input capability")

	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", fmt.Errorf("stdin is not a terminal")
	}

	// INTERVENE - Read password securely
	fmt.Print(prompt)
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println() // Add newline after password input

	if err != nil {
		return "", fmt.Errorf("failed to read password: %w", err)
	}

	passwordStr := string(password)

	// EVALUATE - Validate password input
	if err := validatePasswordInput(passwordStr, "password"); err != nil {
		logger.Warn("Invalid password input", zap.Error(err))
		return "", err
	}
	
	// Sanitize password (conservative approach)
	sanitized := sanitizePasswordInput(passwordStr)

	logger.Debug("Successfully read secure password input")
	return sanitized, nil
}

// ReadInput safely reads input from stdin with validation (for non-interactive use)
func ReadInput(rc *RuntimeContext) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return "", fmt.Errorf("failed to read input: %w", err)
		}
		return "", fmt.Errorf("no input received")
	}
	
	input := scanner.Text()
	
	// Validate and sanitize
	if err := validateUserInput(input, "stdin"); err != nil {
		logger.Warn("Invalid stdin input", zap.Error(err))
		return "", err
	}
	
	sanitized := sanitizeUserInput(input)
	
	logger.Debug("Successfully read stdin input", 
		zap.Int("original_length", len(input)),
		zap.Int("sanitized_length", len(sanitized)))
	
	return sanitized, nil
}

// PromptInputWithValidation prompts for user input with validation and sanitization
func PromptInputWithValidation(rc *RuntimeContext, prompt, fieldName string) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS - Check if we can read from terminal
	logger.Debug("Assessing user input capability", zap.String("field", fieldName))
	
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", fmt.Errorf("stdin is not a terminal")
	}
	
	// INTERVENE - Read input with validation
	logger.Info("terminal prompt: " + prompt)
	fmt.Print(prompt)
	
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return "", fmt.Errorf("failed to read input: %w", err)
		}
		return "", fmt.Errorf("no input received")
	}
	
	input := scanner.Text()
	
	// EVALUATE - Validate and sanitize input
	if err := validateUserInput(input, fieldName); err != nil {
		logger.Warn("Invalid user input", zap.String("field", fieldName), zap.Error(err))
		return "", err
	}
	
	sanitized := sanitizeUserInput(input)
	
	logger.Debug("Successfully read and validated user input", 
		zap.String("field", fieldName),
		zap.Int("original_length", len(input)),
		zap.Int("sanitized_length", len(sanitized)))
	
	return sanitized, nil
}

// PromptYesNoSecure prompts for a yes/no response with validation
func PromptYesNoSecure(rc *RuntimeContext, prompt, fieldName string) (bool, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	input, err := PromptInputWithValidation(rc, prompt, fieldName)
	if err != nil {
		return false, err
	}
	
	result, err := parseYesNoInput(input, fieldName)
	if err != nil {
		logger.Warn("Invalid yes/no input", zap.String("field", fieldName), zap.Error(err))
		return false, err
	}
	
	logger.Debug("Successfully parsed yes/no input", 
		zap.String("field", fieldName),
		zap.Bool("result", result))
	
	return result, nil
}
