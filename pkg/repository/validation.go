// pkg/repository/validation.go
//
// Input validation for repository operations
// Prevents injection attacks and provides clear feedback

package repository

import (
	"fmt"
	"net/mail"
	"regexp"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
)

// InputValidator is a function that validates user input
type InputValidator func(string) error

// ValidationResult contains the result of input validation
type ValidationResult struct {
	Valid   bool
	Error   error
	Warning string
}

// ValidateRepositoryName checks if a repository name is valid
// SECURITY: Validates against path traversal, reserved names, invalid characters
func ValidateRepositoryName(name string) error {
	if name == "" {
		return eos_err.NewValidationError(
			"Repository name cannot be empty",
			"Provide a name for your repository",
		)
	}

	// Length check
	const maxRepoNameLength = 100
	if len(name) > maxRepoNameLength {
		return eos_err.NewValidationError(
			fmt.Sprintf("Repository name too long (%d characters, max %d)", len(name), maxRepoNameLength),
			"Choose a shorter name",
		)
	}

	// Gitea/GitHub reserved names (case-insensitive)
	reserved := map[string]bool{
		".":        true,
		"..":       true,
		"-":        true,
		"_":        true,
		"assets":   true,
		"avatars":  true,
		"user":     true,
		"org":      true,
		"explore":  true,
		"repo":     true,
		"api":      true,
		"admin":    true,
		"new":      true,
		"issues":   true,
		"pulls":    true,
		"commits":  true,
		"releases": true,
		"wiki":     true,
		"activity": true,
		"stars":    true,
		"forks":    true,
	}

	if reserved[strings.ToLower(name)] {
		return eos_err.NewValidationError(
			fmt.Sprintf("Repository name '%s' is reserved", name),
			"Reserved names: ., .., -, _, assets, avatars, user, org, api, admin, etc.",
			"Choose a different name",
		)
	}

	// Path traversal protection
	if strings.Contains(name, "..") {
		return eos_err.NewValidationError(
			"Repository name cannot contain consecutive dots '..'",
			"This is blocked for security (path traversal prevention)",
		)
	}

	// Pattern validation (alphanumeric, dash, underscore, dot)
	validRepoName := regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)
	if !validRepoName.MatchString(name) {
		return eos_err.NewValidationError(
			fmt.Sprintf("Repository name '%s' contains invalid characters", name),
			"Only letters, numbers, dots, dashes, and underscores are allowed",
			"Example: my-project-123, web.app, data_pipeline",
		)
	}

	// Check for leading/trailing special characters
	if strings.HasPrefix(name, ".") || strings.HasPrefix(name, "-") || strings.HasPrefix(name, "_") {
		return eos_err.NewValidationError(
			"Repository name cannot start with ., -, or _",
			fmt.Sprintf("Current: %s", name),
		)
	}
	if strings.HasSuffix(name, ".") || strings.HasSuffix(name, "-") || strings.HasSuffix(name, "_") {
		return eos_err.NewValidationError(
			"Repository name cannot end with ., -, or _",
			fmt.Sprintf("Current: %s", name),
		)
	}

	return nil
}

// Note: ValidateBranchName is already defined in git.go
// This file adds additional validation helpers that don't duplicate existing functions

// ValidateEmail checks if an email address is valid
// Uses RFC 5322 validation
func ValidateEmail(email string) error {
	if email == "" {
		return eos_err.NewValidationError(
			"Email address cannot be empty",
			"Provide a valid email address",
		)
	}

	// Use standard library email parser (RFC 5322)
	if _, err := mail.ParseAddress(email); err != nil {
		return eos_err.NewValidationError(
			fmt.Sprintf("Invalid email address: %s", email),
			"Provide a valid email in format: user@example.com",
			fmt.Sprintf("Parser error: %v", err),
		)
	}

	// Additional sanity checks
	if !strings.Contains(email, "@") || !strings.Contains(email, ".") {
		return eos_err.NewValidationError(
			fmt.Sprintf("Email address '%s' doesn't look valid", email),
			"Email must contain @ and a domain with .",
		)
	}

	// Security: Check for injection attempts
	dangerousPatterns := []string{
		"../",      // Path traversal
		"';",       // SQL injection
		"<script>", // XSS
		"${",       // Variable interpolation
		"$(",       // Command substitution
	}

	lowerEmail := strings.ToLower(email)
	for _, pattern := range dangerousPatterns {
		if strings.Contains(lowerEmail, pattern) {
			return eos_err.NewValidationError(
				"Email address contains suspicious characters",
				"Provide a standard email address",
			)
		}
	}

	return nil
}

// ValidateNonEmpty checks that input is not empty
func ValidateNonEmpty(input string) error {
	if strings.TrimSpace(input) == "" {
		return eos_err.NewValidationError(
			"Input cannot be empty",
			"Provide a value",
		)
	}
	return nil
}

// ValidateLength creates a validator for maximum length
func ValidateLength(maxLen int) InputValidator {
	return func(input string) error {
		if len(input) > maxLen {
			return eos_err.NewValidationError(
				fmt.Sprintf("Input too long (%d characters, max %d)", len(input), maxLen),
				"Provide a shorter value",
			)
		}
		return nil
	}
}

// ValidateNoPathTraversal checks for path traversal attempts
func ValidateNoPathTraversal(input string) error {
	if strings.Contains(input, "..") {
		return eos_err.NewValidationError(
			"Path traversal detected",
			"Suspicious input: "+input,
			"Use simple paths without '..'",
		)
	}
	return nil
}

// ValidateAlphanumeric checks that input contains only letters and numbers
func ValidateAlphanumeric(input string) error {
	if !regexp.MustCompile(`^[a-zA-Z0-9]+$`).MatchString(input) {
		return eos_err.NewValidationError(
			"Input must contain only letters and numbers",
			fmt.Sprintf("Invalid: %s", input),
		)
	}
	return nil
}

// CombineValidators creates a single validator from multiple validators
// All validators must pass for input to be valid
func CombineValidators(validators ...InputValidator) InputValidator {
	return func(input string) error {
		for _, validator := range validators {
			if err := validator(input); err != nil {
				return err
			}
		}
		return nil
	}
}

// SanitizeInput performs basic sanitization on user input
// Trims whitespace and removes control characters
func SanitizeInput(input string) string {
	// Trim whitespace
	input = strings.TrimSpace(input)

	// Remove control characters but preserve newlines if needed
	sanitized := strings.Builder{}
	for _, r := range input {
		// Keep printable characters and space
		if r >= 32 && r != 127 {
			sanitized.WriteRune(r)
		}
	}

	return sanitized.String()
}

// ValidateAndSanitize combines validation and sanitization
func ValidateAndSanitize(input string, validators ...InputValidator) (string, error) {
	// Sanitize first
	sanitized := SanitizeInput(input)

	// Then validate
	for _, validator := range validators {
		if err := validator(sanitized); err != nil {
			return "", err
		}
	}

	return sanitized, nil
}

// Note: min helper already exists in git.go
