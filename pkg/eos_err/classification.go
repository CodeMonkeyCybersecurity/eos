// pkg/eos_err/classification.go
//
// Error classification system with proper exit codes
// Extends existing UserError/UserFriendlyError infrastructure

package eos_err

import (
	"errors"
	"fmt"
	"strings"
)

// ErrorCategory classifies errors for appropriate handling
type ErrorCategory int

const (
	// CategorySystem - OS/filesystem issues (exit 1)
	CategorySystem ErrorCategory = iota
	// CategoryValidation - Input validation failures (exit 2)
	CategoryValidation
	// CategoryNetwork - Network/connectivity issues (exit 1)
	CategoryNetwork
	// CategoryGit - Git-specific errors (exit 1)
	CategoryGit
	// CategoryUser - User cancelled/interrupted (exit 130)
	CategoryUser
	// CategoryInternal - Bugs in EOS itself (exit 3)
	CategoryInternal
	// CategoryDependency - Missing dependencies (exit 1)
	CategoryDependency
	// CategoryPermission - Permission denied (exit 1)
	CategoryPermission
)

// ClassifiedError wraps an error with category and remediation info
type ClassifiedError struct {
	Category    ErrorCategory
	Message     string
	Cause       error
	Remediation []string
	DocsURL     string
}

// Error implements the error interface
func (e *ClassifiedError) Error() string {
	var sb strings.Builder

	// Main error message
	sb.WriteString(e.Message)

	// Add cause if present and different from message
	if e.Cause != nil && e.Cause.Error() != e.Message {
		sb.WriteString(fmt.Sprintf("\n\nCause: %v", e.Cause))
	}

	// Add remediation steps
	if len(e.Remediation) > 0 {
		sb.WriteString("\n\nHow to fix:")
		for i, step := range e.Remediation {
			sb.WriteString(fmt.Sprintf("\n  %d. %s", i+1, step))
		}
	}

	// Add documentation link if available
	if e.DocsURL != "" {
		sb.WriteString(fmt.Sprintf("\n\nDocumentation: %s", e.DocsURL))
	}

	return sb.String()
}

// Unwrap returns the underlying error
func (e *ClassifiedError) Unwrap() error {
	return e.Cause
}

// ExitCode returns the appropriate exit code for this error category
func (e *ClassifiedError) ExitCode() int {
	switch e.Category {
	case CategoryUser:
		return 130 // Standard for SIGINT (Ctrl-C)
	case CategoryValidation:
		return 2 // Invalid input/arguments
	case CategoryInternal:
		return 3 // Internal error/bug
	default:
		return 1 // General error
	}
}

// GetExitCode extracts exit code from any error
// Returns 0 for nil, appropriate code for classified errors, 1 for others
func GetExitCode(err error) int {
	if err == nil {
		return 0
	}

	// Check if it's a classified error
	var classified *ClassifiedError
	if errors.As(err, &classified) {
		return classified.ExitCode()
	}

	// Check if it's a user error (expected, user-fixable)
	if IsExpectedUserError(err) {
		return 0 // User errors don't fail the program
	}

	// Default to general error
	return 1
}

// NewValidationError creates an error for input validation failures
func NewValidationError(message string, remediation ...string) error {
	return &ClassifiedError{
		Category:    CategoryValidation,
		Message:     message,
		Remediation: remediation,
	}
}

// NewDependencyError creates an error for missing dependencies
func NewDependencyError(dependency, operation string, remediation ...string) error {
	return &ClassifiedError{
		Category: CategoryDependency,
		Message: fmt.Sprintf("%s is required for %s but not found",
			dependency, operation),
		Remediation: remediation,
	}
}

// NewGitError creates an error for git-specific issues
func NewGitError(message string, cause error, remediation ...string) error {
	return &ClassifiedError{
		Category:    CategoryGit,
		Message:     message,
		Cause:       cause,
		Remediation: remediation,
	}
}

// NewFilesystemError creates an error for filesystem issues
func NewFilesystemError(message string, cause error, remediation ...string) error {
	return &ClassifiedError{
		Category:    CategorySystem,
		Message:     message,
		Cause:       cause,
		Remediation: remediation,
	}
}

// NewPermissionError creates an error for permission issues
func NewPermissionError(resource, operation string, remediation ...string) error {
	return &ClassifiedError{
		Category: CategoryPermission,
		Message: fmt.Sprintf("Permission denied: cannot %s %s",
			operation, resource),
		Remediation: remediation,
	}
}

// NewNetworkError creates an error for network issues
func NewNetworkError(message string, cause error, remediation ...string) error {
	return &ClassifiedError{
		Category:    CategoryNetwork,
		Message:     message,
		Cause:       cause,
		Remediation: remediation,
	}
}

// NewInternalError creates an error for EOS bugs
// These should be reported to developers
func NewInternalError(message string, cause error) error {
	return &ClassifiedError{
		Category: CategoryInternal,
		Message:  message,
		Cause:    cause,
		Remediation: []string{
			"This is likely a bug in EOS",
			"Please report at: https://github.com/anthropics/claude-code/issues",
			"Include this error message and steps to reproduce",
		},
	}
}

// NewUserCancelledError creates an error for user-initiated cancellation
func NewUserCancelledError(operation string) error {
	return &ClassifiedError{
		Category:    CategoryUser,
		Message:     fmt.Sprintf("Operation cancelled by user: %s", operation),
		Remediation: []string{"Run the command again to retry"},
	}
}

// IsRetryable determines if an error represents a transient condition
// that might succeed on retry
func IsRetryable(err error) bool {
	if err == nil {
		return false
	}

	errStr := strings.ToLower(err.Error())

	// Transient network errors
	if strings.Contains(errStr, "timeout") ||
		strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "temporary failure") ||
		strings.Contains(errStr, "try again") {
		return true
	}

	// Transient filesystem errors
	if strings.Contains(errStr, "resource temporarily unavailable") ||
		strings.Contains(errStr, "device busy") {
		return true
	}

	// Deterministic errors (NOT retryable)
	if strings.Contains(errStr, "not found") ||
		strings.Contains(errStr, "permission denied") ||
		strings.Contains(errStr, "invalid") ||
		strings.Contains(errStr, "already exists") ||
		strings.Contains(errStr, "not configured") {
		return false
	}

	// Check error category
	var classified *ClassifiedError
	if errors.As(err, &classified) {
		switch classified.Category {
		case CategoryValidation, CategoryDependency, CategoryPermission:
			return false // Deterministic, won't fix with retry
		case CategoryNetwork:
			return true // Network issues might be transient
		default:
			return false
		}
	}

	// Default to not retryable (fail-fast principle)
	return false
}

// ClassifyError attempts to classify an existing error
// Useful for wrapping third-party library errors
func ClassifyError(err error, context string) error {
	if err == nil {
		return nil
	}

	// Already classified
	var classified *ClassifiedError
	if errors.As(err, &classified) {
		return err
	}

	errStr := strings.ToLower(err.Error())

	// Try to infer category from error message
	switch {
	case strings.Contains(errStr, "permission denied"):
		return NewPermissionError(context, "access", err.Error())

	case strings.Contains(errStr, "not found"),
		strings.Contains(errStr, "no such file"),
		strings.Contains(errStr, "does not exist"):
		return NewFilesystemError(
			fmt.Sprintf("%s: resource not found", context),
			err,
			"Check that the path or resource exists",
			"Verify spelling and case sensitivity",
		)

	case strings.Contains(errStr, "timeout"),
		strings.Contains(errStr, "connection refused"),
		strings.Contains(errStr, "network unreachable"):
		return NewNetworkError(
			fmt.Sprintf("%s: network error", context),
			err,
			"Check your network connection",
			"Verify the remote service is accessible",
		)

	case strings.Contains(errStr, "invalid"),
		strings.Contains(errStr, "malformed"),
		strings.Contains(errStr, "syntax error"):
		return NewValidationError(
			fmt.Sprintf("%s: validation failed", context),
			"Check the input format",
			"Review command syntax with: eos help",
		)

	case strings.Contains(errStr, "command not found"),
		strings.Contains(errStr, "executable file not found"):
		return NewDependencyError(
			extractCommand(errStr),
			context,
			"Install the required dependency",
			"Check that it's in your PATH",
		)

	default:
		// Can't classify, return as system error
		return NewFilesystemError(
			fmt.Sprintf("%s failed", context),
			err,
		)
	}
}

// extractCommand attempts to extract command name from error message
func extractCommand(errMsg string) string {
	// Try to find pattern like: "exec: \"git\": executable file not found"
	if strings.Contains(errMsg, "exec:") {
		parts := strings.Split(errMsg, "\"")
		if len(parts) >= 2 {
			return parts[1]
		}
	}
	return "command"
}
