package eos_err

import (
	"fmt"
	"strings"
)

// UserFriendlyError provides helpful, actionable error messages for users
type UserFriendlyError struct {
	Operation   string   // What was being attempted
	Cause       error    // The underlying error
	Suggestions []string // Helpful suggestions for resolution
}

// Error implements the error interface
func (e *UserFriendlyError) Error() string {
	var sb strings.Builder

	// Main error message
	sb.WriteString(fmt.Sprintf("Failed to %s", e.Operation))

	// Add cause if present
	if e.Cause != nil {
		sb.WriteString(fmt.Sprintf(": %v", e.Cause))
	}

	// Add suggestions
	if len(e.Suggestions) > 0 {
		sb.WriteString("\n\nTry the following:")
		for i, suggestion := range e.Suggestions {
			sb.WriteString(fmt.Sprintf("\n  %d. %s", i+1, suggestion))
		}
	}

	return sb.String()
}

// Unwrap returns the underlying error
func (e *UserFriendlyError) Unwrap() error {
	return e.Cause
}

// NewUserFriendlyError creates a user-friendly error with suggestions
func NewUserFriendlyError(operation string, cause error, suggestions ...string) error {
	return &UserFriendlyError{
		Operation:   operation,
		Cause:       cause,
		Suggestions: suggestions,
	}
}

// Common error scenarios with helpful suggestions

// NetworkError provides suggestions for network-related errors
func NetworkError(operation string, cause error) error {
	suggestions := []string{
		"Check your internet connection",
		"Verify the target service is running",
		"Check firewall rules (ufw status)",
		"Try using 'sudo' if accessing privileged ports",
		"Run 'eos read network diagnostics' for detailed analysis",
	}
	return NewUserFriendlyError(operation, cause, suggestions...)
}

// PermissionError provides suggestions for permission-related errors
func PermissionError(operation string, cause error) error {
	suggestions := []string{
		"Run the command with 'sudo'",
		"Check file/directory permissions with 'ls -la'",
		"Ensure your user is in the required groups (docker, sudo, etc.)",
		"Run 'eos read user permissions' to check your access",
	}
	return NewUserFriendlyError(operation, cause, suggestions...)
}

// ServiceError provides suggestions for service-related errors
func ServiceError(service, operation string, cause error) error {
	suggestions := []string{
		fmt.Sprintf("Check if %s is installed: which %s", service, service),
		fmt.Sprintf("Check service status: systemctl status %s", service),
		fmt.Sprintf("View service logs: journalctl -u %s -n 50", service),
		fmt.Sprintf("Try restarting: sudo systemctl restart %s", service),
		fmt.Sprintf("Install if missing: eos create %s", service),
	}
	return NewUserFriendlyError(fmt.Sprintf("%s %s", operation, service), cause, suggestions...)
}

// ConfigurationError provides suggestions for configuration errors
func ConfigurationError(component string, cause error) error {
	suggestions := []string{
		fmt.Sprintf("Check configuration syntax: eos read %s config --validate", component),
		fmt.Sprintf("View current configuration: eos read %s config", component),
		fmt.Sprintf("Reset to defaults: eos update %s --reset-config", component),
		"Review configuration documentation: eos read docs " + component,
		"Check for recent changes: git diff",
	}
	return NewUserFriendlyError(fmt.Sprintf("configure %s", component), cause, suggestions...)
}

// DependencyError provides suggestions for missing dependencies
func DependencyError(dependency, operation string, cause error) error {
	suggestions := []string{
		fmt.Sprintf("Install %s: eos create %s", dependency, dependency),
		fmt.Sprintf("Check if %s is in PATH: which %s", dependency, dependency),
		"Update PATH in ~/.bashrc or ~/.zshrc",
		"Run 'eos read system dependencies' to check all requirements",
		"Install all dependencies: eos create dependencies --all",
	}
	return NewUserFriendlyError(fmt.Sprintf("%s (requires %s)", operation, dependency), cause, suggestions...)
}

// VaultError provides suggestions for Vault-related errors
func VaultError(operation string, cause error) error {
	suggestions := []string{
		"Check Vault status: vault status",
		"Ensure Vault is unsealed: eos update vault unseal",
		"Verify VAULT_ADDR environment variable",
		"Check Vault logs: journalctl -u vault -n 50",
		"Re-authenticate: eos update vault auth",
	}
	return NewUserFriendlyError(fmt.Sprintf("%s (Vault operation)", operation), cause, suggestions...)
}

// DatabaseError provides suggestions for database-related errors
func DatabaseError(operation string, cause error) error {
	suggestions := []string{
		"Check database connection: eos read database status",
		"Verify credentials: eos read database credentials",
		"Check if database is running: docker ps | grep postgres",
		"View database logs: eos read database logs",
		"Reset database: eos update database reset --confirm",
	}
	return NewUserFriendlyError(fmt.Sprintf("%s (database operation)", operation), cause, suggestions...)
}
