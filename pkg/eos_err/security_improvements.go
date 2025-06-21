package eos_err

import (
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
)

// SanitizeErrorMessage removes sensitive information from error messages
func SanitizeErrorMessage(err error) string {
	if err == nil {
		return ""
	}

	message := err.Error()

	// Use shared sanitization function
	return shared.SanitizeForLogging(message)
}

// SafeErrorSummary creates a safe error summary without sensitive information
func SafeErrorSummary(err error) string {
	if err == nil {
		return "success"
	}

	sanitized := SanitizeErrorMessage(err)

	// Categorize errors without exposing internals
	lowered := strings.ToLower(sanitized)

	switch {
	case strings.Contains(lowered, "permission") || strings.Contains(lowered, "unauthorized"):
		return "authentication_required"
	case strings.Contains(lowered, "not found"):
		return "resource_unavailable"
	case strings.Contains(lowered, "timeout"):
		return "service_timeout"
	case strings.Contains(lowered, "network") || strings.Contains(lowered, "connection"):
		return "connectivity_issue"
	case strings.Contains(lowered, "validation") || strings.Contains(lowered, "invalid"):
		return "input_validation_error"
	default:
		return "general_error"
	}
}
