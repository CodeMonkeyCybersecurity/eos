package shared

import (
	"fmt"
	"strings"
)

// Common error handling utilities to reduce duplication across the codebase

// InstallationError represents standardized installation errors
type InstallationError struct {
	Tool    string
	Method  string
	Stage   string
	Err     error
}

func (e *InstallationError) Error() string {
	if e.Stage != "" {
		return fmt.Sprintf("failed to %s %s via %s: %v", e.Stage, e.Tool, e.Method, e.Err)
	}
	return fmt.Sprintf("failed to install %s via %s: %v", e.Tool, e.Method, e.Err)
}

func (e *InstallationError) Unwrap() error {
	return e.Err
}

// WrapInstallationError creates a standardized installation error
func WrapInstallationError(tool, method string, err error) error {
	if err == nil {
		return nil
	}
	return &InstallationError{
		Tool:   tool,
		Method: method,
		Stage:  "install",
		Err:    err,
	}
}

// WrapConfigurationError creates a standardized configuration error
func WrapConfigurationError(component string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("failed to configure %s: %w", component, err)
}

// WrapValidationError creates a standardized validation error
func WrapValidationError(field, value string) error {
	return fmt.Errorf("validation failed for field '%s': invalid value '%s'", field, value)
}

// WrapPrerequisiteError creates a standardized prerequisite check error
func WrapPrerequisiteError(tool string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("prerequisite check failed for %s: %v", tool, err)
}

// WrapFileOperationError creates a standardized file operation error
func WrapFileOperationError(operation, path string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("failed to %s file '%s': %w", operation, path, err)
}

// WrapNetworkError creates a standardized network operation error
func WrapNetworkError(operation, endpoint string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("network %s failed for endpoint '%s': %w", operation, endpoint, err)
}

// WrapHealthCheckError creates a standardized health check error
func WrapHealthCheckError(service string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("health check failed for %s: %w", service, err)
}

// ErrorCode represents standardized error codes
type ErrorCode string

const (
	// Installation related errors
	ErrorCodeInstallationFailed    ErrorCode = "INSTALLATION_FAILED"
	ErrorCodePrerequisiteFailed    ErrorCode = "PREREQUISITE_FAILED"
	ErrorCodeConfigurationFailed   ErrorCode = "CONFIGURATION_FAILED"
	
	// Validation related errors
	ErrorCodeValidationFailed      ErrorCode = "VALIDATION_FAILED"
	ErrorCodeRequiredFieldMissing  ErrorCode = "REQUIRED_FIELD_MISSING"
	
	// File operation errors
	ErrorCodeFileNotFound          ErrorCode = "FILE_NOT_FOUND"
	ErrorCodePermissionDenied      ErrorCode = "PERMISSION_DENIED"
	ErrorCodeFileOperationFailed   ErrorCode = "FILE_OPERATION_FAILED"
	
	// Network related errors
	ErrorCodeNetworkTimeout        ErrorCode = "NETWORK_TIMEOUT"
	ErrorCodeConnectionFailed      ErrorCode = "CONNECTION_FAILED"
	ErrorCodeUnauthorized          ErrorCode = "UNAUTHORIZED"
	
	// Service related errors
	ErrorCodeServiceUnavailable    ErrorCode = "SERVICE_UNAVAILABLE"
	ErrorCodeHealthCheckFailed     ErrorCode = "HEALTH_CHECK_FAILED"
)

// CodedError represents an error with a specific error code
type CodedError struct {
	Code    ErrorCode `json:"code"`
	Message string    `json:"message"`
	Details string    `json:"details,omitempty"`
	Err     error     `json:"-"`
}

func (e *CodedError) Error() string {
	if e.Details != "" {
		return fmt.Sprintf("[%s] %s: %s", e.Code, e.Message, e.Details)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

func (e *CodedError) Unwrap() error {
	return e.Err
}

// NewCodedError creates a new error with a specific code
func NewCodedError(code ErrorCode, message string, err error) *CodedError {
	return &CodedError{
		Code:    code,
		Message: message,
		Err:     err,
	}
}

// NewCodedErrorWithDetails creates a new error with code and details
func NewCodedErrorWithDetails(code ErrorCode, message, details string, err error) *CodedError {
	return &CodedError{
		Code:    code,
		Message: message,
		Details: details,
		Err:     err,
	}
}

// IsErrorCode checks if an error has a specific error code
func IsErrorCode(err error, code ErrorCode) bool {
	if codedErr, ok := err.(*CodedError); ok {
		return codedErr.Code == code
	}
	return false
}

// GetErrorCode extracts the error code from an error
func GetErrorCode(err error) ErrorCode {
	if codedErr, ok := err.(*CodedError); ok {
		return codedErr.Code
	}
	return ""
}

// ErrorCategory represents broad error categories for classification
type ErrorCategory string

const (
	CategoryUser    ErrorCategory = "USER"      // User correctable errors
	CategorySystem  ErrorCategory = "SYSTEM"    // System/environment errors  
	CategoryNetwork ErrorCategory = "NETWORK"   // Network related errors
	CategorySecurity ErrorCategory = "SECURITY" // Security related errors
)

// CategorizeError attempts to categorize an error based on its type and content
func CategorizeError(err error) ErrorCategory {
	if err == nil {
		return ""
	}
	
	// Check for specific error types
	// Note: This would need to check for user error types without importing eos_err
	// For now, use message-based detection
	
	if codedErr, ok := err.(*CodedError); ok {
		switch codedErr.Code {
		case ErrorCodeNetworkTimeout, ErrorCodeConnectionFailed:
			return CategoryNetwork
		case ErrorCodeUnauthorized:
			return CategorySecurity
		case ErrorCodeRequiredFieldMissing, ErrorCodeValidationFailed:
			return CategoryUser
		default:
			return CategorySystem
		}
	}
	
	// Check error message content for hints
	errMsg := strings.ToLower(err.Error())
	if strings.Contains(errMsg, "permission denied") || strings.Contains(errMsg, "unauthorized") {
		return CategorySecurity
	}
	if strings.Contains(errMsg, "connection") || strings.Contains(errMsg, "timeout") || strings.Contains(errMsg, "network") {
		return CategoryNetwork
	}
	if strings.Contains(errMsg, "not found") || strings.Contains(errMsg, "invalid") {
		return CategoryUser
	}
	
	return CategorySystem
}

// FormatErrorForUser formats an error message appropriately for user display
func FormatErrorForUser(err error) string {
	if err == nil {
		return ""
	}
	
	category := CategorizeError(err)
	switch category {
	case CategoryUser:
		return fmt.Sprintf("Error: %s", err.Error())
	case CategorySecurity:
		return fmt.Sprintf("Security Error: %s", err.Error())
	case CategoryNetwork:
		return fmt.Sprintf("Network Error: %s. Please check your network connection and try again.", err.Error())
	default:
		return fmt.Sprintf("System Error: %s. Please contact support if this persists.", err.Error())
	}
}

// MultiError represents multiple errors that occurred during an operation
type MultiError struct {
	Errors []error `json:"errors"`
	Context string `json:"context,omitempty"`
}

func (e *MultiError) Error() string {
	if len(e.Errors) == 0 {
		return "no errors"
	}
	
	if len(e.Errors) == 1 {
		if e.Context != "" {
			return fmt.Sprintf("%s: %s", e.Context, e.Errors[0].Error())
		}
		return e.Errors[0].Error()
	}
	
	var msgs []string
	for _, err := range e.Errors {
		msgs = append(msgs, err.Error())
	}
	
	result := fmt.Sprintf("multiple errors (%d): %s", len(e.Errors), strings.Join(msgs, "; "))
	if e.Context != "" {
		result = e.Context + ": " + result
	}
	return result
}

// Add adds an error to the MultiError
func (e *MultiError) Add(err error) {
	if err != nil {
		e.Errors = append(e.Errors, err)
	}
}

// HasErrors returns true if there are any errors
func (e *MultiError) HasErrors() bool {
	return len(e.Errors) > 0
}

// ToError returns the MultiError as an error if there are errors, otherwise nil
func (e *MultiError) ToError() error {
	if !e.HasErrors() {
		return nil
	}
	return e
}

// NewMultiError creates a new MultiError with optional context
func NewMultiError(context string) *MultiError {
	return &MultiError{
		Context: context,
		Errors:  make([]error, 0),
	}
}