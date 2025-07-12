package shared

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// SecurityError represents a security-related error with proper audit logging
type SecurityError struct {
	Code      string                 `json:"code"`
	Message   string                 `json:"message"`
	Details   string                 `json:"details,omitempty"`
	UserID    string                 `json:"user_id,omitempty"`
	Resource  string                 `json:"resource,omitempty"`
	Action    string                 `json:"action,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
	Severity  SecuritySeverity       `json:"severity"`
	Category  SecurityCategory       `json:"category"`
}

// SecuritySeverity defines the severity levels for security errors
type SecuritySeverity string

const (
	SeverityLow      SecuritySeverity = "low"
	SeverityMedium   SecuritySeverity = "medium"
	SeverityHigh     SecuritySeverity = "high"
	SeverityCritical SecuritySeverity = "critical"
)

// SecurityCategory defines categories of security errors
type SecurityCategory string

const (
	CategoryAuthentication  SecurityCategory = "authentication"
	CategoryAuthorization   SecurityCategory = "authorization"
	CategoryDataProtection  SecurityCategory = "data_protection"
	CategorySystemIntegrity SecurityCategory = "system_integrity"
	CategoryNetworkSecurity SecurityCategory = "network_security"
	CategoryCryptography    SecurityCategory = "cryptography"
	CategoryAudit          SecurityCategory = "audit"
	CategoryCompliance     SecurityCategory = "compliance"
)

// Error implements the error interface
func (se *SecurityError) Error() string {
	return fmt.Sprintf("[%s] %s: %s", se.Code, se.Category, se.Message)
}

// NewSecurityError creates a new security error with proper audit logging
func NewSecurityError(ctx context.Context, code, message string, severity SecuritySeverity, category SecurityCategory) *SecurityError {
	logger := otelzap.Ctx(ctx)
	
	err := &SecurityError{
		Code:     code,
		Message:  message,
		Severity: severity,
		Category: category,
		Metadata: make(map[string]interface{}),
	}
	
	// Log security event for audit trail
	logger.Error("Security error occurred",
		zap.String("security_code", code),
		zap.String("security_category", string(category)),
		zap.String("security_severity", string(severity)),
		zap.String("message", message),
		zap.String("event_type", "security_error"))
	
	return err
}

// WithDetails adds additional details to the security error
func (se *SecurityError) WithDetails(details string) *SecurityError {
	se.Details = details
	return se
}

// WithUser adds user information to the security error
func (se *SecurityError) WithUser(userID string) *SecurityError {
	se.UserID = userID
	return se
}

// WithResource adds resource information to the security error
func (se *SecurityError) WithResource(resource string) *SecurityError {
	se.Resource = resource
	return se
}

// WithAction adds action information to the security error
func (se *SecurityError) WithAction(action string) *SecurityError {
	se.Action = action
	return se
}

// WithMetadata adds metadata to the security error
func (se *SecurityError) WithMetadata(key string, value interface{}) *SecurityError {
	se.Metadata[key] = value
	return se
}

// Predefined security errors for common scenarios

// NewAuthenticationError creates an authentication failure error
func NewAuthenticationError(ctx context.Context, message string) *SecurityError {
	return NewSecurityError(ctx, "AUTH_001", message, SeverityHigh, CategoryAuthentication)
}

// NewAuthorizationError creates an authorization failure error
func NewAuthorizationError(ctx context.Context, message string) *SecurityError {
	return NewSecurityError(ctx, "AUTHZ_001", message, SeverityHigh, CategoryAuthorization)
}

// NewCryptographyError creates a cryptography-related error
func NewCryptographyError(ctx context.Context, message string) *SecurityError {
	return NewSecurityError(ctx, "CRYPTO_001", message, SeverityCritical, CategoryCryptography)
}

// NewDataProtectionError creates a data protection error
func NewDataProtectionError(ctx context.Context, message string) *SecurityError {
	return NewSecurityError(ctx, "DATA_001", message, SeverityHigh, CategoryDataProtection)
}

// NewSystemIntegrityError creates a system integrity error
func NewSystemIntegrityError(ctx context.Context, message string) *SecurityError {
	return NewSecurityError(ctx, "SYS_001", message, SeverityCritical, CategorySystemIntegrity)
}

// NewAuditError creates an audit-related error
func NewAuditError(ctx context.Context, message string) *SecurityError {
	return NewSecurityError(ctx, "AUDIT_001", message, SeverityMedium, CategoryAudit)
}

// NewComplianceError creates a compliance-related error
func NewComplianceError(ctx context.Context, message string) *SecurityError {
	return NewSecurityError(ctx, "COMP_001", message, SeverityHigh, CategoryCompliance)
}

// LogSecurityEvent logs a security event for audit purposes
func LogSecurityEvent(ctx context.Context, eventType, action, resource string, metadata map[string]interface{}) {
	logger := otelzap.Ctx(ctx)
	
	fields := []zap.Field{
		zap.String("event_type", eventType),
		zap.String("action", action),
		zap.String("resource", resource),
		zap.Time("timestamp", time.Now()),
	}
	
	// Add metadata fields
	for key, value := range metadata {
		fields = append(fields, zap.Any(key, value))
	}
	
	logger.Info("Security event", fields...)
}

// LogSecuritySuccess logs a successful security operation
func LogSecuritySuccess(ctx context.Context, action, resource string, metadata map[string]interface{}) {
	LogSecurityEvent(ctx, "security_success", action, resource, metadata)
}

// LogSecurityWarning logs a security warning
func LogSecurityWarning(ctx context.Context, action, resource, warning string, metadata map[string]interface{}) {
	logger := otelzap.Ctx(ctx)
	
	fields := []zap.Field{
		zap.String("event_type", "security_warning"),
		zap.String("action", action),
		zap.String("resource", resource),
		zap.String("warning", warning),
		zap.Time("timestamp", time.Now()),
	}
	
	// Add metadata fields
	for key, value := range metadata {
		fields = append(fields, zap.Any(key, value))
	}
	
	logger.Warn("Security warning", fields...)
}