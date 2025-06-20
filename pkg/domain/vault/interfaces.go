// Package vault defines domain interfaces for secret management
package vault

import (
	"context"
)

// SecretStore defines the core secret management operations
type SecretStore interface {
	// Get retrieves a secret by key
	Get(ctx context.Context, key string) (*Secret, error)
	
	// Set stores a secret
	Set(ctx context.Context, key string, secret *Secret) error
	
	// Delete removes a secret
	Delete(ctx context.Context, key string) error
	
	// List returns secrets under a prefix
	List(ctx context.Context, prefix string) ([]*Secret, error)
	
	// Exists checks if a secret exists without retrieving it
	Exists(ctx context.Context, key string) (bool, error)
}

// VaultAuthenticator handles vault authentication operations
type VaultAuthenticator interface {
	// Authenticate performs user authentication
	Authenticate(ctx context.Context, method string, credentials map[string]string) (*AuthResult, error)
	
	// GetAuthStatus returns current authentication status
	GetAuthStatus(ctx context.Context) (*AuthStatus, error)
	
	// RefreshToken refreshes the current authentication token
	RefreshToken(ctx context.Context) (*AuthResult, error)
}

// VaultManager handles vault lifecycle operations
type VaultManager interface {
	// Initialize initializes a new vault instance
	Initialize(ctx context.Context, config *InitConfig) (*InitResult, error)
	
	// Unseal unseals the vault with provided keys
	Unseal(ctx context.Context, keys []string) error
	
	// Seal seals the vault
	Seal(ctx context.Context) error
	
	// GetStatus returns vault health and status
	GetStatus(ctx context.Context) (*VaultStatus, error)
	
	// EnableAuth enables an authentication method
	EnableAuth(ctx context.Context, method string, config map[string]interface{}) error
	
	// EnableAudit enables audit logging
	EnableAudit(ctx context.Context, auditType string, config map[string]interface{}) error
}

// ConfigRepository handles vault configuration persistence
type ConfigRepository interface {
	// GetConfig retrieves configuration by key
	GetConfig(ctx context.Context, key string) (string, error)
	
	// SetConfig stores configuration
	SetConfig(ctx context.Context, key, value string) error
	
	// GetAllConfig returns all configuration
	GetAllConfig(ctx context.Context) (map[string]string, error)
	
	// DeleteConfig removes configuration
	DeleteConfig(ctx context.Context, key string) error
}

// AuditRepository handles audit logging
type AuditRepository interface {
	// Record records an audit event
	Record(ctx context.Context, event *AuditEvent) error
	
	// Query retrieves audit events
	Query(ctx context.Context, filter *AuditFilter) ([]*AuditEvent, error)
	
	// GetStats returns audit statistics
	GetStats(ctx context.Context) (*AuditStats, error)
}