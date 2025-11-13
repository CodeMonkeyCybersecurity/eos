// Package secrets provides universal secret storage abstraction
//
// This file defines the SecretStore interface that abstracts away
// the underlying secret storage backend (Vault, Consul KV, AWS Secrets Manager, etc.)
//
// Design Philosophy:
//   - Backend-agnostic: Code using SecretStore shouldn't care about implementation
//   - Context-aware: All operations accept context.Context for proper timeout/cancellation
//   - Error transparency: Backends return specific errors (ErrSecretNotFound, ErrPermissionDenied)
//   - Optional features: Backends report capabilities (versioning, metadata support)
//
// Code Monkey Cybersecurity - "Cybersecurity. With humans."
//
// Last Updated: 2025-01-27
package secrets

import (
	"context"
	"errors"
)

// Common errors returned by SecretStore implementations
var (
	// ErrSecretNotFound indicates the requested secret does not exist
	ErrSecretNotFound = errors.New("secret not found")

	// ErrPermissionDenied indicates the current credentials lack access
	ErrPermissionDenied = errors.New("permission denied")

	// ErrNotSupported indicates the backend doesn't support this operation
	// Example: ConsulStore doesn't support versioning
	ErrNotSupported = errors.New("operation not supported by this backend")

	// ErrInvalidPath indicates the secret path format is invalid
	ErrInvalidPath = errors.New("invalid secret path")

	// ErrBackendUnavailable indicates the storage backend is unreachable
	ErrBackendUnavailable = errors.New("secret storage backend unavailable")
)

// SecretStore defines the universal interface for secret storage backends.
//
// This interface abstracts Vault, Consul KV, AWS Secrets Manager, and other backends.
// All implementations must be thread-safe and support context-based cancellation.
//
// Example usage:
//
//	store := secrets.NewVaultStore(client, "secret")
//	data, err := store.Get(ctx, "services/production/bionicgpt")
//	if errors.Is(err, secrets.ErrSecretNotFound) {
//	    // Handle missing secret
//	}
type SecretStore interface {
	// Core Operations
	// ===============

	// Get retrieves secret data at the specified path.
	//
	// Path format is backend-specific:
	//   - Vault: "services/production/bionicgpt" (no "secret/" prefix - added by store)
	//   - Consul: "hecate/secrets/postgres/password"
	//
	// Returns:
	//   - map[string]interface{}: Secret key-value pairs
	//   - ErrSecretNotFound: Secret doesn't exist at path
	//   - ErrPermissionDenied: Credentials lack read access
	//   - ErrBackendUnavailable: Backend unreachable
	Get(ctx context.Context, path string) (map[string]interface{}, error)

	// Put stores secret data at the specified path.
	//
	// Behavior:
	//   - Creates secret if it doesn't exist
	//   - Updates secret if it exists (creates new version for versioned backends)
	//   - Atomic operation (all keys written together)
	//
	// Returns:
	//   - ErrPermissionDenied: Credentials lack write access
	//   - ErrInvalidPath: Path format invalid
	//   - ErrBackendUnavailable: Backend unreachable
	Put(ctx context.Context, path string, data map[string]interface{}) error

	// Delete removes the secret at the specified path.
	//
	// Behavior:
	//   - For versioned backends (Vault): soft-delete (can be undeleted)
	//   - For non-versioned backends (Consul): permanent deletion
	//   - Idempotent: no error if secret doesn't exist
	//
	// Returns:
	//   - ErrPermissionDenied: Credentials lack delete access
	//   - ErrBackendUnavailable: Backend unreachable
	Delete(ctx context.Context, path string) error

	// Exists checks if a secret exists at the specified path.
	//
	// This is more efficient than Get() if you only need existence check.
	// Returns true if secret exists, false otherwise.
	//
	// Returns:
	//   - bool: true if secret exists
	//   - ErrPermissionDenied: Credentials lack read access
	//   - ErrBackendUnavailable: Backend unreachable
	Exists(ctx context.Context, path string) (bool, error)

	// List returns secret paths under the specified path prefix.
	//
	// Path format is backend-specific:
	//   - Vault: "services/production" returns ["bionicgpt", "consul", "authentik"]
	//   - Consul: "hecate/secrets" returns ["postgres/", "redis/", "authentik/"]
	//
	// Returns:
	//   - []string: List of secret names/paths (empty slice if none found)
	//   - ErrPermissionDenied: Credentials lack list access
	//   - ErrNotSupported: Backend doesn't support listing
	//   - ErrBackendUnavailable: Backend unreachable
	List(ctx context.Context, path string) ([]string, error)

	// Metadata Operations (Optional)
	// ==============================
	// These return ErrNotSupported if backend doesn't support metadata

	// GetMetadata retrieves metadata for a secret (TTL, owner, created time, etc.)
	//
	// Returns:
	//   - *Metadata: Secret metadata (nil if no metadata exists)
	//   - ErrSecretNotFound: Secret doesn't exist
	//   - ErrNotSupported: Backend doesn't support metadata
	//   - ErrBackendUnavailable: Backend unreachable
	GetMetadata(ctx context.Context, path string) (*Metadata, error)

	// PutMetadata stores metadata for a secret without modifying secret data.
	//
	// Metadata is NOT encrypted (audit-logged only).
	// Never store sensitive data in metadata.
	//
	// Returns:
	//   - ErrSecretNotFound: Secret doesn't exist (create secret first)
	//   - ErrNotSupported: Backend doesn't support metadata
	//   - ErrPermissionDenied: Credentials lack metadata write access
	//   - ErrBackendUnavailable: Backend unreachable
	PutMetadata(ctx context.Context, path string, metadata *Metadata) error

	// Backend Information
	// ===================

	// Name returns the backend type (e.g., "vault", "consul", "aws-secrets-manager")
	Name() string

	// SupportsVersioning reports whether this backend supports secret versioning
	// Example: Vault KV v2 = true, Consul KV = false
	SupportsVersioning() bool

	// SupportsMetadata reports whether this backend supports custom metadata
	// Example: Vault KV v2 = true, Consul KV = false
	SupportsMetadata() bool
}

// Metadata represents custom metadata attached to a secret.
//
// This is used for compliance, auditing, and automated rotation policies.
// Metadata is stored separately from secret data and is NOT encrypted.
//
// WARNING: NEVER put sensitive data in metadata (it's not encrypted).
//
// Example:
//
//	metadata := &secrets.Metadata{
//	    TTL:         "90d",
//	    CreatedBy:   "eos create bionicgpt",
//	    Purpose:     "Azure OpenAI API integration",
//	    Owner:       "bionicgpt",
//	    RotateAfter: "90d",
//	    Custom: map[string]string{
//	        "endpoint": "https://myazure.openai.azure.com",
//	        "model":    "gpt-4",
//	        "region":   "eastus",
//	    },
//	}
type Metadata struct {
	// TTL is the secret's time-to-live (e.g., "24h", "30d", "90d", "never")
	TTL string `json:"ttl,omitempty"`

	// CreatedBy identifies who/what created this secret (e.g., "eos", "user@host", "terraform")
	CreatedBy string `json:"created_by,omitempty"`

	// CreatedAt is the ISO 8601 timestamp of creation (e.g., "2025-01-27T10:30:00Z")
	CreatedAt string `json:"created_at,omitempty"`

	// Purpose is a human-readable description (e.g., "database auth", "API integration")
	Purpose string `json:"purpose,omitempty"`

	// Owner is the owning service (e.g., "bionicgpt", "authentik", "consul")
	Owner string `json:"owner,omitempty"`

	// RotateAfter is the rotation policy (e.g., "90d", "on_use", "never")
	RotateAfter string `json:"rotate_after,omitempty"`

	// Custom holds arbitrary key-value metadata
	// Example: {"endpoint": "...", "model": "gpt-4", "region": "eastus"}
	Custom map[string]string `json:"custom,omitempty"`
}

// StoreCapabilities reports what features a SecretStore implementation supports.
//
// Use this to determine which operations are available before calling them.
//
// Example:
//
//	caps := store.Capabilities()
//	if caps.Versioning {
//	    // Can use GetVersion(), ListVersions(), etc.
//	}
type StoreCapabilities struct {
	// Versioning indicates the backend supports multiple versions per secret
	Versioning bool

	// Metadata indicates the backend supports custom metadata storage
	Metadata bool

	// Listing indicates the backend supports listing secret paths
	Listing bool

	// AtomicOperations indicates the backend supports atomic multi-key operations
	AtomicOperations bool
}
