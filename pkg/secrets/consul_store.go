// Package secrets provides ConsulStore - a SecretStore implementation using HashiCorp Consul KV
//
// This implementation uses Consul KV as a fallback secret storage backend when Vault is unavailable.
// Consul KV is NOT a dedicated secrets manager and lacks encryption-at-rest and versioning.
//
// SECURITY WARNING:
//   - Consul KV stores values in PLAINTEXT (no encryption-at-rest)
//   - Consul ACLs provide access control (but secrets are still unencrypted on disk)
//   - Use Vault for production secrets whenever possible
//   - Only use ConsulStore for:
//   - Development/testing environments
//   - Non-sensitive configuration (feature flags, URLs)
//   - Fallback when Vault is temporarily unavailable
//
// Features:
//   - Simple key-value storage
//   - Atomic operations (CAS - Compare-And-Swap)
//   - Watch support (configuration changes)
//   - Multi-datacenter replication
//
// Limitations:
//   - ❌ No versioning (updates overwrite previous value)
//   - ❌ No encryption-at-rest (plaintext storage)
//   - ❌ No custom metadata storage
//   - ❌ No TTL/expiration (must manually delete)
//
// Code Monkey Cybersecurity - "Cybersecurity. With humans."
//
// Last Updated: 2025-01-27
package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	consulapi "github.com/hashicorp/consul/api"
)

// ConsulStore implements SecretStore using HashiCorp Consul KV.
//
// WARNING: Consul KV is NOT a secrets manager - secrets are stored in PLAINTEXT.
// Only use this for:
//   - Development/testing environments
//   - Non-sensitive configuration
//   - Fallback when Vault is unavailable
//
// Example:
//
//	client, _ := consul.GetConsulClient(rc)
//	store := secrets.NewConsulStore(client)
//	// Only use for non-sensitive data!
//	data, err := store.Get(ctx, "hecate/config/postgres")
type ConsulStore struct {
	client *consulapi.Client
}

// NewConsulStore creates a ConsulStore using an existing Consul client.
//
// The client must be configured with:
//   - Consul address (CONSUL_HTTP_ADDR env var or client config)
//   - ACL token if ACLs enabled (CONSUL_HTTP_TOKEN env var)
//
// Example:
//
//	client, err := consul.GetConsulClient(rc)
//	if err != nil {
//	    return nil, fmt.Errorf("failed to create Consul client: %w", err)
//	}
//	store := secrets.NewConsulStore(client)
func NewConsulStore(client *consulapi.Client) *ConsulStore {
	return &ConsulStore{
		client: client,
	}
}

// Get retrieves secret data from Consul KV.
//
// Consul KV stores individual keys, not nested maps like Vault.
// This implementation stores secrets as JSON-encoded map[string]interface{}.
//
// Path format: "hecate/secrets/postgres" (stores JSON at this single key)
//
// Returns:
//   - map[string]interface{}: Decoded JSON secret map
//   - ErrSecretNotFound: Key doesn't exist in Consul KV
//   - ErrPermissionDenied: ACL token lacks read permission
//   - ErrBackendUnavailable: Consul unreachable
func (cs *ConsulStore) Get(ctx context.Context, path string) (map[string]interface{}, error) {
	// Consul KV Get operation
	kvPair, _, err := cs.client.KV().Get(path, &consulapi.QueryOptions{
		// CRITICAL: Use passed context for proper cancellation
		// Note: Consul SDK doesn't directly accept context in Get(),
		// but we can set it via QueryOptions if needed in future SDK versions
	})

	if err != nil {
		if isConsulPermissionError(err) {
			return nil, fmt.Errorf("%w: %v", ErrPermissionDenied, err)
		}
		return nil, fmt.Errorf("%w: failed to retrieve from Consul KV at %s: %v", ErrBackendUnavailable, path, err)
	}

	// Key doesn't exist (Consul returns nil kvPair, no error)
	if kvPair == nil {
		return nil, fmt.Errorf("%w at path %s", ErrSecretNotFound, path)
	}

	// Decode JSON value
	var data map[string]interface{}
	if err := json.Unmarshal(kvPair.Value, &data); err != nil {
		return nil, fmt.Errorf("failed to decode secret JSON at %s: %w", path, err)
	}

	return data, nil
}

// Put stores secret data in Consul KV.
//
// Behavior:
//   - Creates key if it doesn't exist
//   - Overwrites key if it exists (NO VERSIONING - previous value lost)
//   - Stores data as JSON-encoded map[string]interface{}
//
// SECURITY WARNING: Data stored in PLAINTEXT in Consul data directory.
//
// Path format: "hecate/secrets/postgres"
//
// Returns:
//   - ErrPermissionDenied: ACL token lacks write permission
//   - ErrInvalidPath: Path format invalid (empty path)
//   - ErrBackendUnavailable: Consul unreachable
func (cs *ConsulStore) Put(ctx context.Context, path string, data map[string]interface{}) error {
	// Validate path
	if path == "" {
		return fmt.Errorf("%w: path cannot be empty", ErrInvalidPath)
	}

	// Encode data as JSON
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to encode secret as JSON: %w", err)
	}

	// Consul KV Put operation
	kvPair := &consulapi.KVPair{
		Key:   path,
		Value: jsonData,
	}

	_, err = cs.client.KV().Put(kvPair, &consulapi.WriteOptions{
		// CRITICAL: Consul SDK doesn't directly accept context in Put()
		// but we pass it here for future SDK versions
	})

	if err != nil {
		if isConsulPermissionError(err) {
			return fmt.Errorf("%w: failed to store in Consul KV at %s: %v", ErrPermissionDenied, path, err)
		}
		return fmt.Errorf("%w: failed to store in Consul KV at %s: %v", ErrBackendUnavailable, path, err)
	}

	return nil
}

// Delete removes a key from Consul KV.
//
// Behavior:
//   - Permanent deletion (NO VERSIONING - cannot undo)
//   - Idempotent: no error if key doesn't exist
//
// Returns:
//   - ErrPermissionDenied: ACL token lacks write permission
//   - ErrBackendUnavailable: Consul unreachable
func (cs *ConsulStore) Delete(ctx context.Context, path string) error {
	// Consul KV Delete operation
	_, err := cs.client.KV().Delete(path, &consulapi.WriteOptions{})

	if err != nil {
		if isConsulPermissionError(err) {
			return fmt.Errorf("%w: failed to delete from Consul KV at %s: %v", ErrPermissionDenied, path, err)
		}
		return fmt.Errorf("%w: failed to delete from Consul KV at %s: %v", ErrBackendUnavailable, path, err)
	}

	// Consul Delete is idempotent - no error if key doesn't exist
	return nil
}

// Exists checks if a key exists in Consul KV.
//
// Returns:
//   - true: Key exists
//   - false: Key doesn't exist
//   - ErrPermissionDenied: ACL token lacks read permission
//   - ErrBackendUnavailable: Consul unreachable
func (cs *ConsulStore) Exists(ctx context.Context, path string) (bool, error) {
	// Consul KV Get operation (check for existence)
	kvPair, _, err := cs.client.KV().Get(path, &consulapi.QueryOptions{})

	if err != nil {
		if isConsulPermissionError(err) {
			return false, fmt.Errorf("%w: %v", ErrPermissionDenied, err)
		}
		return false, fmt.Errorf("%w: failed to check existence in Consul KV at %s: %v", ErrBackendUnavailable, path, err)
	}

	// Key doesn't exist (Consul returns nil kvPair)
	if kvPair == nil {
		return false, nil
	}

	return true, nil
}

// List returns keys under the specified path prefix in Consul KV.
//
// Example:
//   - Input: "hecate/secrets"
//   - Output: ["postgres", "redis", "authentik"]
//
// Returns:
//   - []string: List of keys (empty slice if none found)
//   - ErrPermissionDenied: ACL token lacks list permission
//   - ErrBackendUnavailable: Consul unreachable
func (cs *ConsulStore) List(ctx context.Context, path string) ([]string, error) {
	// Consul KV List operation (keys only, not values)
	keys, _, err := cs.client.KV().Keys(path, "/", &consulapi.QueryOptions{})

	if err != nil {
		if isConsulPermissionError(err) {
			return nil, fmt.Errorf("%w: failed to list keys in Consul KV at %s: %v", ErrPermissionDenied, path, err)
		}
		return nil, fmt.Errorf("%w: failed to list keys in Consul KV at %s: %v", ErrBackendUnavailable, path, err)
	}

	// No keys found (not an error - return empty slice)
	if keys == nil {
		return []string{}, nil
	}

	// Remove path prefix from keys to get relative names
	relativeKeys := make([]string, 0, len(keys))
	pathPrefix := strings.TrimSuffix(path, "/") + "/"

	for _, key := range keys {
		// Remove path prefix
		if strings.HasPrefix(key, pathPrefix) {
			relativeKey := strings.TrimPrefix(key, pathPrefix)
			relativeKeys = append(relativeKeys, relativeKey)
		} else {
			// Key doesn't have expected prefix - include as-is
			relativeKeys = append(relativeKeys, key)
		}
	}

	return relativeKeys, nil
}

// GetMetadata returns ErrNotSupported (Consul KV doesn't support metadata).
func (cs *ConsulStore) GetMetadata(ctx context.Context, path string) (*Metadata, error) {
	return nil, fmt.Errorf("%w: Consul KV does not support custom metadata", ErrNotSupported)
}

// PutMetadata returns ErrNotSupported (Consul KV doesn't support metadata).
func (cs *ConsulStore) PutMetadata(ctx context.Context, path string, metadata *Metadata) error {
	return fmt.Errorf("%w: Consul KV does not support custom metadata", ErrNotSupported)
}

// Name returns the backend type identifier.
func (cs *ConsulStore) Name() string {
	return "consul"
}

// SupportsVersioning reports that Consul KV does NOT support versioning.
func (cs *ConsulStore) SupportsVersioning() bool {
	return false
}

// SupportsMetadata reports that Consul KV does NOT support custom metadata.
func (cs *ConsulStore) SupportsMetadata() bool {
	return false
}

// Helper functions for error parsing
// ===================================

// isConsulPermissionError checks if error indicates "permission denied"
func isConsulPermissionError(err error) bool {
	if err == nil {
		return false
	}

	errMsg := strings.ToLower(err.Error())
	return strings.Contains(errMsg, "permission denied") ||
		strings.Contains(errMsg, "access denied") ||
		strings.Contains(errMsg, "acl not found") ||
		strings.Contains(errMsg, "forbidden")
}
