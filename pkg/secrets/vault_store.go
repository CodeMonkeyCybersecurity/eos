// Package secrets provides VaultStore - a SecretStore implementation using HashiCorp Vault
//
// This implementation uses the stable vault/api SDK (v1.16+) with Vault KV v2 secret engine.
//
// Features:
//   - Context-aware operations (proper timeout/cancellation support)
//   - Secret versioning (Vault KV v2 feature)
//   - Custom metadata storage (TTL, owner, rotation policy)
//   - Thread-safe (vault/api client is thread-safe)
//
// Path Handling:
//   - Input path: "services/production/bionicgpt" (no "secret/" prefix)
//   - KVv2 API automatically prepends "secret/data/" for data operations
//   - KVv2 API automatically prepends "secret/metadata/" for metadata operations
//
// Code Monkey Cybersecurity - "Cybersecurity. With humans."
//
// Last Updated: 2025-01-27
package secrets

import (
	"context"
	"errors"
	"fmt"
	"strings"

	vaultapi "github.com/hashicorp/vault/api"
)

// VaultStore implements SecretStore using HashiCorp Vault KV v2 secret engine.
//
// This store provides:
//   - Secret versioning (rollback support)
//   - Custom metadata (TTL, owner, rotation policies)
//   - Audit logging (all operations are logged by Vault)
//   - High availability (if Vault cluster configured)
//
// Example:
//
//	client, _ := vault.GetVaultClient(rc)
//	store := secrets.NewVaultStore(client, "secret")
//	data, err := store.Get(ctx, "services/production/bionicgpt")
type VaultStore struct {
	client *vaultapi.Client
	mount  string // KV v2 mount point (typically "secret")
}

// NewVaultStore creates a VaultStore using an existing Vault client.
//
// The client must be:
//   - Authenticated (token set via client.SetToken() or VAULT_TOKEN env var)
//   - Configured with correct address (VAULT_ADDR env var)
//   - TLS configured if using HTTPS (VAULT_SKIP_VERIFY for self-signed certs)
//
// Use vault.GetVaultClient(rc) to obtain a properly configured client.
//
// Parameters:
//   - client: Authenticated Vault API client
//   - mount: KV v2 mount point (typically "secret")
//
// Example:
//
//	client, err := vault.GetVaultClient(rc)
//	if err != nil {
//	    return nil, fmt.Errorf("failed to create Vault client: %w", err)
//	}
//	store := secrets.NewVaultStore(client, "secret")
func NewVaultStore(client *vaultapi.Client, mount string) *VaultStore {
	return &VaultStore{
		client: client,
		mount:  mount,
	}
}

// Get retrieves secret data from Vault KV v2.
//
// Path format: "services/production/bionicgpt" (no "secret/" prefix)
// The KVv2 API automatically prepends "secret/data/" to form the full Vault path.
//
// Returns:
//   - map[string]interface{}: Secret key-value pairs (e.g., {"postgres_password": "...", "jwt_secret": "..."})
//   - ErrSecretNotFound: Secret doesn't exist at path
//   - ErrPermissionDenied: Token lacks read permission
//   - ErrBackendUnavailable: Vault unreachable or unhealthy
func (vs *VaultStore) Get(ctx context.Context, path string) (map[string]interface{}, error) {
	// CRITICAL: Use passed context (not context.Background()) for proper timeout/cancellation
	kvSecret, err := vs.client.KVv2(vs.mount).Get(ctx, path)
	if err != nil {
		// Parse Vault API errors
		if isVaultNotFoundError(err) {
			return nil, fmt.Errorf("%w at path %s", ErrSecretNotFound, path)
		}
		if isVaultPermissionError(err) {
			return nil, fmt.Errorf("%w: %v", ErrPermissionDenied, err)
		}
		// Network/connection errors
		return nil, fmt.Errorf("%w: failed to retrieve secret from Vault at %s: %v", ErrBackendUnavailable, path, err)
	}

	// Vault KV v2 returns nil for non-existent secrets (no error)
	if kvSecret == nil || kvSecret.Data == nil {
		return nil, fmt.Errorf("%w at path %s", ErrSecretNotFound, path)
	}

	return kvSecret.Data, nil
}

// Put stores secret data in Vault KV v2.
//
// Behavior:
//   - Creates secret if it doesn't exist
//   - Creates NEW VERSION if secret exists (Vault KV v2 versioning)
//   - All keys in data map are written atomically
//
// Path format: "services/production/bionicgpt"
// The KVv2 API automatically prepends "secret/data/" to form the full Vault path.
//
// Returns:
//   - ErrPermissionDenied: Token lacks create/update permission
//   - ErrInvalidPath: Path format invalid
//   - ErrBackendUnavailable: Vault unreachable or unhealthy
func (vs *VaultStore) Put(ctx context.Context, path string, data map[string]interface{}) error {
	// Validate path format
	if path == "" {
		return fmt.Errorf("%w: path cannot be empty", ErrInvalidPath)
	}
	if strings.HasPrefix(path, "secret/") {
		return fmt.Errorf("%w: path should not include 'secret/' prefix (got: %s)", ErrInvalidPath, path)
	}

	// CRITICAL: Use passed context (not context.Background())
	_, err := vs.client.KVv2(vs.mount).Put(ctx, path, data)
	if err != nil {
		// Parse Vault API errors
		if isVaultPermissionError(err) {
			return fmt.Errorf("%w: failed to store secret at %s: %v", ErrPermissionDenied, path, err)
		}
		// Network/connection errors
		return fmt.Errorf("%w: failed to store secret in Vault at %s: %v", ErrBackendUnavailable, path, err)
	}

	return nil
}

// Delete soft-deletes the latest version of a secret in Vault KV v2.
//
// Behavior:
//   - Soft-delete: secret can be undeleted later (Vault KV v2 feature)
//   - Only deletes LATEST version (older versions remain accessible)
//   - Idempotent: no error if secret doesn't exist
//
// To permanently destroy all versions, use Vault CLI:
//
//	vault kv metadata delete secret/data/services/production/bionicgpt
//
// Returns:
//   - ErrPermissionDenied: Token lacks delete permission
//   - ErrBackendUnavailable: Vault unreachable or unhealthy
func (vs *VaultStore) Delete(ctx context.Context, path string) error {
	// CRITICAL: Use passed context (not context.Background())
	err := vs.client.KVv2(vs.mount).Delete(ctx, path)
	if err != nil {
		// Vault returns error even if secret doesn't exist - filter those out
		if isVaultNotFoundError(err) {
			// Idempotent: treat "not found" as success
			return nil
		}
		if isVaultPermissionError(err) {
			return fmt.Errorf("%w: failed to delete secret at %s: %v", ErrPermissionDenied, path, err)
		}
		return fmt.Errorf("%w: failed to delete secret in Vault at %s: %v", ErrBackendUnavailable, path, err)
	}

	return nil
}

// Exists checks if a secret exists at the specified path.
//
// This is more efficient than Get() if you only need existence check,
// but still requires a Vault API call (no local cache).
//
// Returns:
//   - true: Secret exists
//   - false: Secret doesn't exist
//   - ErrPermissionDenied: Token lacks read permission
//   - ErrBackendUnavailable: Vault unreachable
func (vs *VaultStore) Exists(ctx context.Context, path string) (bool, error) {
	// Vault doesn't have a dedicated "exists" API - we use Get() and check for 404
	// CRITICAL: Use passed context (not context.Background())
	kvSecret, err := vs.client.KVv2(vs.mount).Get(ctx, path)
	if err != nil {
		// Not found = doesn't exist (not an error for Exists check)
		if isVaultNotFoundError(err) {
			return false, nil
		}
		// Permission denied is still an error
		if isVaultPermissionError(err) {
			return false, fmt.Errorf("%w: %v", ErrPermissionDenied, err)
		}
		// Network/connection errors
		return false, fmt.Errorf("%w: failed to check secret existence at %s: %v", ErrBackendUnavailable, path, err)
	}

	// Vault returns nil for non-existent secrets (no error)
	if kvSecret == nil || kvSecret.Data == nil {
		return false, nil
	}

	return true, nil
}

// List returns secret paths under the specified path prefix.
//
// Example:
//   - Input: "services/production"
//   - Output: ["bionicgpt", "consul", "authentik"]
//
// Note: Vault LIST operation requires "list" permission in policy.
//
// Returns:
//   - []string: List of secret names (empty slice if none found)
//   - ErrPermissionDenied: Token lacks list permission
//   - ErrBackendUnavailable: Vault unreachable
func (vs *VaultStore) List(ctx context.Context, path string) ([]string, error) {
	// Vault KVv2 LIST uses the metadata path: secret/metadata/{path}
	metadataPath := fmt.Sprintf("%s/metadata/%s", vs.mount, path)

	// CRITICAL: Use passed context (not context.Background())
	secret, err := vs.client.Logical().ListWithContext(ctx, metadataPath)
	if err != nil {
		if isVaultPermissionError(err) {
			return nil, fmt.Errorf("%w: failed to list secrets at %s: %v", ErrPermissionDenied, path, err)
		}
		return nil, fmt.Errorf("%w: failed to list secrets in Vault at %s: %v", ErrBackendUnavailable, path, err)
	}

	// No secrets found (not an error - return empty slice)
	if secret == nil || secret.Data == nil {
		return []string{}, nil
	}

	// Extract "keys" field from response
	keysRaw, ok := secret.Data["keys"]
	if !ok {
		return []string{}, nil
	}

	// Type assert to []interface{} (Vault returns this type)
	keysSlice, ok := keysRaw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected keys type from Vault: %T", keysRaw)
	}

	// Convert interface{} slice to string slice
	keys := make([]string, 0, len(keysSlice))
	for _, keyRaw := range keysSlice {
		keyStr, ok := keyRaw.(string)
		if !ok {
			continue // Skip non-string keys
		}
		keys = append(keys, keyStr)
	}

	return keys, nil
}

// GetMetadata retrieves custom metadata for a secret.
//
// Metadata includes:
//   - TTL, owner, rotation policy (from Custom field)
//   - Vault version info (current_version, created_time, updated_time)
//
// Returns:
//   - *Metadata: Secret metadata (nil if no custom metadata set)
//   - ErrSecretNotFound: Secret doesn't exist
//   - ErrPermissionDenied: Token lacks metadata read permission
//   - ErrBackendUnavailable: Vault unreachable
func (vs *VaultStore) GetMetadata(ctx context.Context, path string) (*Metadata, error) {
	// Vault KVv2 metadata path: secret/metadata/{path}
	metadataPath := fmt.Sprintf("%s/metadata/%s", vs.mount, path)

	// CRITICAL: Use passed context (not context.Background())
	secret, err := vs.client.Logical().ReadWithContext(ctx, metadataPath)
	if err != nil {
		if isVaultNotFoundError(err) {
			return nil, fmt.Errorf("%w at path %s", ErrSecretNotFound, path)
		}
		if isVaultPermissionError(err) {
			return nil, fmt.Errorf("%w: %v", ErrPermissionDenied, err)
		}
		return nil, fmt.Errorf("%w: failed to read metadata at %s: %v", ErrBackendUnavailable, path, err)
	}

	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("%w at path %s", ErrSecretNotFound, path)
	}

	// Extract custom_metadata field (this is where our metadata lives)
	customMetadataRaw, ok := secret.Data["custom_metadata"]
	if !ok {
		// No custom metadata set - return empty metadata (not an error)
		return &Metadata{Custom: make(map[string]string)}, nil
	}

	// Type assert to map[string]interface{} (Vault returns this type)
	customMetadataMap, ok := customMetadataRaw.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected custom_metadata type: %T", customMetadataRaw)
	}

	// Parse metadata fields
	metadata := &Metadata{
		Custom: make(map[string]string),
	}

	// Extract standard fields
	if ttl, ok := customMetadataMap["ttl"].(string); ok {
		metadata.TTL = ttl
	}
	if createdBy, ok := customMetadataMap["created_by"].(string); ok {
		metadata.CreatedBy = createdBy
	}
	if createdAt, ok := customMetadataMap["created_at"].(string); ok {
		metadata.CreatedAt = createdAt
	}
	if purpose, ok := customMetadataMap["purpose"].(string); ok {
		metadata.Purpose = purpose
	}
	if owner, ok := customMetadataMap["owner"].(string); ok {
		metadata.Owner = owner
	}
	if rotateAfter, ok := customMetadataMap["rotate_after"].(string); ok {
		metadata.RotateAfter = rotateAfter
	}

	// Extract custom fields (prefixed with "custom_")
	for key, valueRaw := range customMetadataMap {
		if strings.HasPrefix(key, "custom_") {
			if valueStr, ok := valueRaw.(string); ok {
				// Remove "custom_" prefix
				metadata.Custom[strings.TrimPrefix(key, "custom_")] = valueStr
			}
		}
	}

	return metadata, nil
}

// PutMetadata stores custom metadata for a secret.
//
// SECURITY WARNING: Metadata is NOT encrypted (only audit-logged).
// NEVER store sensitive data in metadata - use secret data storage instead.
//
// Metadata is stored separately from secret data and doesn't create a new secret version.
//
// Returns:
//   - ErrSecretNotFound: Secret doesn't exist (create secret first with Put())
//   - ErrPermissionDenied: Token lacks metadata write permission
//   - ErrBackendUnavailable: Vault unreachable
func (vs *VaultStore) PutMetadata(ctx context.Context, path string, metadata *Metadata) error {
	// Build custom_metadata map for Vault
	customMetadata := make(map[string]string)

	if metadata.TTL != "" {
		customMetadata["ttl"] = metadata.TTL
	}
	if metadata.CreatedBy != "" {
		customMetadata["created_by"] = metadata.CreatedBy
	}
	if metadata.CreatedAt != "" {
		customMetadata["created_at"] = metadata.CreatedAt
	}
	if metadata.Purpose != "" {
		customMetadata["purpose"] = metadata.Purpose
	}
	if metadata.Owner != "" {
		customMetadata["owner"] = metadata.Owner
	}
	if metadata.RotateAfter != "" {
		customMetadata["rotate_after"] = metadata.RotateAfter
	}

	// Add custom fields with "custom_" prefix (avoid collision with standard fields)
	for key, value := range metadata.Custom {
		customMetadata["custom_"+key] = value
	}

	// Vault KVv2 metadata path: secret/metadata/{path}
	metadataPath := fmt.Sprintf("%s/metadata/%s", vs.mount, path)

	// Write metadata to Vault
	// CRITICAL: Use passed context (not context.Background())
	_, err := vs.client.Logical().WriteWithContext(ctx, metadataPath, map[string]interface{}{
		"custom_metadata": customMetadata,
	})

	if err != nil {
		if isVaultNotFoundError(err) {
			return fmt.Errorf("%w: secret must exist before setting metadata at %s", ErrSecretNotFound, path)
		}
		if isVaultPermissionError(err) {
			return fmt.Errorf("%w: failed to write metadata at %s: %v", ErrPermissionDenied, path, err)
		}
		return fmt.Errorf("%w: failed to write metadata to Vault at %s: %v", ErrBackendUnavailable, path, err)
	}

	return nil
}

// Name returns the backend type identifier.
func (vs *VaultStore) Name() string {
	return "vault"
}

// SupportsVersioning reports that Vault KV v2 supports secret versioning.
func (vs *VaultStore) SupportsVersioning() bool {
	return true
}

// SupportsMetadata reports that Vault KV v2 supports custom metadata.
func (vs *VaultStore) SupportsMetadata() bool {
	return true
}

// Helper functions for error parsing
// ===================================

// isVaultNotFoundError checks if error indicates "secret not found" (404)
func isVaultNotFoundError(err error) bool {
	if err == nil {
		return false
	}

	// Vault API returns vaultapi.ResponseError for HTTP errors
	var respErr *vaultapi.ResponseError
	if errors.As(err, &respErr) {
		return respErr.StatusCode == 404
	}

	// Also check error message (fallback for non-ResponseError cases)
	errMsg := strings.ToLower(err.Error())
	return strings.Contains(errMsg, "not found") ||
		strings.Contains(errMsg, "no value found") ||
		strings.Contains(errMsg, "does not exist")
}

// isVaultPermissionError checks if error indicates "permission denied" (403)
func isVaultPermissionError(err error) bool {
	if err == nil {
		return false
	}

	// Vault API returns vaultapi.ResponseError for HTTP errors
	var respErr *vaultapi.ResponseError
	if errors.As(err, &respErr) {
		return respErr.StatusCode == 403
	}

	// Also check error message (fallback for non-ResponseError cases)
	errMsg := strings.ToLower(err.Error())
	return strings.Contains(errMsg, "permission denied") ||
		strings.Contains(errMsg, "access denied") ||
		strings.Contains(errMsg, "forbidden")
}
