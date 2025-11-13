// Package vault provides high-level secret management operations for EOS.
// This file implements the VaultSecretManager wrapper that provides
// environment-aware secret operations using the standardized path structure.
package vault

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	sharedvault "github.com/CodeMonkeyCybersecurity/eos/pkg/shared/vault"
	vaultapi "github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// VaultSecretManager provides high-level secret management operations
// using the standardized secret path structure (services/{environment}/{service}).
//
// This wrapper handles:
// - Environment-aware secret operations
// - KV v2 metadata and data access
// - Version history tracking
// - Error handling and logging
type VaultSecretManager struct {
	rc     *eos_io.RuntimeContext
	client *vaultapi.Client
	mount  string // KV v2 mount point (default: "secret")
}

// ServiceMetadata represents metadata about a service's secrets in Vault KV v2.
//
// This includes version history, timestamps, and the list of secret keys
// stored at the service's path.
type ServiceMetadata struct {
	// Path is the full Vault path (e.g., "secret/metadata/services/production/consul")
	Path string

	// CurrentVersion is the latest version number
	CurrentVersion int

	// CreatedTime is when the secret was first created
	CreatedTime time.Time

	// UpdatedTime is when the secret was last updated
	UpdatedTime time.Time

	// Keys is the list of secret key names in the service's secret bundle
	// Example: ["bootstrap-token", "encryption-key", "acl-token"]
	Keys []string

	// Versions contains detailed information about each version
	// Key: version number (1, 2, 3, ...)
	// Value: version metadata (created time, deleted time, destroyed flag)
	Versions map[int]VersionInfo

	// Custom metadata from Vault (TTL, owner, purpose, etc.)
	CustomMetadata map[string]string
}

// VersionInfo represents metadata about a specific secret version.
type VersionInfo struct {
	// CreatedTime is when this version was created
	CreatedTime time.Time

	// DeletedTime is when this version was soft-deleted (nil if not deleted)
	DeletedTime *time.Time

	// Destroyed indicates if this version was permanently destroyed
	Destroyed bool
}

// NewVaultSecretManager creates a new secret manager using an existing Vault client.
//
// The client should already be authenticated and configured.
// Use vault.GetVaultClient(rc) to obtain a properly configured client.
//
// Example:
//
//	client, err := vault.GetVaultClient(rc)
//	if err != nil {
//	    return err
//	}
//	secretMgr := vault.NewVaultSecretManager(rc, client)
func NewVaultSecretManager(rc *eos_io.RuntimeContext, client *vaultapi.Client) *VaultSecretManager {
	return &VaultSecretManager{
		rc:     rc,
		client: client,
		mount:  sharedvault.DefaultMount,
	}
}

// ListServicesInEnvironment lists all services with secrets in the specified environment.
//
// This performs a Vault LIST operation on the environment's metadata path.
//
// Example:
//
//	services, err := secretMgr.ListServicesInEnvironment(ctx, vault.EnvironmentProduction)
//	// Returns: [consul, authentik, bionicgpt, wazuh]
//
// Returns:
//   - []Service: List of services found in the environment
//   - error: If LIST operation fails or no secrets found
func (v *VaultSecretManager) ListServicesInEnvironment(ctx context.Context, env sharedvault.Environment) ([]sharedvault.Service, error) {
	logger := otelzap.Ctx(v.rc.Ctx)

	path := sharedvault.SecretListPath(v.mount, env)

	logger.Debug("Listing services in environment",
		zap.String("environment", string(env)),
		zap.String("path", path))

	// Perform LIST operation on metadata path
	secret, err := v.client.Logical().ListWithContext(ctx, path)
	if err != nil {
		logger.Error("Failed to list services",
			zap.String("environment", string(env)),
			zap.String("path", path),
			zap.Error(err))
		return nil, fmt.Errorf("failed to list services in environment '%s': %w", env, err)
	}

	if secret == nil || secret.Data == nil {
		logger.Debug("No secrets found in environment",
			zap.String("environment", string(env)))
		return []sharedvault.Service{}, nil
	}

	// Extract keys from LIST response
	keysRaw, ok := secret.Data["keys"]
	if !ok {
		logger.Debug("No keys field in LIST response",
			zap.String("environment", string(env)))
		return []sharedvault.Service{}, nil
	}

	keysSlice, ok := keysRaw.([]interface{})
	if !ok {
		logger.Warn("Keys field is not a slice",
			zap.String("environment", string(env)),
			zap.String("type", fmt.Sprintf("%T", keysRaw)))
		return []sharedvault.Service{}, nil
	}

	// Convert interface{} slice to Service slice
	services := make([]sharedvault.Service, 0, len(keysSlice))
	for _, key := range keysSlice {
		keyStr, ok := key.(string)
		if !ok {
			logger.Warn("List key is not a string",
				zap.String("type", fmt.Sprintf("%T", key)))
			continue
		}

		// Validate service name
		if err := sharedvault.ValidateService(keyStr); err != nil {
			logger.Debug("Skipping invalid service name",
				zap.String("service", keyStr),
				zap.Error(err))
			continue
		}

		services = append(services, sharedvault.Service(keyStr))
	}

	logger.Debug("Listed services in environment",
		zap.String("environment", string(env)),
		zap.Int("count", len(services)))

	return services, nil
}

// GetServiceMetadata retrieves metadata for a service's secrets.
//
// This includes version history, timestamps, key names, and custom metadata.
// Does NOT include the actual secret values (use GetServiceSecrets for that).
//
// Example:
//
//	metadata, err := secretMgr.GetServiceMetadata(ctx, vault.EnvironmentProduction, vault.ServiceConsul)
//
// Returns:
//   - *ServiceMetadata: Complete metadata information
//   - error: If metadata cannot be retrieved
func (v *VaultSecretManager) GetServiceMetadata(ctx context.Context, env sharedvault.Environment, svc sharedvault.Service) (*ServiceMetadata, error) {
	logger := otelzap.Ctx(v.rc.Ctx)

	path := sharedvault.SecretMetadataPath(v.mount, env, svc)

	logger.Debug("Getting service metadata",
		zap.String("environment", string(env)),
		zap.String("service", string(svc)),
		zap.String("path", path))

	// Read metadata from Vault
	secret, err := v.client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		logger.Error("Failed to read metadata",
			zap.String("environment", string(env)),
			zap.String("service", string(svc)),
			zap.Error(err))
		return nil, fmt.Errorf("failed to get metadata for service '%s' in '%s': %w", svc, env, err)
	}

	if secret == nil || secret.Data == nil {
		logger.Warn("No metadata found for service",
			zap.String("environment", string(env)),
			zap.String("service", string(svc)))
		return nil, fmt.Errorf("no metadata found for service '%s' in environment '%s'", svc, env)
	}

	// Parse metadata response
	metadata := &ServiceMetadata{
		Path:           path,
		Versions:       make(map[int]VersionInfo),
		CustomMetadata: make(map[string]string),
	}

	// Extract current version
	if currentVersionRaw, ok := secret.Data["current_version"]; ok {
		if currentVersion, ok := currentVersionRaw.(float64); ok {
			metadata.CurrentVersion = int(currentVersion)
		}
	}

	// Extract created time
	if createdTimeRaw, ok := secret.Data["created_time"]; ok {
		if createdTimeStr, ok := createdTimeRaw.(string); ok {
			if t, err := time.Parse(time.RFC3339, createdTimeStr); err == nil {
				metadata.CreatedTime = t
			}
		}
	}

	// Extract updated time
	if updatedTimeRaw, ok := secret.Data["updated_time"]; ok {
		if updatedTimeStr, ok := updatedTimeRaw.(string); ok {
			if t, err := time.Parse(time.RFC3339, updatedTimeStr); err == nil {
				metadata.UpdatedTime = t
			}
		}
	}

	// Extract version history
	if versionsRaw, ok := secret.Data["versions"]; ok {
		if versionsMap, ok := versionsRaw.(map[string]interface{}); ok {
			for versionStr, versionDataRaw := range versionsMap {
				// Parse version number from string key ("1", "2", "3")
				var versionNum int
				if _, err := fmt.Sscanf(versionStr, "%d", &versionNum); err != nil {
					continue
				}

				versionData, ok := versionDataRaw.(map[string]interface{})
				if !ok {
					continue
				}

				versionInfo := VersionInfo{}

				// Parse created time
				if createdTimeRaw, ok := versionData["created_time"]; ok {
					if createdTimeStr, ok := createdTimeRaw.(string); ok {
						if t, err := time.Parse(time.RFC3339, createdTimeStr); err == nil {
							versionInfo.CreatedTime = t
						}
					}
				}

				// Parse deletion time (may be empty string if not deleted)
				if deletionTimeRaw, ok := versionData["deletion_time"]; ok {
					if deletionTimeStr, ok := deletionTimeRaw.(string); ok && deletionTimeStr != "" {
						if t, err := time.Parse(time.RFC3339, deletionTimeStr); err == nil {
							versionInfo.DeletedTime = &t
						}
					}
				}

				// Parse destroyed flag
				if destroyedRaw, ok := versionData["destroyed"]; ok {
					if destroyed, ok := destroyedRaw.(bool); ok {
						versionInfo.Destroyed = destroyed
					}
				}

				metadata.Versions[versionNum] = versionInfo
			}
		}
	}

	// Extract custom metadata
	if customMetadataRaw, ok := secret.Data["custom_metadata"]; ok {
		if customMetadataMap, ok := customMetadataRaw.(map[string]interface{}); ok {
			for key, valueRaw := range customMetadataMap {
				if valueStr, ok := valueRaw.(string); ok {
					metadata.CustomMetadata[key] = valueStr
				}
			}
		}
	}

	// Get the list of keys by reading the actual data (we need to know what secrets exist)
	dataPath := sharedvault.SecretDataPath(v.mount, env, svc)
	dataSecret, err := v.client.Logical().ReadWithContext(ctx, dataPath)
	if err == nil && dataSecret != nil && dataSecret.Data != nil {
		if dataField, ok := dataSecret.Data["data"]; ok {
			if dataMap, ok := dataField.(map[string]interface{}); ok {
				metadata.Keys = make([]string, 0, len(dataMap))
				for key := range dataMap {
					metadata.Keys = append(metadata.Keys, key)
				}
				sort.Strings(metadata.Keys) // Sort for consistent output
			}
		}
	}

	logger.Debug("Retrieved service metadata",
		zap.String("environment", string(env)),
		zap.String("service", string(svc)),
		zap.Int("current_version", metadata.CurrentVersion),
		zap.Int("key_count", len(metadata.Keys)))

	return metadata, nil
}

// GetServiceSecrets retrieves all secret values for a service.
//
// This returns the actual secret data (passwords, tokens, keys, etc.).
// The returned map contains key-value pairs where keys are secret names
// (e.g., "bootstrap-token", "api-key") and values are the secret strings.
//
// WARNING: This exposes sensitive data. Use with caution.
//
// Example:
//
//	secrets, err := secretMgr.GetServiceSecrets(ctx, vault.EnvironmentProduction, vault.ServiceConsul)
//	bootstrapToken := secrets["bootstrap-token"].(string)
//
// Returns:
//   - map[string]interface{}: Secret key-value pairs
//   - error: If secrets cannot be retrieved
func (v *VaultSecretManager) GetServiceSecrets(ctx context.Context, env sharedvault.Environment, svc sharedvault.Service) (map[string]interface{}, error) {
	logger := otelzap.Ctx(v.rc.Ctx)

	path := sharedvault.SecretDataPath(v.mount, env, svc)

	logger.Debug("Getting service secrets",
		zap.String("environment", string(env)),
		zap.String("service", string(svc)),
		zap.String("path", path))

	// Read data from Vault
	secret, err := v.client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		logger.Error("Failed to read secrets",
			zap.String("environment", string(env)),
			zap.String("service", string(svc)),
			zap.Error(err))
		return nil, fmt.Errorf("failed to get secrets for service '%s' in '%s': %w", svc, env, err)
	}

	if secret == nil || secret.Data == nil {
		logger.Warn("No secrets found for service",
			zap.String("environment", string(env)),
			zap.String("service", string(svc)))
		return nil, fmt.Errorf("no secrets found for service '%s' in environment '%s'", svc, env)
	}

	// KV v2 wraps the actual data in a "data" field
	dataField, ok := secret.Data["data"]
	if !ok {
		logger.Warn("No data field in secret response",
			zap.String("environment", string(env)),
			zap.String("service", string(svc)))
		return nil, fmt.Errorf("invalid secret format for service '%s' in environment '%s'", svc, env)
	}

	dataMap, ok := dataField.(map[string]interface{})
	if !ok {
		logger.Warn("Data field is not a map",
			zap.String("environment", string(env)),
			zap.String("service", string(svc)),
			zap.String("type", fmt.Sprintf("%T", dataField)))
		return nil, fmt.Errorf("invalid secret data format for service '%s' in environment '%s'", svc, env)
	}

	logger.Debug("Retrieved service secrets",
		zap.String("environment", string(env)),
		zap.String("service", string(svc)),
		zap.Int("key_count", len(dataMap)))

	return dataMap, nil
}
