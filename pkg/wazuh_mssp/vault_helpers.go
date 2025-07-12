// pkg/wazuh_mssp/vault_helpers.go
package wazuh_mssp

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// WriteSecret writes a secret to Vault using RuntimeContext
func WriteSecret(rc *eos_io.RuntimeContext, path string, data map[string]interface{}) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Writing secret to Vault", zap.String("path", path))

	client, err := vault.GetVaultClient(rc)
	if err != nil {
		return fmt.Errorf("failed to get vault client: %w", err)
	}

	_, err = client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("failed to write secret: %w", err)
	}

	return nil
}

// ReadSecret reads a secret from Vault using RuntimeContext
func ReadSecret(rc *eos_io.RuntimeContext, path string) (map[string]interface{}, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Reading secret from Vault", zap.String("path", path))

	client, err := vault.GetVaultClient(rc)
	if err != nil {
		return nil, fmt.Errorf("failed to get vault client: %w", err)
	}

	secret, err := client.Logical().Read(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read secret: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("secret not found at path: %s", path)
	}

	// Extract data from the secret
	if data, ok := secret.Data["data"].(map[string]interface{}); ok {
		return data, nil
	}

	// For KV v1, data is directly in secret.Data
	return secret.Data, nil
}

// DeleteSecret deletes a secret from Vault using RuntimeContext
func DeleteSecret(rc *eos_io.RuntimeContext, path string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Deleting secret from Vault", zap.String("path", path))

	client, err := vault.GetVaultClient(rc)
	if err != nil {
		return fmt.Errorf("failed to get vault client: %w", err)
	}

	_, err = client.Logical().Delete(path)
	if err != nil {
		return fmt.Errorf("failed to delete secret: %w", err)
	}

	return nil
}

// DeleteSecretRecursive deletes all secrets under a path
func DeleteSecretRecursive(rc *eos_io.RuntimeContext, path string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Deleting secrets recursively", zap.String("path", path))

	client, err := vault.GetVaultClient(rc)
	if err != nil {
		return fmt.Errorf("failed to get vault client: %w", err)
	}

	// List all secrets under the path
	secret, err := client.Logical().List(path)
	if err != nil {
		return fmt.Errorf("failed to list secrets: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return nil // No secrets to delete
	}

	if keys, ok := secret.Data["keys"].([]interface{}); ok {
		for _, key := range keys {
			keyStr := key.(string)
			fullPath := fmt.Sprintf("%s/%s", path, keyStr)

			if keyStr[len(keyStr)-1] == '/' {
				// It's a directory, recurse
				if err := DeleteSecretRecursive(rc, fullPath[:len(fullPath)-1]); err != nil {
					logger.Warn("Failed to delete directory",
						zap.String("path", fullPath),
						zap.Error(err))
				}
			} else {
				// It's a secret, delete it
				if err := DeleteSecret(rc, fullPath); err != nil {
					logger.Warn("Failed to delete secret",
						zap.String("path", fullPath),
						zap.Error(err))
				}
			}
		}
	}

	return nil
}

// CreatePolicy creates a Vault policy
func CreatePolicy(rc *eos_io.RuntimeContext, name string, policy string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Creating Vault policy", zap.String("name", name))

	client, err := vault.GetVaultClient(rc)
	if err != nil {
		return fmt.Errorf("failed to get vault client: %w", err)
	}

	err = client.Sys().PutPolicy(name, policy)
	if err != nil {
		return fmt.Errorf("failed to create policy: %w", err)
	}

	return nil
}

// GetStatus gets the Vault status
func GetStatus(rc *eos_io.RuntimeContext) (*StatusInfo, error) {
	client, err := vault.GetVaultClient(rc)
	if err != nil {
		return nil, fmt.Errorf("failed to get vault client: %w", err)
	}

	sealStatus, err := client.Sys().SealStatus()
	if err != nil {
		return nil, fmt.Errorf("failed to get seal status: %w", err)
	}

	return &StatusInfo{
		Sealed:      sealStatus.Sealed,
		Version:     sealStatus.Version,
		ClusterName: sealStatus.ClusterName,
		Initialized: sealStatus.Initialized,
		Standby:     false,
	}, nil
}

// StatusInfo represents Vault status information
type StatusInfo struct {
	Sealed      bool   `json:"sealed"`
	Version     string `json:"version"`
	ClusterName string `json:"cluster_name"`
	Initialized bool   `json:"initialized"`
	Standby     bool   `json:"standby"`
}

// HealthResponse represents Vault health response
type HealthResponse struct {
	Initialized bool `json:"initialized"`
	Sealed      bool `json:"sealed"`
	Standby     bool `json:"standby"`
}
