// Package vault provides infrastructure implementations for vault domain interfaces
package vault

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/domain/vault"
)

// VaultManagerImpl implements vault.VaultManager
type VaultManagerImpl struct {
	client *api.Client
	logger *zap.Logger
}

// NewVaultManager creates a new vault manager implementation
func NewVaultManager(client *api.Client, logger *zap.Logger) *VaultManagerImpl {
	return &VaultManagerImpl{
		client: client,
		logger: logger.Named("vault.manager"),
	}
}

// Initialize initializes a new vault instance
func (v *VaultManagerImpl) Initialize(ctx context.Context, config *vault.InitConfig) (*vault.InitResult, error) {
	v.logger.Info("Initializing vault",
		zap.Int("secret_shares", config.SecretShares),
		zap.Int("secret_threshold", config.SecretThreshold))

	// Check if vault is already initialized
	status, err := v.client.Sys().InitStatusWithContext(ctx)
	if err != nil {
		v.logger.Error("Failed to check initialization status", zap.Error(err))
		return nil, fmt.Errorf("failed to check vault init status: %w", err)
	}

	if status {
		v.logger.Info("Vault is already initialized")
		return &vault.InitResult{
			Initialized: true,
			Timestamp:   time.Now(),
		}, nil
	}

	// Prepare initialization request
	initReq := &api.InitRequest{
		SecretShares:      config.SecretShares,
		SecretThreshold:   config.SecretThreshold,
		RecoveryShares:    config.RecoveryShares,
		RecoveryThreshold: config.RecoveryThreshold,
		StoredShares:      config.StoredShares,
		PGPKeys:           config.PGPKeys,
		RootTokenPGPKey:   config.RootTokenPGPKey,
	}

	// Initialize vault
	initResp, err := v.client.Sys().InitWithContext(ctx, initReq)
	if err != nil {
		v.logger.Error("Vault initialization failed", zap.Error(err))
		return nil, fmt.Errorf("vault initialization failed: %w", err)
	}

	v.logger.Info("Vault initialized successfully",
		zap.Int("key_shares", len(initResp.Keys)),
		zap.Int("key_threshold", config.SecretThreshold))

	return &vault.InitResult{
		Keys:         initResp.Keys,
		KeysBase64:   []string{}, // KeysBase64 not available in current API
		RootToken:    initResp.RootToken,
		Initialized:  true,
		Timestamp:    time.Now(),
		KeyThreshold: config.SecretThreshold,
		KeyShares:    len(initResp.Keys),
	}, nil
}

// Unseal unseals the vault with provided keys
func (v *VaultManagerImpl) Unseal(ctx context.Context, keys []string) error {
	v.logger.Info("Unsealing vault", zap.Int("key_count", len(keys)))

	// Check current seal status
	status, err := v.GetStatus(ctx)
	if err != nil {
		return fmt.Errorf("failed to get vault status: %w", err)
	}

	if !status.Sealed {
		v.logger.Info("Vault is already unsealed")
		return nil
	}

	// Unseal with each key
	for i, key := range keys {
		unsealResp, err := v.client.Sys().UnsealWithContext(ctx, key)
		if err != nil {
			v.logger.Error("Unseal attempt failed",
				zap.Int("key_index", i),
				zap.Error(err))
			return fmt.Errorf("unseal failed with key %d: %w", i, err)
		}

		v.logger.Debug("Unseal progress",
			zap.Int("progress", unsealResp.Progress),
			zap.Int("threshold", unsealResp.T))

		if !unsealResp.Sealed {
			v.logger.Info("Vault unsealed successfully")
			return nil
		}
	}

	return fmt.Errorf("vault remains sealed after all keys")
}

// Seal seals the vault
func (v *VaultManagerImpl) Seal(ctx context.Context) error {
	v.logger.Info("Sealing vault")

	err := v.client.Sys().SealWithContext(ctx)
	if err != nil {
		v.logger.Error("Failed to seal vault", zap.Error(err))
		return fmt.Errorf("failed to seal vault: %w", err)
	}

	v.logger.Info("Vault sealed successfully")
	return nil
}

// GetStatus returns vault health and status
func (v *VaultManagerImpl) GetStatus(ctx context.Context) (*vault.VaultStatus, error) {
	// Get seal status
	sealStatus, err := v.client.Sys().SealStatusWithContext(ctx)
	if err != nil {
		v.logger.Error("Failed to get seal status", zap.Error(err))
		return nil, fmt.Errorf("failed to get vault seal status: %w", err)
	}

	// Get health status
	healthResp, err := v.client.Sys().HealthWithContext(ctx)
	if err != nil {
		// Health endpoint might return non-200 status codes that are still valid
		v.logger.Debug("Health check returned error", zap.Error(err))
	}

	status := &vault.VaultStatus{
		Initialized: sealStatus.Initialized,
		Sealed:      sealStatus.Sealed,
		Timestamp:   time.Now(),
		Progress:    sealStatus.Progress,
		Threshold:   sealStatus.T,
		Nonce:       sealStatus.Nonce,
	}

	if healthResp != nil {
		status.Standby = healthResp.Standby
		status.Version = healthResp.Version
		status.ClusterName = healthResp.ClusterName
		status.ClusterID = healthResp.ClusterID
		// ReplicationMode not available in current API version
	}

	v.logger.Debug("Vault status retrieved",
		zap.Bool("initialized", status.Initialized),
		zap.Bool("sealed", status.Sealed),
		zap.Bool("standby", status.Standby))

	return status, nil
}

// EnableAuth enables an authentication method
func (v *VaultManagerImpl) EnableAuth(ctx context.Context, method string, config map[string]interface{}) error {
	v.logger.Info("Enabling authentication method", zap.String("method", method))

	authPath := method
	// Use the method name as the path for all methods

	// Check if auth method is already enabled
	auths, err := v.client.Sys().ListAuthWithContext(ctx)
	if err != nil {
		v.logger.Error("Failed to list auth methods", zap.Error(err))
		return fmt.Errorf("failed to list auth methods: %w", err)
	}

	authPath = authPath + "/"
	if _, exists := auths[authPath]; exists {
		v.logger.Info("Authentication method already enabled", zap.String("method", method))
		return nil
	}

	// Enable the auth method
	authOptions := &api.EnableAuthOptions{
		Type:        method,
		Description: fmt.Sprintf("%s authentication", method),
		Config:      api.AuthConfigInput{},
	}

	// Apply configuration if provided
	for key, value := range config {
		switch key {
		case "default_lease_ttl":
			if ttl, ok := value.(string); ok {
				authOptions.Config.DefaultLeaseTTL = ttl
			}
		case "max_lease_ttl":
			if ttl, ok := value.(string); ok {
				authOptions.Config.MaxLeaseTTL = ttl
			}
		case "description":
			if desc, ok := value.(string); ok {
				authOptions.Description = desc
			}
		}
	}

	err = v.client.Sys().EnableAuthWithOptionsWithContext(ctx, authPath, authOptions)
	if err != nil {
		v.logger.Error("Failed to enable auth method",
			zap.String("method", method),
			zap.Error(err))
		return fmt.Errorf("failed to enable auth method %s: %w", method, err)
	}

	v.logger.Info("Authentication method enabled successfully", zap.String("method", method))
	return nil
}

// EnableAudit enables audit logging
func (v *VaultManagerImpl) EnableAudit(ctx context.Context, auditType string, config map[string]interface{}) error {
	v.logger.Info("Enabling audit device", zap.String("type", auditType))

	// Check if audit device is already enabled
	audits, err := v.client.Sys().ListAuditWithContext(ctx)
	if err != nil {
		v.logger.Error("Failed to list audit devices", zap.Error(err))
		return fmt.Errorf("failed to list audit devices: %w", err)
	}

	auditPath := auditType + "/"
	if _, exists := audits[auditPath]; exists {
		v.logger.Info("Audit device already enabled", zap.String("type", auditType))
		return nil
	}

	// Prepare audit options
	options := make(map[string]string)
	for key, value := range config {
		if str, ok := value.(string); ok {
			options[key] = str
		}
	}

	// Set default file path for file audit device
	if auditType == "file" && options["file_path"] == "" {
		options["file_path"] = "/var/log/eos/vault-audit.log"
	}

	auditOptions := &api.EnableAuditOptions{
		Type:        auditType,
		Description: fmt.Sprintf("%s audit device", auditType),
		Options:     options,
	}

	err = v.client.Sys().EnableAuditWithOptionsWithContext(ctx, auditPath, auditOptions)
	if err != nil {
		v.logger.Error("Failed to enable audit device",
			zap.String("type", auditType),
			zap.Error(err))
		return fmt.Errorf("failed to enable audit device %s: %w", auditType, err)
	}

	v.logger.Info("Audit device enabled successfully",
		zap.String("type", auditType),
		zap.Any("options", options))
	return nil
}
