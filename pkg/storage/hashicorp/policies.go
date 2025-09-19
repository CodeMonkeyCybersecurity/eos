package hashicorp

import (
	"context"
	"encoding/json"
	"fmt"

	consulapi "github.com/hashicorp/consul/api"
	vaultapi "github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// StoragePolicyEngine handles storage policy evaluation and enforcement
type StoragePolicyEngine struct {
	consul *consulapi.Client
	vault  *vaultapi.Client
	logger otelzap.LoggerWithCtx
}

// StoragePolicy defines storage governance rules
type StoragePolicy struct {
	MaxVolumeSize      int64             `json:"max_volume_size"`
	RequireEncryption  bool              `json:"require_encryption"`
	AllowedProviders   []string          `json:"allowed_providers"`
	DefaultTags        map[string]string `json:"default_tags"`
	RetentionDays      int               `json:"retention_days"`
	BackupRequired     bool              `json:"backup_required"`
	AllowedRegions     []string          `json:"allowed_regions"`
}

// QuotaInfo represents storage quota information
type QuotaInfo struct {
	Namespace string `json:"namespace"`
	Limit     int64  `json:"limit"`
	Used      int64  `json:"used"`
	Available int64  `json:"available"`
}

// NewStoragePolicyEngine creates a new policy engine
func NewStoragePolicyEngine(consul *consulapi.Client, vault *vaultapi.Client, logger otelzap.LoggerWithCtx) *StoragePolicyEngine {
	return &StoragePolicyEngine{
		consul: consul,
		vault:  vault,
		logger: logger,
	}
}

// EvaluateStorageRequest evaluates a storage request against policies
func (spe *StoragePolicyEngine) EvaluateStorageRequest(ctx context.Context, req *VolumeRequest) (*PolicyDecision, error) {
	spe.logger.Info("Evaluating storage request",
		zap.String("volume_id", req.ID),
		zap.String("namespace", req.Namespace))

	// Get policies from Consul KV
	policies, err := spe.getStoragePolicies(ctx, req.Namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to get storage policies: %w", err)
	}

	decision := &PolicyDecision{
		Allowed: true,
		Reason:  "Request meets all policy requirements",
	}

	// Evaluate size limits
	if req.SizeBytes > policies.MaxVolumeSize {
		decision.Allowed = false
		decision.Reason = fmt.Sprintf("Volume size %d bytes exceeds maximum %d bytes",
			req.SizeBytes, policies.MaxVolumeSize)
		return decision, nil
	}

	// Evaluate encryption requirements
	if policies.RequireEncryption && !req.Encrypted {
		decision.Allowed = false
		decision.Reason = "Encryption is required by policy but not requested"
		return decision, nil
	}

	// Evaluate allowed providers
	if len(policies.AllowedProviders) > 0 {
		allowed := false
		for _, provider := range policies.AllowedProviders {
			if provider == req.Provider {
				allowed = true
				break
			}
		}
		if !allowed {
			decision.Allowed = false
			decision.Reason = fmt.Sprintf("Provider %s is not in allowed list: %v",
				req.Provider, policies.AllowedProviders)
			return decision, nil
		}
	}

	// Check quota limits via Vault
	quota, err := spe.checkQuota(ctx, req.Namespace)
	if err != nil {
		spe.logger.Warn("Failed to check quota", zap.Error(err))
		// Continue without quota check rather than failing
	} else if quota.Used+req.SizeBytes > quota.Limit {
		decision.Allowed = false
		decision.Reason = fmt.Sprintf("Would exceed storage quota: %d + %d > %d",
			quota.Used, req.SizeBytes, quota.Limit)
		return decision, nil
	}

	spe.logger.Info("Storage request approved", zap.String("volume_id", req.ID))
	return decision, nil
}

// getStoragePolicies retrieves storage policies from Consul
func (spe *StoragePolicyEngine) getStoragePolicies(ctx context.Context, namespace string) (*StoragePolicy, error) {
	// Try namespace-specific policy first
	key := fmt.Sprintf("storage/policies/%s", namespace)
	pair, _, err := spe.consul.KV().Get(key, &consulapi.QueryOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get policy from Consul: %w", err)
	}

	// Fall back to default policy if namespace-specific doesn't exist
	if pair == nil {
		key = "storage/policies/default"
		pair, _, err = spe.consul.KV().Get(key, &consulapi.QueryOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to get default policy from Consul: %w", err)
		}
	}

	// Use built-in defaults if no policy exists
	if pair == nil {
		return &StoragePolicy{
			MaxVolumeSize:     100 * 1024 * 1024 * 1024, // 100GB
			RequireEncryption: true,
			AllowedProviders:  []string{"aws-ebs", "gcp-pd", "azure-disk"},
			DefaultTags: map[string]string{
				"managed-by": "eos",
				"created-by": "hashicorp-storage-manager",
			},
			RetentionDays:  30,
			BackupRequired: true,
			AllowedRegions: []string{"us-east-1", "us-west-2", "eu-west-1"},
		}, nil
	}

	var policy StoragePolicy
	if err := json.Unmarshal(pair.Value, &policy); err != nil {
		return nil, fmt.Errorf("failed to unmarshal policy: %w", err)
	}

	return &policy, nil
}

// checkQuota checks storage quota via Vault
func (spe *StoragePolicyEngine) checkQuota(ctx context.Context, namespace string) (*QuotaInfo, error) {
	path := fmt.Sprintf("storage/quota/%s", namespace)

	secret, err := spe.vault.Logical().Read(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read quota from Vault: %w", err)
	}

	if secret == nil || secret.Data == nil {
		// Return default quota if none exists
		return &QuotaInfo{
			Namespace: namespace,
			Limit:     1024 * 1024 * 1024 * 1024, // 1TB default
			Used:      0,
			Available: 1024 * 1024 * 1024 * 1024,
		}, nil
	}

	return &QuotaInfo{
		Namespace: namespace,
		Limit:     int64(secret.Data["limit"].(float64)),
		Used:      int64(secret.Data["used"].(float64)),
		Available: int64(secret.Data["available"].(float64)),
	}, nil
}

// SetStoragePolicy sets a storage policy for a namespace
func (spe *StoragePolicyEngine) SetStoragePolicy(ctx context.Context, namespace string, policy *StoragePolicy) error {
	data, err := json.Marshal(policy)
	if err != nil {
		return fmt.Errorf("failed to marshal policy: %w", err)
	}

	key := fmt.Sprintf("storage/policies/%s", namespace)
	_, err = spe.consul.KV().Put(&consulapi.KVPair{
		Key:   key,
		Value: data,
	}, &consulapi.WriteOptions{})

	if err != nil {
		return fmt.Errorf("failed to store policy in Consul: %w", err)
	}

	spe.logger.Info("Storage policy updated",
		zap.String("namespace", namespace),
		zap.Int64("max_volume_size", policy.MaxVolumeSize))

	return nil
}

// UpdateQuota updates storage quota for a namespace
func (spe *StoragePolicyEngine) UpdateQuota(ctx context.Context, namespace string, quota *QuotaInfo) error {
	path := fmt.Sprintf("storage/quota/%s", namespace)

	data := map[string]interface{}{
		"limit":     quota.Limit,
		"used":      quota.Used,
		"available": quota.Available,
	}

	_, err := spe.vault.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("failed to update quota in Vault: %w", err)
	}

	spe.logger.Info("Storage quota updated",
		zap.String("namespace", namespace),
		zap.Int64("limit", quota.Limit),
		zap.Int64("used", quota.Used))

	return nil
}
