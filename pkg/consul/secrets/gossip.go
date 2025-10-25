// pkg/consul/secrets/gossip.go
//
// Gossip Encryption Key Management for Consul with Vault Integration
//
// This package implements HashiCorp best practices for storing Consul gossip
// encryption keys in Vault and enabling automatic rotation via Consul Template.
//
// Reference: https://developer.hashicorp.com/consul/tutorials/vault-secure/vault-kv-consul-secure-gossip
//
// Best Practices Implemented:
// 1. Generate cryptographically secure 32-byte (256-bit) gossip keys
// 2. Store keys in Vault KV secrets engine at consul/secret/gossip
// 3. Enable automatic key rotation with configurable TTL
// 4. Integrate with Consul Template for dynamic retrieval
//
// Last Updated: 2025-01-25

package secrets

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	vaultapi "github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

const (
	// GossipKeyVaultPath is the Vault KV path for Consul gossip encryption key
	// HashiCorp best practice: consul/secret/gossip
	GossipKeyVaultPath = "consul/secret/gossip"

	// GossipKeyLength is the required key length for Consul (32 bytes = 256 bits)
	GossipKeyLength = 32

	// GossipKeyRotationTTL is the recommended rotation interval
	// HashiCorp recommends regular rotation for security
	GossipKeyRotationTTL = 90 * 24 * time.Hour // 90 days
)

// GossipKeyMetadata contains metadata about a gossip encryption key
type GossipKeyMetadata struct {
	Key           string    // Base64-encoded gossip key
	GeneratedAt   time.Time // When key was generated
	GeneratedBy   string    // Who/what generated the key (e.g., "eos create consul")
	RotationDue   time.Time // When key should be rotated
	VaultPath     string    // Where key is stored in Vault
	Primary       bool      // Is this the primary (active) key?
	RotationIndex int       // Rotation sequence number
}

// GenerateGossipKey generates a cryptographically secure gossip encryption key
//
// This function generates a 32-byte (256-bit) key as required by Consul and
// encodes it to base64 format.
//
// Returns:
//   - Base64-encoded gossip key
//   - Error if generation fails
//
// Example:
//
//	key, err := GenerateGossipKey()
//	if err != nil {
//	    return fmt.Errorf("failed to generate gossip key: %w", err)
//	}
//	logger.Info("Generated gossip key", zap.String("key_preview", key[:16]+"..."))
func GenerateGossipKey() (string, error) {
	// Allocate 32-byte buffer for key material
	keyBytes := make([]byte, GossipKeyLength)

	// Fill with cryptographically secure random bytes
	if _, err := rand.Read(keyBytes); err != nil {
		return "", fmt.Errorf("failed to generate random key material: %w\n"+
			"This may indicate a system entropy issue.\n"+
			"Remediation:\n"+
			"  - Check available entropy: cat /proc/sys/kernel/random/entropy_avail\n"+
			"  - Ensure rng-tools is installed: apt install rng-tools\n"+
			"  - Check for hardware RNG: ls /dev/hwrng",
			err)
	}

	// Encode to base64 as required by Consul
	encodedKey := base64.StdEncoding.EncodeToString(keyBytes)

	return encodedKey, nil
}

// StoreGossipKeyInVault stores a gossip encryption key in Vault KV secrets engine
//
// This function stores the gossip key in Vault following HashiCorp best practices:
// - Path: consul/secret/gossip
// - Includes metadata for rotation tracking
// - Sets TTL hint for Consul Template integration
//
// Parameters:
//   - rc: Runtime context for logging
//   - vaultClient: Authenticated Vault client
//   - gossipKey: Base64-encoded gossip encryption key
//   - metadata: Additional metadata about the key
//
// Returns:
//   - Error if storage fails
//
// Example:
//
//	metadata := &GossipKeyMetadata{
//	    Key:           gossipKey,
//	    GeneratedAt:   time.Now(),
//	    GeneratedBy:   "eos create consul",
//	    RotationDue:   time.Now().Add(90 * 24 * time.Hour),
//	    Primary:       true,
//	    RotationIndex: 1,
//	}
//	if err := StoreGossipKeyInVault(rc, vaultClient, gossipKey, metadata); err != nil {
//	    return fmt.Errorf("failed to store gossip key: %w", err)
//	}
func StoreGossipKeyInVault(
	rc *eos_io.RuntimeContext,
	vaultClient *vaultapi.Client,
	gossipKey string,
	metadata *GossipKeyMetadata,
) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Storing Consul gossip encryption key in Vault",
		zap.String("vault_path", GossipKeyVaultPath))

	// Prepare data for Vault storage
	data := map[string]interface{}{
		"gossip":           gossipKey,
		"generated_at":     metadata.GeneratedAt.Format(time.RFC3339),
		"generated_by":     metadata.GeneratedBy,
		"rotation_due":     metadata.RotationDue.Format(time.RFC3339),
		"rotation_index":   metadata.RotationIndex,
		"primary":          metadata.Primary,
		"key_length":       GossipKeyLength,
		"encoding":         "base64",
		"algorithm":        "AES-256-GCM",
		"purpose":          "Consul gossip protocol encryption",
		"warning":          "This key encrypts Consul cluster gossip traffic - protect it carefully!",
		"recovery_steps":   "To retrieve: vault kv get -field=gossip consul/secret/gossip",
		"rotation_command": "eos update consul --rotate-gossip-key",
	}

	// Store in Vault KV v2 at consul/secret/gossip
	// NOTE: We use "consul" as the mount path, "secret/gossip" as the key path
	_, err := vaultClient.KVv2("consul").Put(rc.Ctx, "secret/gossip", data)
	if err != nil {
		return fmt.Errorf("failed to store gossip key in Vault: %w\n"+
			"Vault path: %s\n"+
			"Remediation:\n"+
			"  - Ensure Vault KV v2 engine is enabled at 'consul/': vault secrets enable -path=consul kv-v2\n"+
			"  - Check Vault token has write permissions to consul/data/secret/gossip\n"+
			"  - Verify Vault is unsealed: vault status\n"+
			"  - Check Vault logs: journalctl -u vault -n 50",
			err, GossipKeyVaultPath)
	}

	logger.Info("Gossip key stored in Vault successfully",
		zap.String("vault_path", GossipKeyVaultPath),
		zap.Time("rotation_due", metadata.RotationDue),
		zap.Int("rotation_index", metadata.RotationIndex))

	return nil
}

// GetGossipKeyFromVault retrieves the gossip encryption key from Vault
//
// This function retrieves the current gossip key from Vault KV storage.
// Used during Consul configuration to fetch the key for use.
//
// Parameters:
//   - ctx: Context for cancellation
//   - vaultClient: Authenticated Vault client
//
// Returns:
//   - GossipKeyMetadata with key and metadata
//   - Error if retrieval fails
//
// Example:
//
//	metadata, err := GetGossipKeyFromVault(ctx, vaultClient)
//	if err != nil {
//	    return fmt.Errorf("failed to retrieve gossip key: %w", err)
//	}
//	logger.Info("Retrieved gossip key", zap.Int("rotation_index", metadata.RotationIndex))
func GetGossipKeyFromVault(ctx context.Context, vaultClient *vaultapi.Client) (*GossipKeyMetadata, error) {
	// Read from Vault KV v2
	secret, err := vaultClient.KVv2("consul").Get(ctx, "secret/gossip")
	if err != nil {
		return nil, fmt.Errorf("failed to read gossip key from Vault: %w\n"+
			"Vault path: %s\n"+
			"Remediation:\n"+
			"  - Verify secret exists: vault kv get consul/secret/gossip\n"+
			"  - Check Vault token has read permissions to consul/data/secret/gossip\n"+
			"  - Ensure gossip key was stored during Consul creation: eos create consul",
			err, GossipKeyVaultPath)
	}

	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("gossip key not found in Vault at %s\n"+
			"The key may not have been stored during Consul installation.\n"+
			"Remediation:\n"+
			"  - Generate and store a new key: eos update consul --generate-gossip-key\n"+
			"  - Or manually store: vault kv put consul/secret/gossip gossip=\"$(consul keygen)\"",
			GossipKeyVaultPath)
	}

	// Extract gossip key
	gossipKey, ok := secret.Data["gossip"].(string)
	if !ok || gossipKey == "" {
		return nil, fmt.Errorf("invalid gossip key format in Vault (expected base64 string)")
	}

	// Parse metadata
	metadata := &GossipKeyMetadata{
		Key:       gossipKey,
		VaultPath: GossipKeyVaultPath,
		Primary:   true, // Default to primary
	}

	// Parse generated_at
	if genAtStr, ok := secret.Data["generated_at"].(string); ok {
		if genAt, err := time.Parse(time.RFC3339, genAtStr); err == nil {
			metadata.GeneratedAt = genAt
		}
	}

	// Parse rotation_due
	if rotDueStr, ok := secret.Data["rotation_due"].(string); ok {
		if rotDue, err := time.Parse(time.RFC3339, rotDueStr); err == nil {
			metadata.RotationDue = rotDue
		}
	}

	// Parse generated_by
	if genBy, ok := secret.Data["generated_by"].(string); ok {
		metadata.GeneratedBy = genBy
	}

	// Parse rotation_index
	if rotIdx, ok := secret.Data["rotation_index"].(float64); ok {
		metadata.RotationIndex = int(rotIdx)
	}

	// Parse primary flag
	if primary, ok := secret.Data["primary"].(bool); ok {
		metadata.Primary = primary
	}

	return metadata, nil
}

// EnableGossipKeyRotation configures Vault KV engine for gossip key rotation
//
// This function sets up the Vault KV secrets engine with appropriate TTL
// settings to support automatic gossip key rotation via Consul Template.
//
// Parameters:
//   - rc: Runtime context
//   - vaultClient: Authenticated Vault client
//
// Returns:
//   - Error if configuration fails
//
// Example:
//
//	if err := EnableGossipKeyRotation(rc, vaultClient); err != nil {
//	    return fmt.Errorf("failed to enable key rotation: %w", err)
//	}
func EnableGossipKeyRotation(rc *eos_io.RuntimeContext, vaultClient *vaultapi.Client) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Configuring Vault KV engine for gossip key rotation")

	// Check if KV v2 engine is enabled at consul/ mount
	mounts, err := vaultClient.Sys().ListMounts()
	if err != nil {
		return fmt.Errorf("failed to list Vault mounts: %w", err)
	}

	// Check if consul/ mount exists
	if _, exists := mounts["consul/"]; !exists {
		logger.Info("Enabling KV v2 secrets engine at consul/ mount")

		// Enable KV v2 engine
		if err := vaultClient.Sys().Mount("consul", &vaultapi.MountInput{
			Type:        "kv-v2",
			Description: "Consul secrets (gossip keys, TLS certs, configuration)",
			Config: vaultapi.MountConfigInput{
				DefaultLeaseTTL: GossipKeyRotationTTL.String(),
				MaxLeaseTTL:     (GossipKeyRotationTTL * 2).String(),
			},
		}); err != nil {
			return fmt.Errorf("failed to enable KV v2 engine at consul/ mount: %w", err)
		}

		logger.Info("KV v2 secrets engine enabled successfully",
			zap.String("mount", "consul/"),
			zap.Duration("default_ttl", GossipKeyRotationTTL))
	} else {
		logger.Info("KV v2 secrets engine already enabled at consul/ mount")
	}

	return nil
}

// ValidateGossipKey validates a gossip encryption key format
//
// Consul requires gossip keys to be exactly 32 bytes (256 bits) encoded in base64.
//
// Parameters:
//   - gossipKey: Base64-encoded key to validate
//
// Returns:
//   - Error if validation fails
//
// Example:
//
//	if err := ValidateGossipKey(key); err != nil {
//	    return fmt.Errorf("invalid gossip key: %w", err)
//	}
func ValidateGossipKey(gossipKey string) error {
	// Decode from base64
	keyBytes, err := base64.StdEncoding.DecodeString(gossipKey)
	if err != nil {
		return fmt.Errorf("gossip key is not valid base64: %w", err)
	}

	// Check length
	if len(keyBytes) != GossipKeyLength {
		return fmt.Errorf("gossip key must be exactly %d bytes, got %d bytes\n"+
			"Consul requires a 256-bit (32-byte) encryption key.\n"+
			"Generate a valid key with: consul keygen",
			GossipKeyLength, len(keyBytes))
	}

	return nil
}
