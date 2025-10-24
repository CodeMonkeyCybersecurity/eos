// pkg/vault/raft_helpers.go
//
// DEPRECATED: This file contains Raft Integrated Storage helpers.
// Vault is transitioning to Consul storage backend as the recommended approach.
// These functions are maintained for backward compatibility but should not be
// used for new deployments.
//
// For new deployments, use Consul storage backend instead.
// See: https://developer.hashicorp.com/vault/docs/configuration/storage/consul

package vault

import (
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// DEPRECATED: RaftConfig contains configuration for Raft Integrated Storage deployment
// Use Consul storage backend instead for new deployments.
// Reference: vault-complete-specification-v1.0-raft-integrated.md
type RaftConfig struct {
	// Node configuration
	NodeID      string // Unique identifier for this node (e.g., "eos-vault-node1-az1")
	APIAddr     string // This node's API address (e.g., "https://10.0.1.10:8179")
	ClusterAddr string // This node's cluster address (e.g., "https://10.0.1.10:8180")

	// Storage configuration
	DataPath string // Path for Raft data storage (default: /opt/vault/data)

	// TLS configuration
	TLSCertPath string // Path to TLS certificate
	TLSKeyPath  string // Path to TLS private key

	// Multi-node cluster configuration
	RetryJoinNodes []shared.RetryJoinNode // Other nodes to join

	// Auto-unseal configuration
	AutoUnseal       bool
	AutoUnsealConfig string // HCL block for seal configuration

	// Operational settings
	PerformanceMultiplier int  // Performance tuning (default: 1)
	EnableTelemetry       bool // Enable Prometheus telemetry
}

// GenerateAutoUnsealConfig generates the HCL configuration block for auto-unseal
// Reference: vault-complete-specification-v1.0-raft-integrated.md Section: Auto-Unseal Setup
func GenerateAutoUnsealConfig(rc *eos_io.RuntimeContext, config *InstallConfig) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	if !config.AutoUnseal {
		logger.Debug("Auto-unseal not enabled, skipping config generation")
		return "", nil
	}

	logger.Info("Generating auto-unseal configuration",
		zap.String("type", config.AutoUnsealType))

	switch strings.ToLower(config.AutoUnsealType) {
	case "awskms", "aws":
		return generateAWSKMSConfig(rc, config)
	case "azurekeyvault", "azure":
		return generateAzureKeyVaultConfig(rc, config)
	case "gcpckms", "gcp":
		return generateGCPCKMSConfig(rc, config)
	default:
		logger.Error("Unsupported auto-unseal type",
			zap.String("type", config.AutoUnsealType),
			zap.Strings("supported", []string{"awskms", "azurekeyvault", "gcpckms"}))
		return "", fmt.Errorf("unsupported auto-unseal type: %s (supported: awskms, azurekeyvault, gcpckms)", config.AutoUnsealType)
	}
}

// generateAWSKMSConfig generates AWS KMS auto-unseal configuration
// Reference: vault-complete-specification-v1.0-raft-integrated.md - AWS KMS Auto-Unseal
func generateAWSKMSConfig(rc *eos_io.RuntimeContext, config *InstallConfig) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	if config.KMSKeyID == "" {
		logger.Error("AWS KMS auto-unseal configuration incomplete", zap.String("missing", "KMSKeyID"))
		return "", fmt.Errorf("AWS KMS auto-unseal requires KMSKeyID")
	}
	if config.KMSRegion == "" {
		config.KMSRegion = "ap-southeast-2" // Default to Australia
		logger.Debug("Using default AWS region", zap.String("region", config.KMSRegion))
	}

	logger.Info("Generated AWS KMS auto-unseal config",
		zap.String("region", config.KMSRegion),
		zap.String("kms_key_id", config.KMSKeyID))

	return fmt.Sprintf(`seal "awskms" {
  region     = "%s"
  kms_key_id = "%s"
}`, config.KMSRegion, config.KMSKeyID), nil
}

// generateAzureKeyVaultConfig generates Azure Key Vault auto-unseal configuration
// Reference: vault-complete-specification-v1.0-raft-integrated.md - Azure Key Vault Auto-Unseal
func generateAzureKeyVaultConfig(rc *eos_io.RuntimeContext, config *InstallConfig) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	requiredFields := map[string]string{
		"AzureTenantID":     config.AzureTenantID,
		"AzureClientID":     config.AzureClientID,
		"AzureClientSecret": config.AzureClientSecret,
		"AzureVaultName":    config.AzureVaultName,
		"AzureKeyName":      config.AzureKeyName,
	}

	for field, value := range requiredFields {
		if value == "" {
			logger.Error("Azure Key Vault auto-unseal configuration incomplete", zap.String("missing", field))
			return "", fmt.Errorf("Azure Key Vault auto-unseal requires %s", field)
		}
	}

	logger.Info("Generated Azure Key Vault auto-unseal config",
		zap.String("tenant_id", config.AzureTenantID),
		zap.String("vault_name", config.AzureVaultName),
		zap.String("key_name", config.AzureKeyName))

	return fmt.Sprintf(`seal "azurekeyvault" {
  tenant_id      = "%s"
  client_id      = "%s"
  client_secret  = "%s"
  vault_name     = "%s"
  key_name       = "%s"
}`, config.AzureTenantID, config.AzureClientID, config.AzureClientSecret,
		config.AzureVaultName, config.AzureKeyName), nil
}

// generateGCPCKMSConfig generates GCP Cloud KMS auto-unseal configuration
// Reference: vault-complete-specification-v1.0-raft-integrated.md - GCP Cloud KMS Auto-Unseal
func generateGCPCKMSConfig(rc *eos_io.RuntimeContext, config *InstallConfig) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	if config.GCPProject == "" {
		logger.Error("GCP Cloud KMS auto-unseal configuration incomplete", zap.String("missing", "GCPProject"))
		return "", fmt.Errorf("GCP Cloud KMS auto-unseal requires GCPProject")
	}
	if config.GCPLocation == "" {
		config.GCPLocation = "australia-southeast1" // Default to Australia
		logger.Debug("Using default GCP location", zap.String("location", config.GCPLocation))
	}
	if config.GCPKeyRing == "" {
		logger.Error("GCP Cloud KMS auto-unseal configuration incomplete", zap.String("missing", "GCPKeyRing"))
		return "", fmt.Errorf("GCP Cloud KMS auto-unseal requires GCPKeyRing")
	}
	if config.GCPCryptoKey == "" {
		logger.Error("GCP Cloud KMS auto-unseal configuration incomplete", zap.String("missing", "GCPCryptoKey"))
		return "", fmt.Errorf("GCP Cloud KMS auto-unseal requires GCPCryptoKey")
	}

	credentialsLine := ""
	if config.GCPCredentials != "" {
		credentialsLine = fmt.Sprintf("\n  credentials = \"%s\"", config.GCPCredentials)
	}

	logger.Info("Generated GCP Cloud KMS auto-unseal config",
		zap.String("project", config.GCPProject),
		zap.String("location", config.GCPLocation),
		zap.String("key_ring", config.GCPKeyRing),
		zap.String("crypto_key", config.GCPCryptoKey))

	return fmt.Sprintf(`seal "gcpckms" {
  project     = "%s"
  region      = "%s"
  key_ring    = "%s"
  crypto_key  = "%s"%s
}`, config.GCPProject, config.GCPLocation, config.GCPKeyRing,
		config.GCPCryptoKey, credentialsLine), nil
}

// DEPRECATED: RenderRaftConfig generates Vault configuration for Raft deployment
// This is a convenience wrapper around shared.RenderVaultConfigRaft
// Use Consul storage backend instead for new deployments.
func RenderRaftConfig(rc *eos_io.RuntimeContext, config *InstallConfig) (string, error) {
	log := otelzap.Ctx(rc.Ctx)
	log.Info("Generating Raft configuration",
		zap.String("node_id", config.NodeID),
		zap.String("storage_backend", config.StorageBackend),
		zap.Bool("auto_unseal", config.AutoUnseal))

	// Set defaults
	if config.NodeID == "" {
		config.NodeID = "eos-vault-node1"
	}
	if config.ClusterPort == 0 {
		config.ClusterPort = shared.PortVaultCluster
	}
	if config.DataPath == "" {
		config.DataPath = shared.VaultDataPath
	}
	if config.LogLevel == "" {
		config.LogLevel = "info"
	}

	// Generate auto-unseal configuration if enabled
	autoUnsealConfig := ""
	if config.AutoUnseal {
		var err error
		autoUnsealConfig, err = GenerateAutoUnsealConfig(rc, config)
		if err != nil {
			log.Error("Failed to generate auto-unseal configuration", zap.Error(err))
			return "", fmt.Errorf("generate auto-unseal config: %w", err)
		}
		log.Info("Auto-unseal configuration generated", zap.String("type", config.AutoUnsealType))
	}

	// Build configuration parameters
	params := shared.VaultConfigParams{
		Port:             fmt.Sprintf("%d", shared.PortVault),
		ClusterPort:      fmt.Sprintf("%d", config.ClusterPort),
		TLSCrt:           shared.TLSCrt,
		TLSKey:           shared.TLSKey,
		VaultDataPath:    config.DataPath,
		APIAddr:          config.APIAddr,
		ClusterAddr:      config.ClusterAddr,
		NodeID:           config.NodeID,
		LogLevel:         config.LogLevel,
		LogFormat:        "json",
		RetryJoinNodes:   config.RetryJoinNodes,
		AutoUnseal:       config.AutoUnseal,
		AutoUnsealConfig: autoUnsealConfig,
	}

	// Render configuration
	hcl, err := shared.RenderVaultConfigRaft(params)
	if err != nil {
		log.Error("Failed to render Raft configuration", zap.Error(err))
		return "", fmt.Errorf("render raft config: %w", err)
	}

	log.Info("Raft configuration generated successfully",
		zap.Int("config_size", len(hcl)),
		zap.Int("retry_join_nodes", len(config.RetryJoinNodes)))

	return hcl, nil
}

// ValidateRaftConfig validates Raft configuration parameters
// Reference: vault-complete-specification-v1.0-raft-integrated.md
func ValidateRaftConfig(rc *eos_io.RuntimeContext, config *InstallConfig) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info("Validating Raft configuration")

	// Node ID is required for Raft
	if config.NodeID == "" {
		return fmt.Errorf("node_id is required for Raft storage backend")
	}

	// Validate node ID format (alphanumeric, hyphens, underscores)
	if !isValidNodeID(config.NodeID) {
		return fmt.Errorf("invalid node_id format: %s (must be alphanumeric with hyphens/underscores)", config.NodeID)
	}

	// API address is required
	if config.APIAddr == "" {
		return fmt.Errorf("api_addr is required for Raft storage backend")
	}

	// Cluster address is required for multi-node
	if len(config.RetryJoinNodes) > 0 && config.ClusterAddr == "" {
		return fmt.Errorf("cluster_addr is required for multi-node Raft cluster")
	}

	// Validate auto-unseal configuration
	if config.AutoUnseal {
		if config.AutoUnsealType == "" {
			return fmt.Errorf("auto_unseal_type is required when auto_unseal is enabled")
		}

		// Validate type-specific requirements
		switch strings.ToLower(config.AutoUnsealType) {
		case "awskms", "aws":
			if config.KMSKeyID == "" {
				return fmt.Errorf("kms_key_id is required for AWS KMS auto-unseal")
			}
		case "azurekeyvault", "azure":
			if config.AzureTenantID == "" || config.AzureClientID == "" ||
				config.AzureClientSecret == "" || config.AzureVaultName == "" ||
				config.AzureKeyName == "" {
				return fmt.Errorf("Azure Key Vault auto-unseal requires tenant_id, client_id, client_secret, vault_name, and key_name")
			}
		case "gcpckms", "gcp":
			if config.GCPProject == "" || config.GCPKeyRing == "" || config.GCPCryptoKey == "" {
				return fmt.Errorf("GCP Cloud KMS auto-unseal requires project, key_ring, and crypto_key")
			}
		default:
			return fmt.Errorf("unsupported auto_unseal_type: %s", config.AutoUnsealType)
		}
	}

	// Validate retry join nodes
	for i, node := range config.RetryJoinNodes {
		if node.APIAddr == "" {
			return fmt.Errorf("retry_join_nodes[%d]: api_addr is required", i)
		}
		if node.Hostname == "" {
			return fmt.Errorf("retry_join_nodes[%d]: hostname is required", i)
		}
	}

	log.Info("Raft configuration validated successfully")
	return nil
}

// isValidNodeID checks if a node ID is valid (alphanumeric with hyphens/underscores)
func isValidNodeID(nodeID string) bool {
	if nodeID == "" {
		return false
	}
	for _, c := range nodeID {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// GetRaftPeerList retrieves the list of Raft peers from a running Vault cluster
// This is useful for verifying cluster formation
func GetRaftPeerList(rc *eos_io.RuntimeContext) (string, error) {
	log := otelzap.Ctx(rc.Ctx)
	log.Info("Retrieving Raft peer list")

	// TODO: Implement using Vault API client
	// vault operator raft list-peers

	return "", fmt.Errorf("not yet implemented")
}

// ConfigureAutopilot configures Autopilot for automated node lifecycle management
// Reference: vault-complete-specification-v1.0-raft-integrated.md - Autopilot Configuration
func ConfigureAutopilot(rc *eos_io.RuntimeContext, minQuorum int) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info("Configuring Autopilot", zap.Int("min_quorum", minQuorum))

	// TODO: Implement using Vault API client
	// vault operator raft autopilot set-config \
	//   -cleanup-dead-servers=true \
	//   -dead-server-last-contact-threshold=10m \
	//   -min-quorum=3 \
	//   -server-stabilization-time=10s

	return fmt.Errorf("not yet implemented")
}
