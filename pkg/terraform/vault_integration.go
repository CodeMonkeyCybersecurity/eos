// pkg/terraform/vault_integration.go

package terraform

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// VaultIntegration holds configuration for Vault-Terraform integration
type VaultIntegration struct {
	VaultAddr    string
	VaultToken   string
	SecretsPath  string
	BackendPath  string
	EnableState  bool
	EnableSecrets bool
}

// VaultSecretReference represents a reference to a Vault secret
type VaultSecretReference struct {
	Path        string
	Key         string
	VarName     string
	Sensitive   bool
	Description string
}

// VaultBackendConfig represents Vault backend configuration for Terraform state
type VaultBackendConfig struct {
	Address     string
	Path        string
	Token       string
	Namespace   string
	SkipTLSVerify bool
}

// ConfigureVaultIntegration sets up Vault integration for the Terraform manager
func (m *Manager) ConfigureVaultIntegration(rc *eos_io.RuntimeContext, config VaultIntegration) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Configuring Vault integration for Terraform", 
		zap.String("vault_addr", config.VaultAddr),
		zap.Bool("enable_state", config.EnableState),
		zap.Bool("enable_secrets", config.EnableSecrets))

	// Validate Vault connectivity
	if err := m.validateVaultConnection(rc, config); err != nil {
		return fmt.Errorf("vault connection validation failed: %w", err)
	}

	// Configure Vault backend for state if enabled
	if config.EnableState {
		if err := m.configureVaultBackend(rc, config); err != nil {
			return fmt.Errorf("vault backend configuration failed: %w", err)
		}
	}

	// Configure secret references if enabled
	if config.EnableSecrets {
		if err := m.setupSecretReferences(rc, config); err != nil {
			return fmt.Errorf("vault secret references setup failed: %w", err)
		}
	}

	logger.Info("Vault integration configured successfully")
	return nil
}

// LoadSecretsFromVault retrieves secrets from Vault and adds them as Terraform variables
func (m *Manager) LoadSecretsFromVault(rc *eos_io.RuntimeContext, secretRefs []VaultSecretReference) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Loading secrets from Vault", zap.Int("secret_count", len(secretRefs)))

	client, err := vault.GetVaultClient(rc)
	if err != nil {
		return fmt.Errorf("failed to get vault client: %w", err)
	}

	for _, ref := range secretRefs {
		secret, err := m.retrieveVaultSecret(rc, client, ref)
		if err != nil {
			logger.Error("Failed to retrieve secret", 
				zap.String("path", ref.Path),
				zap.String("key", ref.Key),
				zap.Error(err))
			return fmt.Errorf("failed to retrieve secret %s:%s: %w", ref.Path, ref.Key, err)
		}

		// Add as Terraform variable
		m.SetVariable(ref.VarName, secret)
		logger.Debug("Secret loaded as Terraform variable", 
			zap.String("var_name", ref.VarName),
			zap.String("vault_path", ref.Path))
	}

	logger.Info("All secrets loaded successfully from Vault")
	return nil
}

// GenerateVaultBackendConfig creates a Terraform backend configuration for Vault
func (m *Manager) GenerateVaultBackendConfig(rc *eos_io.RuntimeContext, config VaultBackendConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Generating Vault backend configuration")

	backendHCL := fmt.Sprintf(`
terraform {
  backend "http" {
    address        = "%s/v1/%s"
    lock_address   = "%s/v1/%s-lock"
    unlock_address = "%s/v1/%s-lock"
    username       = "terraform"
    password       = "%s"
    lock_method    = "PUT"
    unlock_method  = "DELETE"
    retry_max      = 5
    retry_wait_min = 1
    retry_wait_max = 10
  }
}
`, config.Address, config.Path, 
   config.Address, config.Path,
   config.Address, config.Path,
   config.Token)

	backendFile := filepath.Join(m.Config.WorkingDir, "backend.tf")
	if err := os.WriteFile(backendFile, []byte(backendHCL), 0644); err != nil {
		return fmt.Errorf("failed to write backend configuration: %w", err)
	}

	logger.Info("Vault backend configuration generated", zap.String("file", backendFile))
	return nil
}

// GenerateVaultProviderConfig creates Vault provider configuration for Terraform
func (m *Manager) GenerateVaultProviderConfig(rc *eos_io.RuntimeContext, vaultAddr, vaultToken string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	providerHCL := fmt.Sprintf(`
terraform {
  required_providers {
    vault = {
      source  = "hashicorp/vault"
      version = "~> 3.0"
    }
  }
}

provider "vault" {
  address = "%s"
  token   = "%s"
}
`, vaultAddr, vaultToken)

	providerFile := filepath.Join(m.Config.WorkingDir, "vault_provider.tf")
	if err := os.WriteFile(providerFile, []byte(providerHCL), 0644); err != nil {
		return fmt.Errorf("failed to write vault provider configuration: %w", err)
	}

	logger.Info("Vault provider configuration generated", zap.String("file", providerFile))
	return nil
}

// SyncTerraformOutputsToVault stores Terraform outputs in Vault
func (m *Manager) SyncTerraformOutputsToVault(rc *eos_io.RuntimeContext, vaultPath string, outputNames []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Syncing Terraform outputs to Vault", 
		zap.String("vault_path", vaultPath),
		zap.Strings("outputs", outputNames))

	client, err := vault.GetVaultClient(rc)
	if err != nil {
		return fmt.Errorf("failed to get vault client: %w", err)
	}

	secrets := make(map[string]interface{})

	// Retrieve all specified outputs
	for _, outputName := range outputNames {
		output, err := m.Output(rc, outputName)
		if err != nil {
			logger.Warn("Failed to retrieve output", 
				zap.String("output", outputName),
				zap.Error(err))
			continue
		}
		secrets[outputName] = output
	}

	// Store in Vault
	if err := m.storeSecretsInVault(rc, client, vaultPath, secrets); err != nil {
		return fmt.Errorf("failed to store outputs in vault: %w", err)
	}

	logger.Info("Terraform outputs synced to Vault successfully")
	return nil
}

// CreateVaultSecretsEngine ensures a KV v2 secrets engine exists for Terraform
func (m *Manager) CreateVaultSecretsEngine(rc *eos_io.RuntimeContext, path string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Creating Vault secrets engine for Terraform", zap.String("path", path))

	client, err := vault.GetVaultClient(rc)
	if err != nil {
		return fmt.Errorf("failed to get vault client: %w", err)
	}

	// Check if secrets engine already exists
	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return fmt.Errorf("failed to list mounts: %w", err)
	}

	mountPath := path + "/"
	if _, exists := mounts[mountPath]; exists {
		logger.Info("Secrets engine already exists", zap.String("path", path))
		return nil
	}

	// Create KV v2 secrets engine
	options := &api.MountInput{
		Type:        "kv",
		Description: "Terraform secrets managed by Eos",
		Options: map[string]string{
			"version": "2",
		},
	}

	if err := client.Sys().Mount(path, options); err != nil {
		return fmt.Errorf("failed to create secrets engine: %w", err)
	}

	logger.Info("Vault secrets engine created successfully", zap.String("path", path))
	return nil
}

// validateVaultConnection checks if Vault is accessible
func (m *Manager) validateVaultConnection(rc *eos_io.RuntimeContext, config VaultIntegration) error {
	client, err := vault.GetVaultClient(rc)
	if err != nil {
		return fmt.Errorf("failed to create vault client: %w", err)
	}

	ctx, cancel := context.WithTimeout(rc.Ctx, 10*time.Second)
	defer cancel()

	// Test connection with health check
	health, err := client.Sys().HealthWithContext(ctx)
	if err != nil {
		return fmt.Errorf("vault health check failed: %w", err)
	}

	if !health.Initialized {
		return fmt.Errorf("vault is not initialized")
	}

	if health.Sealed {
		return fmt.Errorf("vault is sealed")
	}

	return nil
}

// configureVaultBackend sets up Vault as Terraform state backend
func (m *Manager) configureVaultBackend(rc *eos_io.RuntimeContext, config VaultIntegration) error {
	backendConfig := VaultBackendConfig{
		Address: config.VaultAddr,
		Path:    config.BackendPath,
		Token:   config.VaultToken,
	}

	return m.GenerateVaultBackendConfig(rc, backendConfig)
}

// setupSecretReferences configures Terraform to use Vault data sources
func (m *Manager) setupSecretReferences(rc *eos_io.RuntimeContext, config VaultIntegration) error {
	// Generate Vault provider configuration
	return m.GenerateVaultProviderConfig(rc, config.VaultAddr, config.VaultToken)
}

// retrieveVaultSecret fetches a secret from Vault
func (m *Manager) retrieveVaultSecret(rc *eos_io.RuntimeContext, client *api.Client, ref VaultSecretReference) (interface{}, error) {
	secret, err := client.KVv2(ref.Path).Get(rc.Ctx, ref.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to read secret: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("secret not found or empty")
	}

	value, exists := secret.Data[ref.Key]
	if !exists {
		return nil, fmt.Errorf("key %s not found in secret", ref.Key)
	}

	return value, nil
}

// storeSecretsInVault stores key-value pairs in Vault
func (m *Manager) storeSecretsInVault(rc *eos_io.RuntimeContext, client *api.Client, path string, secrets map[string]interface{}) error {
	// Extract mount path and secret path
	parts := strings.SplitN(path, "/", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid vault path format: %s", path)
	}

	mountPath := parts[0]
	secretPath := parts[1]

	_, err := client.KVv2(mountPath).Put(rc.Ctx, secretPath, secrets)
	if err != nil {
		return fmt.Errorf("failed to store secrets: %w", err)
	}

	return nil
}

// GenerateVaultDataSources creates Terraform data sources for Vault secrets
func (m *Manager) GenerateVaultDataSources(rc *eos_io.RuntimeContext, secretRefs []VaultSecretReference) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Generating Vault data sources", zap.Int("secret_count", len(secretRefs)))

	var dataSourcesHCL strings.Builder

	for _, ref := range secretRefs {
		dataSourcesHCL.WriteString(fmt.Sprintf(`
data "vault_kv_secret_v2" "%s" {
  mount = "%s"
  name  = "%s"
}

locals {
  %s = data.vault_kv_secret_v2.%s.data["%s"]
}
`, ref.VarName, strings.Split(ref.Path, "/")[0], strings.Join(strings.Split(ref.Path, "/")[1:], "/"),
   ref.VarName, ref.VarName, ref.Key))
	}

	dataSourcesFile := filepath.Join(m.Config.WorkingDir, "vault_data_sources.tf")
	if err := os.WriteFile(dataSourcesFile, []byte(dataSourcesHCL.String()), 0644); err != nil {
		return fmt.Errorf("failed to write vault data sources: %w", err)
	}

	logger.Info("Vault data sources generated", zap.String("file", dataSourcesFile))
	return nil
}