// cmd/create/secret.go

package create

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/saltstack/orchestrator"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/secrets"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	vaultorch "github.com/CodeMonkeyCybersecurity/eos/pkg/vault/orchestrator"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var CreateSecretCmd = &cobra.Command{
	Use:   "secret",
	Short: "Generate a secure random secret (like openssl rand -hex 32)",
	Example: `  eos create secret
  eos create secret --length 64
  eos create secret --length 24 --format base64`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		// Get flags
		length, _ := cmd.Flags().GetInt("length")
		format, _ := cmd.Flags().GetString("format")

		// Set defaults
		if length <= 0 {
			length = 32 // Default to openssl rand -hex 32
		}
		if format == "" {
			format = "hex"
		}

		// Generate secret using the secrets package
		opts := &secrets.GenerateSecretOptions{
			Length: length,
			Format: format,
		}

		secret, err := secrets.Generate(opts)
		if err != nil {
			return err
		}

		logger.Info("terminal prompt: " + secret)
		return nil
	}),
}

func init() {
	CreateCmd.AddCommand(CreateSecretCmd)
	CreateSecretCmd.Flags().Int("length", 0, "Length of random bytes to generate (default: 32)")
	CreateSecretCmd.Flags().String("format", "", "Output format: hex (default) or base64")
}

var CreateVaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Install and configure HashiCorp Vault using native installer",
	Long: `Install HashiCorp Vault for secrets management using the native installer.

This installer provides:
- Direct binary or repository installation
- Multiple storage backends (file, consul, raft)
- Auto-unseal configuration
- TLS setup
- Systemd service management
- Automatic version resolution

Examples:
  eos create vault                              # Basic installation
  eos create vault --storage-backend=consul     # Use Consul storage
  eos create vault --auto-unseal --kms-key=...  # AWS KMS auto-unseal
  eos create vault --ui                         # Enable web UI`,
	RunE: eos.Wrap(runCreateVaultNative),
}

func init() {
	CreateCmd.AddCommand(CreateVaultCmd)
	
	// Vault flags for native installer
	CreateVaultCmd.Flags().String("version", "latest", "Vault version to install")
	CreateVaultCmd.Flags().String("storage-backend", "file", "Storage backend (file, consul, raft)")
	CreateVaultCmd.Flags().Bool("ui", true, "Enable web UI")
	CreateVaultCmd.Flags().String("listener-address", "0.0.0.0:8200", "Listener address")
	CreateVaultCmd.Flags().Bool("tls", true, "Enable TLS")
	CreateVaultCmd.Flags().Bool("auto-unseal", false, "Enable auto-unseal")
	CreateVaultCmd.Flags().String("kms-key", "", "KMS key ID for auto-unseal")
	CreateVaultCmd.Flags().Bool("clean", false, "Clean install (remove existing)")
	CreateVaultCmd.Flags().Bool("force", false, "Force reinstall")
	CreateVaultCmd.Flags().Bool("use-repository", false, "Install via APT repository")
}

func runCreateVaultNative(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Installing Vault using unified installer")

	// Parse flags
	config := &vault.InstallConfig{
		Version:         cmd.Flag("version").Value.String(),
		UseRepository:   cmd.Flag("use-repository").Value.String() == "true",
		UIEnabled:       cmd.Flag("ui").Value.String() == "true",
		StorageBackend:  cmd.Flag("storage-backend").Value.String(),
		ListenerAddress: cmd.Flag("listener-address").Value.String(),
		AutoUnseal:      cmd.Flag("auto-unseal").Value.String() == "true",
		KMSKeyID:        cmd.Flag("kms-key").Value.String(),
		TLSEnabled:      cmd.Flag("tls").Value.String() == "true",
		CleanInstall:    cmd.Flag("clean").Value.String() == "true",
		ForceReinstall:  cmd.Flag("force").Value.String() == "true",
	}

	// Create and run installer
	installer := vault.NewVaultInstaller(rc, config)
	if err := installer.Install(); err != nil {
		return fmt.Errorf("Vault installation failed: %w", err)
	}

	logger.Info("Vault installation completed successfully")
	logger.Info("terminal prompt: Vault is installed. Initialize with: vault operator init")
	return nil
}

// Removed unused Salt-based functions - now using native installer

var CreateVaultEnhancedCmd = &cobra.Command{
	Use:   "vault-enhanced",
	Short: "Installs Vault with TLS, systemd service, and initial configuration (Salt orchestration supported)",
	Long: `Install and configure HashiCorp Vault with comprehensive orchestration support.

This enhanced version supports both direct execution and Salt orchestration,
allowing for coordinated deployment across multiple nodes and integration
with broader infrastructure automation.

Direct Execution:
  eos create vault-enhanced

Salt Orchestration:
  eos create vault-enhanced --orchestrator=salt --salt-target 'vault-*'
  eos create vault-enhanced --orchestrator=salt --salt-target 'vault-cluster' --salt-pillar cluster_size=3
  eos create vault-enhanced --orchestrator=salt --salt-batch 1 --salt-async

Features:
  - TLS certificate generation and configuration
  - Systemd service setup and management
  - Initial Vault configuration and unsealing
  - HA cluster support via Salt orchestration
  - Integration with Consul backend when available
  - Automated backup configuration
  - Security hardening and best practices

Salt States Used:
  - hashicorp.vault.install: Core Vault installation
  - hashicorp.vault.config: Configuration management
  - hashicorp.vault.cluster: HA cluster setup
  - hashicorp.vault.security: Security hardening

Environment Variables:
  VAULT_VERSION: Specific Vault version to install
  VAULT_CONFIG_PATH: Custom configuration directory
  VAULT_DATA_PATH: Custom data directory`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		// Get orchestration options
		opts, err := orchestrator.GetOrchestrationOptions(cmd)
		if err != nil {
			return fmt.Errorf("failed to get orchestration options: %w", err)
		}

		logger.Info("Starting Vault creation",
			zap.String("orchestration_mode", string(opts.Mode)),
			zap.String("target", opts.Target))

		// Define direct execution function
		directExec := func(rc *eos_io.RuntimeContext) error {
			logger.Info("Executing direct Vault installation")
			err := vault.OrchestrateVaultCreate(rc)
			if err != nil {
				return fmt.Errorf("vault create failed: %w", err)
			}
			return nil
		}

		// Define Salt operation
		saltOp := vaultorch.CreateSaltOperation(opts)

		// Execute based on orchestration mode
		if opts.Mode == orchestrator.OrchestrationModeSalt {
			return vaultorch.ExecuteWithSalt(rc, opts, directExec, saltOp)
		}

		// Execute directly
		return directExec(rc)
	}),
}

func init() {
	// Add orchestration flags
	orchestrator.AddOrchestrationFlags(CreateVaultEnhancedCmd)

	// Add Vault-specific flags
	CreateVaultEnhancedCmd.Flags().String("vault-version", "", "Specific Vault version to install")
	CreateVaultEnhancedCmd.Flags().String("vault-config-path", "/etc/vault.d", "Vault configuration directory")
	CreateVaultEnhancedCmd.Flags().String("vault-data-path", "/opt/vault/data", "Vault data directory")
	CreateVaultEnhancedCmd.Flags().Bool("vault-ha", false, "Configure for high availability")
	CreateVaultEnhancedCmd.Flags().String("vault-backend", "file", "Storage backend (file, consul, etc.)")
	CreateVaultEnhancedCmd.Flags().String("vault-cluster-name", "vault-cluster", "Cluster name for HA setup")
	CreateVaultEnhancedCmd.Flags().Int("vault-cluster-size", 3, "Number of nodes in HA cluster")
	CreateVaultEnhancedCmd.Flags().Bool("vault-auto-unseal", false, "Configure auto-unseal with cloud providers")
	CreateVaultEnhancedCmd.Flags().String("vault-tls-cert", "", "Path to TLS certificate")
	CreateVaultEnhancedCmd.Flags().String("vault-tls-key", "", "Path to TLS private key")

	CreateCmd.AddCommand(CreateVaultEnhancedCmd)
}
