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
	Short: "Install and configure HashiCorp Vault using SaltStack",
	Long: `Install and configure HashiCorp Vault using SaltStack orchestration.

This command provides a complete Vault deployment including:
- Installation of Vault binary
- TLS certificate generation
- Service configuration
- Initialization and unsealing
- Auth method configuration (userpass, approle)
- Policy management
- Audit logging
- Security hardening
- Backup configuration

The deployment is managed entirely through SaltStack states, ensuring
consistent and repeatable installations.`,
	RunE: eos.Wrap(runCreateVault),
}

func init() {
	CreateCmd.AddCommand(CreateVaultCmd)
	
	// Installation flags
	CreateVaultCmd.Flags().String("version", "latest", "Vault version to install")
	CreateVaultCmd.Flags().String("install-path", "/opt/vault", "Installation directory")
	CreateVaultCmd.Flags().String("config-path", "/etc/vault.d", "Configuration directory")
	CreateVaultCmd.Flags().String("data-path", "/opt/vault/data", "Data storage directory")
	CreateVaultCmd.Flags().String("log-path", "/var/log/vault", "Log directory")
	
	// Network configuration
	CreateVaultCmd.Flags().String("listen-address", "0.0.0.0", "Listen address for Vault API")
	CreateVaultCmd.Flags().Int("port", 8179, "Vault API port (Eos default)")
	CreateVaultCmd.Flags().Int("cluster-port", 8180, "Vault cluster port")
	
	// TLS configuration
	CreateVaultCmd.Flags().Bool("tls-disable", false, "Disable TLS (not recommended)")
	CreateVaultCmd.Flags().String("tls-cert-file", "", "Path to TLS certificate file")
	CreateVaultCmd.Flags().String("tls-key-file", "", "Path to TLS key file")
	
	// Storage configuration
	CreateVaultCmd.Flags().String("storage-type", "raft", "Storage backend type")
	
	// Initialization configuration
	CreateVaultCmd.Flags().Int("key-shares", 5, "Number of key shares")
	CreateVaultCmd.Flags().Int("key-threshold", 3, "Key threshold for unsealing")
	
	// Feature flags
	CreateVaultCmd.Flags().Bool("enable-userpass", true, "Enable userpass auth method")
	CreateVaultCmd.Flags().Bool("enable-approle", true, "Enable approle auth method")
	CreateVaultCmd.Flags().Bool("enable-mfa", true, "Enable MFA")
	CreateVaultCmd.Flags().Bool("enable-audit", true, "Enable audit logging")
	CreateVaultCmd.Flags().Bool("enable-policies", true, "Configure default policies")
	
	// Hardening flags
	CreateVaultCmd.Flags().Bool("harden-system", true, "Apply system hardening")
	CreateVaultCmd.Flags().Bool("harden-network", true, "Apply network hardening")
	CreateVaultCmd.Flags().Bool("harden-vault", true, "Apply Vault-specific hardening")
	CreateVaultCmd.Flags().Bool("harden-backup", true, "Configure secure backups")
	
	// Backup configuration
	CreateVaultCmd.Flags().Bool("backup-enabled", true, "Enable automatic backups")
	CreateVaultCmd.Flags().String("backup-path", "/opt/vault/backup", "Backup directory")
	CreateVaultCmd.Flags().String("backup-schedule", "0 2 * * *", "Cron schedule for backups")
	
	// Integration flags
	CreateVaultCmd.Flags().Bool("hecate-integration", true, "Enable Hecate integration")
	CreateVaultCmd.Flags().Bool("delphi-integration", true, "Enable Delphi integration")
	
	// Workflow flags
	CreateVaultCmd.Flags().Bool("skip-install", false, "Skip installation phase")
	CreateVaultCmd.Flags().Bool("skip-configure", false, "Skip configuration phase")
	CreateVaultCmd.Flags().Bool("skip-enable", false, "Skip feature enablement phase")
	CreateVaultCmd.Flags().Bool("skip-harden", false, "Skip hardening phase")
	CreateVaultCmd.Flags().Bool("skip-verify", false, "Skip verification phase")
}

func runCreateVault(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting Vault deployment via SaltStack")
	
	// Run pre-flight checks before attempting installation
	if err := vault.PreflightChecks(rc); err != nil {
		return err
	}
	
	// Build configuration from flags
	config := buildVaultConfig(cmd)
	
	// Execute installation phase
	skipInstall, _ := cmd.Flags().GetBool("skip-install")
	if !skipInstall {
		logger.Info("Phase 1: Installing Vault")
		if err := vault.SaltInstall(rc, config); err != nil {
			return err
		}
	}
	
	// Execute configuration phase
	skipConfigure, _ := cmd.Flags().GetBool("skip-configure")
	if !skipConfigure {
		logger.Info("Phase 2: Configuring Vault")
		if err := vault.SaltConfigure(rc, config); err != nil {
			return err
		}
	}
	
	// Execute enablement phase
	skipEnable, _ := cmd.Flags().GetBool("skip-enable")
	if !skipEnable {
		logger.Info("Phase 3: Enabling Vault features")
		if err := vault.SaltEnable(rc, config); err != nil {
			return err
		}
	}
	
	// Execute hardening phase
	skipHarden, _ := cmd.Flags().GetBool("skip-harden")
	if !skipHarden {
		logger.Info("Phase 4: Hardening Vault")
		if err := vault.SaltHarden(rc, config); err != nil {
			return err
		}
	}
	
	// Execute verification phase
	skipVerify, _ := cmd.Flags().GetBool("skip-verify")
	if !skipVerify {
		logger.Info("Phase 5: Verifying Vault deployment")
		if err := vault.SaltVerify(rc); err != nil {
			return err
		}
	}
	
	// Display completion message
	displayVaultCompletionMessage(rc, config)
	
	logger.Info("Vault deployment completed successfully")
	return nil
}

func buildVaultConfig(cmd *cobra.Command) *vault.SaltConfig {
	config := vault.DefaultSaltConfig()
	
	// Update from flags
	if v := cmd.Flag("version").Value.String(); v != "" {
		config.Version = v
	}
	if v := cmd.Flag("install-path").Value.String(); v != "" {
		config.InstallPath = v
	}
	if v := cmd.Flag("config-path").Value.String(); v != "" {
		config.ConfigPath = v
	}
	if v := cmd.Flag("data-path").Value.String(); v != "" {
		config.DataPath = v
	}
	if v := cmd.Flag("log-path").Value.String(); v != "" {
		config.LogPath = v
	}
	
	// Network configuration
	if v := cmd.Flag("listen-address").Value.String(); v != "" {
		config.ListenAddress = v
	}
	if v, err := cmd.Flags().GetInt("port"); err == nil {
		config.Port = v
	}
	if v, err := cmd.Flags().GetInt("cluster-port"); err == nil {
		config.ClusterPort = v
	}
	
	// TLS configuration
	if v, err := cmd.Flags().GetBool("tls-disable"); err == nil {
		config.TLSDisable = v
	}
	if v := cmd.Flag("tls-cert-file").Value.String(); v != "" {
		config.TLSCertFile = v
	}
	if v := cmd.Flag("tls-key-file").Value.String(); v != "" {
		config.TLSKeyFile = v
	}
	
	// Storage configuration
	if v := cmd.Flag("storage-type").Value.String(); v != "" {
		config.StorageType = v
	}
	
	// Initialization configuration
	if v, err := cmd.Flags().GetInt("key-shares"); err == nil {
		config.KeyShares = v
	}
	if v, err := cmd.Flags().GetInt("key-threshold"); err == nil {
		config.KeyThreshold = v
	}
	
	// Feature flags
	if v, err := cmd.Flags().GetBool("enable-userpass"); err == nil {
		config.EnableUserpass = v
	}
	if v, err := cmd.Flags().GetBool("enable-approle"); err == nil {
		config.EnableAppRole = v
	}
	if v, err := cmd.Flags().GetBool("enable-mfa"); err == nil {
		config.EnableMFA = v
	}
	if v, err := cmd.Flags().GetBool("enable-audit"); err == nil {
		config.EnableAudit = v
	}
	if v, err := cmd.Flags().GetBool("enable-policies"); err == nil {
		config.EnablePolicies = v
	}
	
	// Hardening flags
	if v, err := cmd.Flags().GetBool("harden-system"); err == nil {
		config.HardenSystem = v
	}
	if v, err := cmd.Flags().GetBool("harden-network"); err == nil {
		config.HardenNetwork = v
	}
	if v, err := cmd.Flags().GetBool("harden-vault"); err == nil {
		config.HardenVault = v
	}
	if v, err := cmd.Flags().GetBool("harden-backup"); err == nil {
		config.HardenBackup = v
	}
	
	// Backup configuration
	if v, err := cmd.Flags().GetBool("backup-enabled"); err == nil {
		config.BackupEnabled = v
	}
	if v := cmd.Flag("backup-path").Value.String(); v != "" {
		config.BackupPath = v
	}
	if v := cmd.Flag("backup-schedule").Value.String(); v != "" {
		config.BackupSchedule = v
	}
	
	// Integration flags
	if v, err := cmd.Flags().GetBool("hecate-integration"); err == nil {
		config.HecateIntegration = v
	}
	if v, err := cmd.Flags().GetBool("delphi-integration"); err == nil {
		config.DelphiIntegration = v
	}
	
	return config
}

func displayVaultCompletionMessage(rc *eos_io.RuntimeContext, config *vault.SaltConfig) {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("=== Vault Deployment Complete ===")
	logger.Info("Vault Details:",
		zap.String("version", config.Version),
		zap.Int("api_port", config.Port),
		zap.Int("cluster_port", config.ClusterPort),
		zap.Bool("tls_enabled", !config.TLSDisable))
	
	vaultAddr := "https://127.0.0.1:8179"
	if config.TLSDisable {
		vaultAddr = "http://127.0.0.1:8179"
	}
	
	logger.Info("Access Information:",
		zap.String("vault_addr", vaultAddr),
		zap.String("init_data", "/var/lib/eos/secret/vault_init.json"))
	
	logger.Info("Next Steps:",
		zap.String("1", "Review the initialization data for root token and unseal keys"),
		zap.String("2", "Configure additional auth methods as needed"),
		zap.String("3", "Create application-specific policies"),
		zap.String("4", "Set up monitoring and alerting"),
		zap.String("5", "Test backup and restoration procedures"))
	
	logger.Info("Useful Commands:",
		zap.String("status", "vault status"),
		zap.String("unseal", "vault operator unseal"),
		zap.String("login", "vault login"),
		zap.String("audit_log", "tail -f /var/log/vault/vault-audit.log"))
}

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
