package create

import (
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault_salt"
)

var createVaultSaltCmd = &cobra.Command{
	Use:   "vault-salt",
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
	RunE: eos_cli.Wrap(runCreateVaultSalt),
}

func init() {
	CreateCmd.AddCommand(createVaultSaltCmd)
	
	// Installation flags
	createVaultSaltCmd.Flags().String("version", "latest", "Vault version to install")
	createVaultSaltCmd.Flags().String("install-path", "/opt/vault", "Installation directory")
	createVaultSaltCmd.Flags().String("config-path", "/etc/vault.d", "Configuration directory")
	createVaultSaltCmd.Flags().String("data-path", "/opt/vault/data", "Data storage directory")
	createVaultSaltCmd.Flags().String("log-path", "/var/log/vault", "Log directory")
	
	// Network configuration
	createVaultSaltCmd.Flags().String("listen-address", "0.0.0.0", "Listen address for Vault API")
	createVaultSaltCmd.Flags().Int("port", 8179, "Vault API port (Eos default)")
	createVaultSaltCmd.Flags().Int("cluster-port", 8180, "Vault cluster port")
	
	// TLS configuration
	createVaultSaltCmd.Flags().Bool("tls-disable", false, "Disable TLS (not recommended)")
	createVaultSaltCmd.Flags().String("tls-cert-file", "", "Path to TLS certificate file")
	createVaultSaltCmd.Flags().String("tls-key-file", "", "Path to TLS key file")
	
	// Storage configuration
	createVaultSaltCmd.Flags().String("storage-type", "raft", "Storage backend type")
	
	// Initialization configuration
	createVaultSaltCmd.Flags().Int("key-shares", 5, "Number of key shares")
	createVaultSaltCmd.Flags().Int("key-threshold", 3, "Key threshold for unsealing")
	
	// Feature flags
	createVaultSaltCmd.Flags().Bool("enable-userpass", true, "Enable userpass auth method")
	createVaultSaltCmd.Flags().Bool("enable-approle", true, "Enable approle auth method")
	createVaultSaltCmd.Flags().Bool("enable-mfa", true, "Enable MFA")
	createVaultSaltCmd.Flags().Bool("enable-audit", true, "Enable audit logging")
	createVaultSaltCmd.Flags().Bool("enable-policies", true, "Configure default policies")
	
	// Hardening flags
	createVaultSaltCmd.Flags().Bool("harden-system", true, "Apply system hardening")
	createVaultSaltCmd.Flags().Bool("harden-network", true, "Apply network hardening")
	createVaultSaltCmd.Flags().Bool("harden-vault", true, "Apply Vault-specific hardening")
	createVaultSaltCmd.Flags().Bool("harden-backup", true, "Configure secure backups")
	
	// Backup configuration
	createVaultSaltCmd.Flags().Bool("backup-enabled", true, "Enable automatic backups")
	createVaultSaltCmd.Flags().String("backup-path", "/opt/vault/backup", "Backup directory")
	createVaultSaltCmd.Flags().String("backup-schedule", "0 2 * * *", "Cron schedule for backups")
	
	// Integration flags
	createVaultSaltCmd.Flags().Bool("hecate-integration", true, "Enable Hecate integration")
	createVaultSaltCmd.Flags().Bool("delphi-integration", true, "Enable Delphi integration")
	
	// Workflow flags
	createVaultSaltCmd.Flags().Bool("skip-install", false, "Skip installation phase")
	createVaultSaltCmd.Flags().Bool("skip-configure", false, "Skip configuration phase")
	createVaultSaltCmd.Flags().Bool("skip-enable", false, "Skip feature enablement phase")
	createVaultSaltCmd.Flags().Bool("skip-harden", false, "Skip hardening phase")
	createVaultSaltCmd.Flags().Bool("skip-verify", false, "Skip verification phase")
}

func runCreateVaultSalt(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting Vault deployment via SaltStack")
	
	// Run pre-flight checks before attempting installation
	if err := vault.PreflightChecks(rc); err != nil {
		return err
	}
	
	// Build configuration from flags
	config := buildVaultSaltConfig(cmd)
	
	// Execute installation phase
	skipInstall, _ := cmd.Flags().GetBool("skip-install")
	if !skipInstall {
		logger.Info("Phase 1: Installing Vault")
		if err := vault_salt.Install(rc, config); err != nil {
			return err
		}
	}
	
	// Execute configuration phase
	skipConfigure, _ := cmd.Flags().GetBool("skip-configure")
	if !skipConfigure {
		logger.Info("Phase 2: Configuring Vault")
		if err := vault_salt.Configure(rc, config); err != nil {
			return err
		}
	}
	
	// Execute enablement phase
	skipEnable, _ := cmd.Flags().GetBool("skip-enable")
	if !skipEnable {
		logger.Info("Phase 3: Enabling Vault features")
		if err := vault_salt.Enable(rc, config); err != nil {
			return err
		}
	}
	
	// Execute hardening phase
	skipHarden, _ := cmd.Flags().GetBool("skip-harden")
	if !skipHarden {
		logger.Info("Phase 4: Hardening Vault")
		if err := vault_salt.Harden(rc, config); err != nil {
			return err
		}
	}
	
	// Execute verification phase
	skipVerify, _ := cmd.Flags().GetBool("skip-verify")
	if !skipVerify {
		logger.Info("Phase 5: Verifying Vault deployment")
		if err := vault_salt.Verify(rc); err != nil {
			return err
		}
	}
	
	// Display completion message
	displayCompletionMessage(rc, config)
	
	logger.Info("Vault deployment completed successfully")
	return nil
}

func buildVaultSaltConfig(cmd *cobra.Command) *vault_salt.Config {
	config := vault_salt.DefaultConfig()
	
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

func displayCompletionMessage(rc *eos_io.RuntimeContext, config *vault_salt.Config) {
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