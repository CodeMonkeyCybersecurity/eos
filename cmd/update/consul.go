// cmd/update/consul.go
package update

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul"
	consulacl "github.com/CodeMonkeyCybersecurity/eos/pkg/consul/acl"
	consulconfig "github.com/CodeMonkeyCybersecurity/eos/pkg/consul/config"
	consulfix "github.com/CodeMonkeyCybersecurity/eos/pkg/consul/fix"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var (
	consulPorts          string
	consulDryRun         bool
	consulFix            bool
	consulBootstrapToken bool
	consulDataDir        string
	consulEnableACLs     bool
)

// ConsulCmd updates Consul configuration
var ConsulCmd = &cobra.Command{
	Use:   "consul",
	Short: "Update Consul configuration",
	Long: `Update Consul's configuration by modifying settings and restarting the service.

The command intelligently updates:
1. Consul HCL configuration file (/etc/consul.d/consul.hcl)
2. Configuration drift correction (--fix)
3. ACL system management (--bootstrap-token, --enable-acls)
4. Restarts Consul service to apply changes
5. Verifies new configuration is accessible

Configuration Drift Correction:
  --fix       Detect and correct drift from canonical state
  --dry-run   Preview changes without applying (works with --fix, --ports, --bootstrap-token, --enable-acls)

  The --fix flag compares current Consul installation against the canonical
  state from 'eos create consul' and automatically corrects:
  - File permissions (config, data directories)
  - File ownership (consul user/group)
  - Missing helper scripts
  - Systemd service configuration
  - ACL enablement (if ACLs were disabled)

  Like combing through the configuration to correct any settings that drifted.

ACL Enablement:
  --enable-acls           Enable ACLs in Consul configuration if disabled
  --dry-run               Preview changes without applying

  The --enable-acls flag modifies the Consul configuration to enable the ACL
  system with secure defaults (deny-by-default policy). It:
  - Creates backup of current configuration
  - Modifies ACL block to set enabled = true
  - Sets default_policy = "deny" (secure by default)
  - Validates HCL syntax after modification
  - Restarts Consul service to apply changes
  - Provides next steps for ACL bootstrap

  This is useful for:
  - Recovering from accidentally disabled ACLs
  - Enabling ACLs on existing installations
  - Configuration drift correction for ACL settings

  NOTE: ACLs are ENABLED BY DEFAULT in 'eos create consul'. This flag is
  primarily for recovery scenarios where ACLs were manually disabled.

  After enabling ACLs, you must bootstrap them:
    eos update consul --enable-acls
    eos update consul --bootstrap-token

ACL Bootstrap Token Recovery:
  --bootstrap-token        Reset ACL bootstrap and recover/generate bootstrap token
  --data-dir PATH          Consul data directory (auto-detected if omitted)

  The --bootstrap-token flag performs Consul ACL bootstrap reset when the
  bootstrap token is lost or not stored in Vault. It:
  - Detects current ACL bootstrap state via SDK
  - Determines data directory (6-layer fallback, or use --data-dir)
  - Writes reset index file to Consul data directory
  - Re-bootstraps ACL system (generates new token)
  - Stores token securely in Vault at secret/consul/bootstrap-token

  Data directory detection (in priority order):
  1. --data-dir flag (highest priority - manual override)
  2. Running process inspection (ps aux, systemd service)
  3. Config file parsing (/etc/consul.d/*.hcl, *.json)
  4. Consul API query (requires token, may fail with 403)
  5. Well-known paths: /opt/consul, /var/lib/consul
  6. Actionable error with manual override guidance

  If auto-detection fails, specify manually:
    eos update consul --bootstrap-token --data-dir /opt/consul

  This solves the "lost bootstrap token" problem without destroying cluster data.

Examples:
  # Detect and fix all configuration drift
  eos update consul --fix

  # Show what would be fixed (dry-run)
  eos update consul --fix --dry-run

  # Enable ACLs in configuration
  eos update consul --enable-acls

  # Preview ACL enablement (dry-run)
  eos update consul --enable-acls --dry-run

  # Recover lost ACL bootstrap token (auto-detect data dir)
  eos update consul --bootstrap-token

  # Recover with explicit data directory
  eos update consul --bootstrap-token --data-dir /opt/consul

  # Preview bootstrap token recovery (dry-run)
  eos update consul --bootstrap-token --dry-run

  # Preview with manual data directory
  eos update consul --bootstrap-token --data-dir /var/lib/consul --dry-run

  # Change HTTP port from current to HashiCorp default
  eos update consul --ports 8161 -> default
  eos update consul --ports 8161 -> 8500

  # Change DNS port
  eos update consul --ports 8389 -> 8600

  # Preview changes without applying
  eos update consul --ports 8161 -> default --dry-run

The "default" keyword uses HashiCorp standard ports:
  - HTTP port: 8500
  - DNS port: 8600
  - RPC port: 8300
  - Serf LAN: 8301
  - Serf WAN: 8302

Syntax: --ports FROM -> TO
  FROM: Current port number (or "default")
  TO: New port number (or "default")

Code Monkey Cybersecurity - "Cybersecurity. With humans."`,
	RunE: eos.Wrap(runConsulUpdate),
}

func init() {
	ConsulCmd.Flags().StringVar(&consulPorts, "ports", "",
		"Port migration in format: FROM -> TO (e.g., '8161 -> default' or '8161 -> 8500')")
	ConsulCmd.Flags().BoolVar(&consulDryRun, "dry-run", false,
		"Preview changes without applying them (works with --fix, --ports, --bootstrap-token, --enable-acls)")
	ConsulCmd.Flags().BoolVar(&consulFix, "fix", false,
		"Fix configuration drift from canonical state (use --dry-run to preview)")
	ConsulCmd.Flags().BoolVar(&consulBootstrapToken, "bootstrap-token", false,
		"Reset ACL bootstrap and recover/generate bootstrap token (stores in Vault)")
	ConsulCmd.Flags().StringVar(&consulDataDir, "data-dir", "",
		"Consul data directory path (auto-detected if omitted, used with --bootstrap-token)")
	ConsulCmd.Flags().BoolVar(&consulEnableACLs, "enable-acls", false,
		"Enable ACLs in Consul configuration if disabled (creates backup, validates syntax)")
}

func runConsulUpdate(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Count operations (--dry-run is a modifier, not an operation)
	operationCount := 0
	if consulFix {
		operationCount++
	}
	if consulPorts != "" {
		operationCount++
	}
	if consulBootstrapToken {
		operationCount++
	}
	if consulEnableACLs {
		operationCount++
	}

	// Only allow ONE operation at a time
	if operationCount > 1 {
		return eos_err.NewUserError(
			"Cannot specify multiple operations simultaneously.\n\n" +
				"Choose ONE of:\n" +
				"  --fix              Fix configuration drift\n" +
				"  --ports            Migrate ports\n" +
				"  --bootstrap-token  Reset ACL bootstrap and recover token\n" +
				"  --enable-acls      Enable ACLs in configuration\n\n" +
				"Use --dry-run to preview changes for any operation.\n\n" +
				"Examples:\n" +
				"  eos update consul --fix\n" +
				"  eos update consul --fix --dry-run\n" +
				"  eos update consul --bootstrap-token\n" +
				"  eos update consul --enable-acls\n" +
				"  eos update consul --ports 8161 -> default --dry-run")
	}

	// Handle --bootstrap-token flag (ACL bootstrap reset and recovery)
	if consulBootstrapToken {
		logger.Info("Running ACL bootstrap token reset and recovery",
			zap.Bool("dry_run", consulDryRun))

		// Need Vault client to store the bootstrap token
		vaultClient, err := vault.GetVaultClient(rc)
		if err != nil {
			return fmt.Errorf("failed to get Vault client: %w\n\n"+
				"ACL bootstrap token must be stored securely in Vault.\n"+
				"Vault client is required to store the token.\n\n"+
				"Remediation:\n"+
				"  - Ensure Vault is installed: eos create vault\n"+
				"  - Ensure Vault is unsealed: vault status\n"+
				"  - Check Vault agent is running: systemctl status vault-agent-eos",
				err)
		}

		// Delegate to pkg/consul/acl/reset.go
		resetConfig := &consulacl.ResetConfig{
			VaultClient: vaultClient,
			Force:       false,
			DryRun:      consulDryRun,
			DataDir:     consulDataDir, // User-provided or empty for auto-detection
		}

		result, err := consulacl.ResetACLBootstrap(rc, resetConfig)
		if err != nil {
			return err
		}

		logger.Info("ACL bootstrap reset completed",
			zap.Bool("already_done", result.AlreadyDone),
			zap.Bool("stored_in_vault", result.StoredInVault),
			zap.String("accessor", result.Accessor))

		return nil
	}

	// Handle --enable-acls flag (ACL enablement in config)
	if consulEnableACLs {
		logger.Info("Enabling ACLs in Consul configuration",
			zap.Bool("dry_run", consulDryRun))

		if consulDryRun {
			logger.Info("DRY RUN MODE: Would enable ACLs in configuration")
			logger.Info("  - Would backup /etc/consul.d/consul.hcl")
			logger.Info("  - Would modify ACL block to set enabled = true")
			logger.Info("  - Would validate HCL syntax")
			logger.Info("  - Would restart Consul service if config changed")
			logger.Info("")
			logger.Info("Run without --dry-run to apply changes")
			return nil
		}

		// Delegate to pkg/consul/config/acl_enablement.go
		enableConfig := &consulconfig.ACLEnablementConfig{
			ConfigPath:     "/etc/consul.d/consul.hcl",
			BackupEnabled:  true,
			ValidateSyntax: true,
			DefaultPolicy:  "deny", // Secure by default
		}

		result, err := consulconfig.EnableACLsInConfig(rc, enableConfig)
		if err != nil {
			return fmt.Errorf("failed to enable ACLs: %w", err)
		}

		if result.ConfigChanged {
			logger.Info("ACL configuration updated successfully",
				zap.String("backup_path", result.BackupPath))

			// Restart Consul service to apply changes
			logger.Info("Restarting Consul service to apply ACL configuration")
			if err := consulconfig.RestartConsulService(rc); err != nil {
				return fmt.Errorf("failed to restart Consul service: %w\n\n"+
					"Configuration was updated but Consul restart failed.\n"+
					"Remediation:\n"+
					"  - Manually restart: systemctl restart consul\n"+
					"  - Check service status: systemctl status consul\n"+
					"  - View logs: journalctl -u consul -n 50\n"+
					"  - Restore backup if needed: cp %s /etc/consul.d/consul.hcl",
					err, result.BackupPath)
			}

			logger.Info("Consul service restarted successfully")
			logger.Info("ACLs are now enabled with deny-by-default policy")
			logger.Info("Next steps:")
			logger.Info("  1. Bootstrap ACLs: consul acl bootstrap")
			logger.Info("  2. Or use Eos: eos update consul --bootstrap-token")
			logger.Info("  3. Create policies and tokens as needed")
		} else {
			logger.Info(result.Message)
		}

		return nil
	}

	// Handle --fix flag (configuration drift correction)
	if consulFix {
		logger.Info("Running configuration drift correction",
			zap.Bool("dry_run", consulDryRun))

		// Delegate to pkg/consul/fix - same logic as 'eos fix consul'
		config := &consulfix.Config{
			DryRun:          consulDryRun,
			PermissionsOnly: false,
			SkipRestart:     false,
		}

		return consulfix.RunFixes(rc, config)
	}

	// Validate ports flag is specified
	if consulPorts == "" {
		return eos_err.NewUserError(
			"Must specify one of: --ports, --fix, --bootstrap-token, or --enable-acls.\n\n" +
				"Fix configuration drift:\n" +
				"  eos update consul --fix\n" +
				"  eos update consul --fix --dry-run  (preview without applying)\n\n" +
				"Reset ACL bootstrap token:\n" +
				"  eos update consul --bootstrap-token\n" +
				"  eos update consul --bootstrap-token --dry-run\n\n" +
				"Enable ACLs in configuration:\n" +
				"  eos update consul --enable-acls\n" +
				"  eos update consul --enable-acls --dry-run\n\n" +
				"Port migration:\n" +
				"  eos update consul --ports 8161 -> default\n" +
				"  eos update consul --ports 8161 -> 8500 --dry-run\n" +
				"  eos update consul --ports 8389 -> 8600")
	}

	logger.Info("Starting Consul port update",
		zap.String("ports", consulPorts),
		zap.Bool("dry_run", consulDryRun))

	// Parse port migration syntax (business logic in pkg/)
	portMigration, err := consul.ParsePortMigrationSyntax(consulPorts)
	if err != nil {
		return err
	}

	// Prepare configuration for update
	updateConfig := &consul.UpdatePortsConfig{
		PortMigration: portMigration,
		DryRun:        consulDryRun,
		ConfigPath:    "/etc/consul.d/consul.hcl",
	}

	// Delegate to business logic in pkg/consul
	return consul.UpdateConsulPorts(rc, updateConfig)
}
