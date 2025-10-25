// cmd/update/consul.go
package update

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul"
	consulacl "github.com/CodeMonkeyCybersecurity/eos/pkg/consul/acl"
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
)

// ConsulCmd updates Consul configuration
var ConsulCmd = &cobra.Command{
	Use:   "consul",
	Short: "Update Consul configuration",
	Long: `Update Consul's configuration by modifying settings and restarting the service.

The command intelligently updates:
1. Consul HCL configuration file (/etc/consul.d/consul.hcl)
2. Configuration drift correction (--fix)
3. Restarts Consul service to apply changes
4. Verifies new configuration is accessible

Configuration Drift Correction:
  --fix       Detect and correct drift from canonical state
  --dry-run   Preview changes without applying (works with --fix, --ports, --bootstrap-token)

  The --fix flag compares current Consul installation against the canonical
  state from 'eos create consul' and automatically corrects:
  - File permissions (config, data directories)
  - File ownership (consul user/group)
  - Missing helper scripts
  - Systemd service configuration

  Like combing through the configuration to correct any settings that drifted.

ACL Bootstrap Token Recovery:
  --bootstrap-token   Reset ACL bootstrap and recover/generate bootstrap token

  The --bootstrap-token flag performs Consul ACL bootstrap reset when the
  bootstrap token is lost or not stored in Vault. It:
  - Detects current ACL bootstrap state via SDK
  - Writes reset index file to Consul data directory
  - Re-bootstraps ACL system (generates new token)
  - Stores token securely in Vault at secret/consul/bootstrap-token

  This solves the "lost bootstrap token" problem without destroying cluster data.

Examples:
  # Detect and fix all configuration drift
  eos update consul --fix

  # Show what would be fixed (dry-run)
  eos update consul --fix --dry-run

  # Recover lost ACL bootstrap token
  eos update consul --bootstrap-token

  # Preview bootstrap token recovery (dry-run)
  eos update consul --bootstrap-token --dry-run

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
		"Preview changes without applying them (works with --fix, --ports, --bootstrap-token)")
	ConsulCmd.Flags().BoolVar(&consulFix, "fix", false,
		"Fix configuration drift from canonical state (use --dry-run to preview)")
	ConsulCmd.Flags().BoolVar(&consulBootstrapToken, "bootstrap-token", false,
		"Reset ACL bootstrap and recover/generate bootstrap token (stores in Vault)")
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

	// Only allow ONE operation at a time
	if operationCount > 1 {
		return eos_err.NewUserError(
			"Cannot specify multiple operations simultaneously.\n\n" +
				"Choose ONE of:\n" +
				"  --fix              Fix configuration drift\n" +
				"  --ports            Migrate ports\n" +
				"  --bootstrap-token  Reset ACL bootstrap and recover token\n\n" +
				"Use --dry-run to preview changes for any operation.\n\n" +
				"Examples:\n" +
				"  eos update consul --fix\n" +
				"  eos update consul --fix --dry-run\n" +
				"  eos update consul --bootstrap-token\n" +
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
			"Must specify one of: --ports, --fix, or --bootstrap-token.\n\n" +
				"Fix configuration drift:\n" +
				"  eos update consul --fix\n" +
				"  eos update consul --fix --dry-run  (preview without applying)\n\n" +
				"Reset ACL bootstrap token:\n" +
				"  eos update consul --bootstrap-token\n" +
				"  eos update consul --bootstrap-token --dry-run\n\n" +
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
