// cmd/update/vault.go
package update

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/environment"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var (
	vaultPorts   string
	vaultAddress string
	vaultDryRun  bool
)

// VaultCmd updates Vault configuration
var VaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Update Vault configuration",
	Long: `Update Vault's configuration by modifying settings and restarting the service.

The command intelligently updates:
1. Vault address stored in Consul KV (--address)
2. Vault HCL configuration file ports (--ports)
3. Restarts Vault service to apply changes (ports only)
4. Verifies new configuration is accessible

Examples:
  # Update Vault address (stored in Consul KV for discovery)
  eos update vault --address vhost5
  eos update vault --address 192.168.1.10
  eos update vault --address vault.example.com:8200
  eos update vault --address https://vault.internal.net

  # Change ports from current to HashiCorp defaults
  eos update vault --ports 8179 -> default
  eos update vault --ports 8179 -> 8200

  # Change cluster port
  eos update vault --ports 8180 -> 8201

  # Preview port changes without applying
  eos update vault --ports 8179 -> default --dry-run

The "default" keyword uses HashiCorp standard ports:
  - API port: 8200
  - Cluster port: 8201

Address Format:
  - IP: 192.168.1.10 or 192.168.1.10:8200
  - DNS: vault.example.com or vault.example.com:8200
  - Tailscale: vhost5 or vhost5:8200
  - URL: https://vault.internal.net:8200
  (Protocol defaults to https, port defaults to 8200)

Ports Syntax: --ports FROM -> TO
  FROM: Current port number (or "default")
  TO: New port number (or "default")

Code Monkey Cybersecurity - "Cybersecurity. With humans."`,
	RunE: eos.Wrap(runVaultUpdate),
}

func init() {
	VaultCmd.Flags().StringVar(&vaultAddress, "address", "",
		"Vault address (IP, DNS, or Tailscale name) to store in Consul KV")
	VaultCmd.Flags().StringVar(&vaultPorts, "ports", "",
		"Port migration in format: FROM -> TO (e.g., '8179 -> default' or '8179 -> 8200')")
	VaultCmd.Flags().BoolVar(&vaultDryRun, "dry-run", false,
		"Preview changes without applying them")
}

func runVaultUpdate(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	// ASSESS - Determine which operation to perform
	if vaultAddress != "" && vaultPorts != "" {
		return eos_err.NewUserError(
			"Cannot specify both --address and --ports.\n\n" +
				"Use --address to update Vault address in Consul KV:\n" +
				"  eos update vault --address vhost5\n\n" +
				"Use --ports to migrate Vault ports:\n" +
				"  eos update vault --ports 8179 -> default")
	}

	if vaultAddress == "" && vaultPorts == "" {
		return eos_err.NewUserError(
			"Must specify either --address or --ports.\n\n" +
				"Update Vault address in Consul KV:\n" +
				"  eos update vault --address vhost5\n" +
				"  eos update vault --address 192.168.1.10\n" +
				"  eos update vault --address vault.example.com:8200\n\n" +
				"Migrate Vault ports:\n" +
				"  eos update vault --ports 8179 -> default\n" +
				"  eos update vault --ports 8179 -> 8200")
	}

	// Route to appropriate handler
	if vaultAddress != "" {
		return runVaultAddressUpdate(rc)
	}
	return runVaultPortsUpdate(rc)
}

// runVaultAddressUpdate orchestrates Vault address update
func runVaultAddressUpdate(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting Vault address update",
		zap.String("address", vaultAddress))

	// Discover environment
	envConfig, err := environment.DiscoverEnvironment(rc)
	if err != nil {
		return fmt.Errorf("failed to discover environment: %w", err)
	}

	logger.Debug("Environment discovered",
		zap.String("environment", envConfig.Environment))

	// Initialize Vault discovery client
	vaultDiscovery, err := vault.NewVaultDiscovery(rc, envConfig.Environment)
	if err != nil {
		return fmt.Errorf("failed to initialize Vault discovery: %w", err)
	}

	// Store the address (business logic in pkg/vault/discovery.go)
	if err := vaultDiscovery.StoreVaultAddress(rc.Ctx, vaultAddress); err != nil {
		return err
	}

	// Retrieve and display the stored address
	storedAddr, err := vaultDiscovery.DiscoverVaultAddress(rc.Ctx)
	if err != nil {
		logger.Warn("Address stored but discovery failed (non-critical)",
			zap.Error(err))
	}

	// Display results
	displayAddressUpdateResults(logger, envConfig.Environment, storedAddr)

	return nil
}

// runVaultPortsUpdate orchestrates Vault port migration
func runVaultPortsUpdate(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting Vault port update",
		zap.String("ports", vaultPorts),
		zap.Bool("dry_run", vaultDryRun))

	// Create migration config
	config := &vault.PortMigrationConfig{
		PortsArg:   vaultPorts,
		DryRun:     vaultDryRun,
		ConfigPath: vault.VaultConfigPath,
	}

	// Execute migration (all business logic in pkg/vault/port_migration.go)
	result, err := vault.MigrateVaultPorts(rc, config)
	if err != nil {
		return err
	}

	// Display results
	displayPortMigrationResults(logger, result)

	return nil
}

// displayAddressUpdateResults displays the results of address update
func displayAddressUpdateResults(logger otelzap.LoggerWithCtx, environment, storedAddr string) {
	logger.Info("================================================================================")
	logger.Info("Vault address updated successfully")
	logger.Info("================================================================================")
	logger.Info(fmt.Sprintf("  Environment: %s", environment))
	logger.Info(fmt.Sprintf("  Stored Address: %s", storedAddr))
	logger.Info("")
	logger.Info("All Eos Vault operations will now use this address for discovery.")
	logger.Info("")
	logger.Info("Consul KV Key: eos/config/" + environment + "/vault_address")
	logger.Info("")
	logger.Info("Code Monkey Cybersecurity - 'Cybersecurity. With humans.'")
	logger.Info("================================================================================")
}

// displayPortMigrationResults displays the results of port migration
func displayPortMigrationResults(logger otelzap.LoggerWithCtx, result *vault.PortMigrationResult) {
	if !result.Changed {
		logger.Info("Port is already set to requested value - no changes needed")
		return
	}

	// Dry run mode
	if result.NewAPIPort == 0 && result.NewClusterPort == 0 {
		logger.Info("================================================================================")
		logger.Info("DRY RUN MODE - No changes will be made")
		logger.Info("================================================================================")
		logger.Info("")
		logger.Info("Would perform the following changes:")

		if result.PortType == "api" {
			logger.Info(fmt.Sprintf("  • %s Port: %d → %d", result.PortLabel, result.OldAPIPort, result.NewAPIPort))
		} else {
			logger.Info(fmt.Sprintf("  • %s Port: %d → %d", result.PortLabel, result.OldClusterPort, result.NewClusterPort))
		}

		logger.Info("")
		logger.Info("Would update: " + vault.VaultConfigPath)
		logger.Info("Would restart: vault.service")
		logger.Info("")
		logger.Info("Run without --dry-run to apply changes")
		return
	}

	// Success output
	logger.Info("================================================================================")
	logger.Info("Vault port configuration updated successfully")
	logger.Info("================================================================================")

	if result.PortType == "api" {
		logger.Info(fmt.Sprintf("  %s Port: %d → %d", result.PortLabel, result.OldAPIPort, result.NewAPIPort))
	} else {
		logger.Info(fmt.Sprintf("  %s Port: %d → %d", result.PortLabel, result.OldClusterPort, result.NewClusterPort))
	}

	logger.Info("")
	logger.Info("Vault is now listening on:")
	logger.Info(fmt.Sprintf("  • API: https://0.0.0.0:%d", result.NewAPIPort))
	logger.Info(fmt.Sprintf("  • Cluster: https://0.0.0.0:%d", result.NewClusterPort))
	logger.Info("")

	if result.PortType == "api" {
		logger.Info("Update VAULT_ADDR environment variable:")
		logger.Info(fmt.Sprintf("  export VAULT_ADDR=https://127.0.0.1:%d", result.NewAPIPort))
		logger.Info("")
		logger.Info("Or add to your shell profile:")
		logger.Info(fmt.Sprintf("  echo 'export VAULT_ADDR=https://127.0.0.1:%d' >> ~/.bashrc", result.NewAPIPort))
		logger.Info("")
	}

	logger.Info("Code Monkey Cybersecurity - 'Cybersecurity. With humans.'")
	logger.Info("================================================================================")
}
