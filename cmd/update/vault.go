// cmd/update/vault.go
package update

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/environment"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	vaultfix "github.com/CodeMonkeyCybersecurity/eos/pkg/vault/fix"
	"github.com/hashicorp/vault/api"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var (
	vaultPorts          string
	vaultAddress        string
	vaultDryRun         bool
	vaultUpdatePolicies bool
	vaultFix            bool
	vaultUnseal         bool
)

// VaultCmd updates Vault configuration
var VaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Update Vault configuration",
	Long: `Update Vault's configuration by modifying settings and restarting the service.

The command intelligently updates:
1. Vault address stored in Consul KV (--address)
2. Vault HCL configuration file ports (--ports)
3. Vault policies to latest version (--update-policies)
4. Configuration drift correction (--fix)
5. Vault seal status (--unseal)
6. Restarts Vault service to apply changes (ports only)
7. Verifies new configuration is accessible

Unseal Vault:
  --unseal     Unseal Vault using stored unseal keys
               Loads unseal keys from /run/eos/vault_init_output.json
               Automatically unseals if Vault is sealed
               Idempotent: safe to run multiple times

Configuration Drift Correction:
  --fix        Detect and correct drift from canonical state
  --dry-run    Preview changes without applying (works with --fix, --ports, --address)

  The --fix flag compares current Vault installation against the canonical
  state from 'eos create vault' and automatically corrects:
  - File permissions (config, data, TLS certs)
  - Duplicate binaries
  - Configuration file syntax
  - API/cluster addresses (localhost → hostname)

  Like combing through the configuration to correct any settings that drifted.

Examples:
  # Unseal Vault (recommended after seal or reboot)
  eos update vault --unseal

  # Detect and fix all configuration drift
  eos update vault --fix

  # Show what would be fixed (dry-run)
  eos update vault --fix --dry-run

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
		"Preview changes without applying them (works with --fix, --ports, --address)")
	VaultCmd.Flags().BoolVar(&vaultUpdatePolicies, "update-policies", false,
		"Update Vault policies to latest version (requires root token)")
	VaultCmd.Flags().BoolVar(&vaultFix, "fix", false,
		"Fix configuration drift from canonical state (use --dry-run to preview)")
	VaultCmd.Flags().BoolVar(&vaultUnseal, "unseal", false,
		"Unseal Vault using stored unseal keys from initialization")
}

func runVaultUpdate(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Determine which operation to perform

	// Count how many operation types were requested (--dry-run is a modifier, not an operation)
	operationCount := 0
	if vaultFix {
		operationCount++
	}
	if vaultUpdatePolicies {
		operationCount++
	}
	if vaultAddress != "" {
		operationCount++
	}
	if vaultPorts != "" {
		operationCount++
	}
	if vaultUnseal {
		operationCount++
	}

	// CRITICAL: Only allow ONE operation at a time
	if operationCount > 1 {
		return eos_err.NewUserError(
			"Cannot specify multiple operations simultaneously.\n\n" +
				"Choose ONE of:\n" +
				"  --unseal          Unseal Vault\n" +
				"  --fix             Fix configuration drift\n" +
				"  --address         Update Vault address\n" +
				"  --ports           Migrate ports\n" +
				"  --update-policies Update policies\n\n" +
				"Use --dry-run to preview changes for any operation.\n\n" +
				"Examples:\n" +
				"  eos update vault --unseal\n" +
				"  eos update vault --fix\n" +
				"  eos update vault --fix --dry-run\n" +
				"  eos update vault --address vhost5\n" +
				"  eos update vault --ports 8179 -> default --dry-run")
	}

	// Handle --unseal flag first (most common operation)
	if vaultUnseal {
		return runVaultUnseal(rc)
	}

	// Handle --fix flag (configuration drift correction)
	if vaultFix {
		logger.Info("Running configuration drift correction",
			zap.Bool("dry_run", vaultDryRun))

		// Delegate to pkg/vault/fix - same logic as 'eos fix vault'
		config := &vaultfix.Config{
			DryRun: vaultDryRun,
			All:    true, // Check all drift types
		}

		result, err := vaultfix.RunFixes(rc, config)
		if err != nil {
			return fmt.Errorf("drift correction failed: %w", err)
		}

		displayFixSummary(rc, result, vaultDryRun)
		return nil
	}

	// Policy update is standalone
	if vaultUpdatePolicies {
		return runVaultPolicyUpdate(rc)
	}

	if vaultAddress != "" && vaultPorts != "" {
		return eos_err.NewUserError(
			"Cannot specify both --address and --ports.\n\n" +
				"Use --address to update Vault address in Consul KV:\n" +
				"  eos update vault --address vhost5\n\n" +
				"Use --ports to migrate Vault ports:\n" +
				"  eos update vault --ports 8179 -> default\n\n" +
				"Use --update-policies to update Vault policies:\n" +
				"  eos update vault --update-policies\n\n" +
				"Use --fix to correct configuration drift:\n" +
				"  eos update vault --fix")
	}

	if vaultAddress == "" && vaultPorts == "" {
		return eos_err.NewUserError(
			"Must specify one of: --unseal, --address, --ports, --update-policies, or --fix.\n\n" +
				"Unseal Vault (after reboot or seal):\n" +
				"  eos update vault --unseal\n\n" +
				"Fix configuration drift:\n" +
				"  eos update vault --fix\n" +
				"  eos update vault --fix --dry-run  (preview without applying)\n\n" +
				"Update Vault address in Consul KV:\n" +
				"  eos update vault --address vhost5\n" +
				"  eos update vault --address 192.168.1.10\n" +
				"  eos update vault --address vault.example.com:8200\n\n" +
				"Migrate Vault ports:\n" +
				"  eos update vault --ports 8179 -> default\n" +
				"  eos update vault --ports 8179 -> 8200 --dry-run\n\n" +
				"Update policies to latest version:\n" +
				"  eos update vault --update-policies")
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
		logger.Info(fmt.Sprintf("  export VAULT_ADDR=https://%s:%d", shared.GetInternalHostname(), result.NewAPIPort))
		logger.Info("")
		logger.Info("Or add to your shell profile:")
		logger.Info(fmt.Sprintf("  echo 'export VAULT_ADDR=https://%s:%d' >> ~/.bashrc", shared.GetInternalHostname(), result.NewAPIPort))
		logger.Info("")
	}

	logger.Info("Code Monkey Cybersecurity - 'Cybersecurity. With humans.'")
	logger.Info("================================================================================")
}

// runVaultPolicyUpdate updates Vault policies to the latest version
func runVaultPolicyUpdate(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("================================================================================")
	logger.Info("Updating Vault Policies to Latest Version")
	logger.Info("================================================================================")
	logger.Info("")

	// ASSESS - Check Vault seal status BEFORE attempting authentication
	// This provides clear, actionable errors instead of cryptic 503 responses
	logger.Info("Checking Vault status...")
	initialized, sealed, err := vault.CheckVaultSealStatusUnauthenticated(rc)
	if err != nil {
		return fmt.Errorf("failed to check Vault status: %w\n\n"+
			"Ensure Vault service is running:\n"+
			"  sudo systemctl status vault", err)
	}

	if !initialized {
		return eos_err.NewUserError(
			"Vault is not initialized.\n\n" +
				"Initialize Vault first:\n" +
				"  sudo eos create vault")
	}

	if sealed {
		return eos_err.NewUserError(
			"Vault is sealed. Unseal it first:\n\n" +
				"Automatic unsealing:\n" +
				"  sudo eos update vault --unseal\n\n" +
				"Manual unsealing:\n" +
				"  vault operator unseal")
	}

	logger.Info("✓ Vault is unsealed and ready")
	logger.Info("")

	// ASSESS - Get root client
	logger.Info("Authenticating to Vault (requires root token)...")
	_, err = vault.GetRootClient(rc)
	if err != nil {
		return fmt.Errorf("failed to get root client: %w\n\n"+
			"This operation requires root token access.\n"+
			"The root token is stored in: %s", err, shared.VaultInitPath)
	}

	logger.Info("✓ Authenticated with root token")
	logger.Info("")

	// INTERVENE - Write policies using existing infrastructure
	logger.Info("Updating policies...")
	if err := vault.EnsurePolicy(rc); err != nil {
		return fmt.Errorf("failed to write policies: %w", err)
	}

	logger.Info("")
	logger.Info("================================================================================")
	logger.Info("✓ Vault Policies Updated Successfully")
	logger.Info("================================================================================")
	logger.Info("")
	logger.Info("Updated policies:")
	logger.Info("  • eos-default-policy - Standard user access")
	logger.Info("    ├─ Service secrets: secret/data/services/*")
	logger.Info("    ├─ Consul integration: secret/data/consul/*")
	logger.Info("    ├─ Secrets engine management: sys/mounts (read/list)")
	logger.Info("    ├─ Secrets engine enablement: sys/mounts/{consul,database,pki}")
	logger.Info("    └─ Consul secrets engine: consul/* (dynamic token generation)")
	logger.Info("  • eos-admin-policy - Infrastructure management")
	logger.Info("  • eos-emergency-policy - Emergency response")
	logger.Info("  • eos-readonly-policy - Monitoring and auditing")
	logger.Info("")
	logger.Info("All tokens using these policies now have the updated permissions.")
	logger.Info("No restart or re-authentication required - changes are immediate.")
	logger.Info("")
	logger.Info("Vault-Consul integration now enabled:")
	logger.Info("  • Run: sudo eos sync --vault --consul")
	logger.Info("")
	logger.Info("Code Monkey Cybersecurity - 'Cybersecurity. With humans.'")
	logger.Info("================================================================================")

	return nil
}

// displayFixSummary shows the results of drift correction
func displayFixSummary(rc *eos_io.RuntimeContext, result *vaultfix.RepairResult, dryRun bool) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("================================================================================")
	if dryRun {
		logger.Info("Configuration Drift Detection Report (Dry-Run)")
	} else {
		logger.Info("Configuration Drift Correction Results")
	}
	logger.Info("================================================================================")
	logger.Info(fmt.Sprintf("  Issues detected: %d", result.IssuesFound))

	if dryRun {
		logger.Info(fmt.Sprintf("  Would fix: %d issues", result.IssuesFixed))
		logger.Info("")
		logger.Info("Run with --fix (without --drift) to apply corrections")
	} else {
		logger.Info(fmt.Sprintf("  Issues corrected: %d", result.IssuesFixed))
		if result.IssuesFixed == result.IssuesFound && result.IssuesFound > 0 {
			logger.Info("")
			logger.Info("✓ All drift corrected - Vault matches canonical state")
		} else if result.IssuesFound == 0 {
			logger.Info("")
			logger.Info("✓ No drift detected - Vault matches canonical state")
		}
	}

	if len(result.Errors) > 0 {
		logger.Info("")
		logger.Info(fmt.Sprintf("Encountered %d errors during correction:", len(result.Errors)))
		for i, err := range result.Errors {
			logger.Info(fmt.Sprintf("  %d. %v", i+1, err))
		}
	}

	logger.Info("================================================================================")
}

// runVaultUnseal unseals Vault using stored unseal keys
func runVaultUnseal(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("================================================================================")
	logger.Info("Unsealing Vault")
	logger.Info("================================================================================")
	logger.Info("")

	// ASSESS - Check if Vault is running
	logger.Info("[ASSESS] Checking Vault status")

	// Use unauthenticated client to check seal status
	initialized, sealed, err := vault.CheckVaultSealStatusUnauthenticated(rc)
	if err != nil {
		return fmt.Errorf("failed to check Vault status: %w\n\n"+
			"Ensure Vault service is running:\n"+
			"  systemctl status vault", err)
	}

	if !initialized {
		return eos_err.NewUserError(
			"Vault is not initialized.\n\n" +
				"Initialize Vault first:\n" +
				"  sudo eos create vault")
	}

	if !sealed {
		logger.Info("✓ Vault is already unsealed")
		logger.Info("")
		logger.Info("No action needed - Vault is ready to use.")
		logger.Info("================================================================================")
		return nil
	}

	logger.Info("Vault is sealed - proceeding with unseal operation")
	logger.Info("")

	// INTERVENE - Unseal Vault (UNAUTHENTICATED operation)
	logger.Info("[INTERVENE] Unsealing Vault with stored unseal keys")
	logger.Debug("Unsealing is an unauthenticated operation - no token required")

	// Create UNAUTHENTICATED client for unseal operation
	// CRITICAL: Unsealing does NOT require authentication by design
	// The /v1/sys/seal-status and /v1/sys/unseal endpoints are unauthenticated
	vaultAddr := shared.GetVaultAddrWithEnv()
	config := api.DefaultConfig()
	config.Address = vaultAddr

	// Read environment for VAULT_SKIP_VERIFY and other settings
	if err := config.ReadEnvironment(); err != nil {
		logger.Warn("Failed to read Vault environment config", zap.Error(err))
		// Continue anyway - ReadEnvironment is best-effort
	}

	client, err := api.NewClient(config)
	if err != nil {
		return fmt.Errorf("failed to create unauthenticated Vault client: %w", err)
	}
	// No token set - this is intentional, unsealing doesn't need authentication

	logger.Debug("Unauthenticated client created",
		zap.String("vault_addr", vaultAddr))

	// Use existing unseal infrastructure
	unsealed, err := vault.UnsealVaultIfNeeded(rc, client)
	if err != nil {
		return fmt.Errorf("unseal operation failed: %w\n\n"+
			"Common causes:\n"+
			"  • Unseal keys not found in /run/eos/vault_init_output.json\n"+
			"  • Insufficient unseal keys provided\n"+
			"  • Vault service not responding\n\n"+
			"Manual unseal:\n"+
			"  vault operator unseal", err)
	}

	if !unsealed {
		logger.Warn("Vault was already unsealed (no operation performed)")
	} else {
		logger.Info("✓ Vault unsealed successfully")
	}

	// EVALUATE - Verify Vault is operational
	logger.Info("")
	logger.Info("[EVALUATE] Verifying Vault is operational")

	finalInitialized, finalSealed, err := vault.CheckVaultSealStatusUnauthenticated(rc)
	if err != nil {
		logger.Warn("Could not verify final seal status", zap.Error(err))
	} else if finalSealed {
		return fmt.Errorf("vault is still sealed after unseal operation\n\n" +
			"This should not happen - please check Vault logs:\n" +
			"  journalctl -u vault -n 50")
	} else if !finalInitialized {
		return fmt.Errorf("vault is not initialized - unexpected state")
	} else {
		logger.Info("✓ Vault is unsealed and operational")
	}

	logger.Info("")
	logger.Info("================================================================================")
	logger.Info("✓ Unseal Complete")
	logger.Info("================================================================================")
	logger.Info("")
	logger.Info("Vault is now unsealed and ready for use.")
	logger.Info("")
	logger.Info("Next steps:")
	logger.Info("  • Verify Vault health: vault status")
	logger.Info("  • Check authentication: vault token lookup")
	logger.Info("  • List secrets engines: vault secrets list")
	logger.Info("")
	logger.Info("Code Monkey Cybersecurity - 'Cybersecurity. With humans.'")
	logger.Info("================================================================================")

	return nil
}
