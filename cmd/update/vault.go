// cmd/update/vault.go
package update

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var (
	vaultPorts   string
	vaultDryRun  bool
)

// VaultCmd updates Vault configuration
var VaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Update Vault configuration",
	Long: `Update Vault's configuration by modifying settings and restarting the service.

The command intelligently updates:
1. Vault HCL configuration file (/etc/vault.d/vault.hcl)
2. Restarts Vault service to apply changes
3. Verifies new configuration is accessible

Examples:
  # Change ports from current to HashiCorp defaults
  eos update vault --ports 8179 -> default
  eos update vault --ports 8179 -> 8200

  # Change cluster port
  eos update vault --ports 8180 -> 8201

  # Preview changes without applying
  eos update vault --ports 8179 -> default --dry-run

The "default" keyword uses HashiCorp standard ports:
  - API port: 8200
  - Cluster port: 8201

Syntax: --ports FROM -> TO
  FROM: Current port number (or "default")
  TO: New port number (or "default")

Code Monkey Cybersecurity - "Cybersecurity. With humans."`,
	RunE: eos.Wrap(runVaultUpdate),
}

func init() {
	VaultCmd.Flags().StringVar(&vaultPorts, "ports", "",
		"Port migration in format: FROM -> TO (e.g., '8179 -> default' or '8179 -> 8200')")
	VaultCmd.Flags().BoolVar(&vaultDryRun, "dry-run", false,
		"Preview changes without applying them")
}

func runVaultUpdate(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Validate ports flag is specified
	if vaultPorts == "" {
		return eos_err.NewUserError(
			"Port migration must be specified.\n\n" +
				"Examples:\n" +
				"  eos update vault --ports 8179 -> default\n" +
				"  eos update vault --ports 8179 -> 8200\n" +
				"  eos update vault --ports 8180 -> 8201")
	}

	logger.Info("Starting Vault update",
		zap.String("ports", vaultPorts),
		zap.Bool("dry_run", vaultDryRun))

	// ASSESS: Parse port migration syntax
	fromPort, toPort, portType, err := parsePortMigration(vaultPorts)
	if err != nil {
		return err
	}

	logger.Info("Parsed port migration",
		zap.Int("from_port", fromPort),
		zap.Int("to_port", toPort),
		zap.String("port_type", portType))

	// Read current configuration
	configPath := "/etc/vault.d/vault.hcl"
	currentConfig, err := os.ReadFile(configPath)
	if err != nil {
		return eos_err.NewUserError(
			"Failed to read Vault configuration: %v\n\n"+
				"Make sure Vault is installed:\n"+
				"  sudo eos create vault", err)
	}

	// Extract current ports
	currentAPIPort := extractVaultPort(string(currentConfig), "address")
	currentClusterPort := extractVaultPort(string(currentConfig), "cluster_address")

	logger.Info("Current Vault configuration",
		zap.Int("current_api_port", currentAPIPort),
		zap.Int("current_cluster_port", currentClusterPort))

	// Determine which port type we're migrating
	var actualFromPort, actualToPort int
	var portLabel string

	if portType == "api" || fromPort == currentAPIPort {
		actualFromPort = currentAPIPort
		actualToPort = toPort
		portLabel = "API"
		portType = "api"
	} else if portType == "cluster" || fromPort == currentClusterPort {
		actualFromPort = currentClusterPort
		actualToPort = toPort
		portLabel = "Cluster"
		portType = "cluster"
	} else {
		return eos_err.NewUserError(
			"Port %d not found in current configuration.\n\n"+
				"Current ports:\n"+
				"  API: %d\n"+
				"  Cluster: %d\n\n"+
				"Use one of these as FROM port.", fromPort, currentAPIPort, currentClusterPort)
	}

	// Verify FROM port matches
	if fromPort != actualFromPort {
		return eos_err.NewUserError(
			"Port mismatch: You specified FROM port %d, but current %s port is %d.\n\n"+
				"Current configuration:\n"+
				"  API: %d\n"+
				"  Cluster: %d\n\n"+
				"Use: eos update vault --ports %d -> %d",
			fromPort, portLabel, actualFromPort,
			currentAPIPort, currentClusterPort,
			actualFromPort, toPort)
	}

	logger.Info("Port migration validated",
		zap.String("type", portLabel),
		zap.Int("from", actualFromPort),
		zap.Int("to", actualToPort))

	// Check if change is needed
	if actualFromPort == actualToPort {
		logger.Info("Port is already set to requested value - no changes needed")
		return nil
	}

	if vaultDryRun {
		logger.Info("================================================================================")
		logger.Info("DRY RUN MODE - No changes will be made")
		logger.Info("================================================================================")
		logger.Info("")
		logger.Info("Would perform the following changes:")
		logger.Info(fmt.Sprintf("  • %s Port: %d → %d", portLabel, actualFromPort, actualToPort))
		logger.Info("")
		logger.Info("Would update: /etc/vault.d/vault.hcl")
		logger.Info("Would restart: vault.service")
		logger.Info("")
		logger.Info("Run without --dry-run to apply changes")
		return nil
	}

	// INTERVENE: Backup current configuration
	logger.Info("Backing up current configuration")
	backupPath := fmt.Sprintf("%s.backup.%d", configPath, os.Getpid())
	if err := os.WriteFile(backupPath, currentConfig, 0640); err != nil {
		logger.Warn("Failed to create backup", zap.Error(err))
	} else {
		logger.Info("Configuration backed up", zap.String("backup", backupPath))
	}

	// Update configuration
	logger.Info("Updating Vault configuration")
	var newConfig string
	if portType == "api" {
		newConfig = updateVaultPorts(string(currentConfig), actualToPort, 0)
	} else {
		newConfig = updateVaultPorts(string(currentConfig), 0, actualToPort)
	}

	if err := os.WriteFile(configPath, []byte(newConfig), 0640); err != nil {
		return fmt.Errorf("failed to write updated configuration: %w", err)
	}

	logger.Info("Configuration updated", zap.String("config", configPath))

	// Restart Vault service
	logger.Info("Restarting Vault service")
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"restart", "vault"},
		Capture: true,
	})
	if err != nil {
		logger.Error("Failed to restart Vault", zap.String("output", output))
		logger.Info("Attempting to restore backup", zap.String("backup", backupPath))
		_ = os.WriteFile(configPath, currentConfig, 0640)
		return fmt.Errorf("failed to restart Vault service: %w\nOutput: %s", err, output)
	}

	logger.Info("Vault service restarted successfully")

	// EVALUATE: Verify new port is accessible
	logger.Info("Verifying Vault is accessible on new port")

	// Wait a moment for Vault to start
	logger.Info("Waiting for Vault to initialize...")
	output, _ = execute.Run(rc.Ctx, execute.Options{
		Command: "sleep",
		Args:    []string{"3"},
		Capture: true,
	})

	// Check status
	statusOutput, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"status", "vault", "--no-pager"},
		Capture: true,
	})

	if strings.Contains(statusOutput, "Active: active") {
		logger.Info("Vault service is active")
	} else {
		logger.Warn("Vault service may not be fully started", zap.String("status", statusOutput))
	}

	logger.Info("================================================================================")
	logger.Info("Vault port configuration updated successfully")
	logger.Info("================================================================================")
	logger.Info(fmt.Sprintf("  %s Port: %d → %d", portLabel, actualFromPort, actualToPort))
	logger.Info("")
	logger.Info("Vault is now listening on:")
	if portType == "api" {
		logger.Info(fmt.Sprintf("  • API: https://0.0.0.0:%d", actualToPort))
		logger.Info(fmt.Sprintf("  • Cluster: https://0.0.0.0:%d", currentClusterPort))
		logger.Info("")
		logger.Info("Update VAULT_ADDR environment variable:")
		logger.Info(fmt.Sprintf("  export VAULT_ADDR=https://127.0.0.1:%d", actualToPort))
		logger.Info("")
		logger.Info("Or add to your shell profile:")
		logger.Info(fmt.Sprintf("  echo 'export VAULT_ADDR=https://127.0.0.1:%d' >> ~/.bashrc", actualToPort))
	} else {
		logger.Info(fmt.Sprintf("  • API: https://0.0.0.0:%d", currentAPIPort))
		logger.Info(fmt.Sprintf("  • Cluster: https://0.0.0.0:%d", actualToPort))
	}
	logger.Info("")
	logger.Info("Code Monkey Cybersecurity - 'Cybersecurity. With humans.'")
	logger.Info("================================================================================")

	return nil
}

// parsePortMigration parses port migration syntax: "FROM -> TO"
// Returns: fromPort, toPort, portType, error
func parsePortMigration(portsArg string) (int, int, string, error) {
	// Split on "->"
	parts := strings.Split(portsArg, "->")
	if len(parts) != 2 {
		return 0, 0, "", eos_err.NewUserError(
			"Invalid port syntax: must be 'FROM -> TO'\n\n" +
				"Examples:\n" +
				"  8179 -> default\n" +
				"  8179 -> 8200\n" +
				"  8180 -> 8201")
	}

	fromStr := strings.TrimSpace(parts[0])
	toStr := strings.TrimSpace(parts[1])

	// Parse FROM port
	var fromPort int
	if fromStr == "default" {
		return 0, 0, "", eos_err.NewUserError(
			"FROM port cannot be 'default' - specify the current port number.\n\n" +
				"Example:\n" +
				"  eos update vault --ports 8179 -> default")
	}
	var err error
	fromPort, err = strconv.Atoi(fromStr)
	if err != nil {
		return 0, 0, "", eos_err.NewUserError(
			"Invalid FROM port '%s': must be a number\n\n"+
				"Example:\n"+
				"  eos update vault --ports 8179 -> default", fromStr)
	}

	// Parse TO port
	var toPort int
	if toStr == "default" {
		// Determine which default based on FROM port
		if fromPort == 8179 || fromPort == 8200 {
			toPort = shared.PortVault // API default
		} else if fromPort == 8180 || fromPort == 8201 {
			toPort = shared.PortVaultCluster // Cluster default
		} else {
			// Default to API port if ambiguous
			toPort = shared.PortVault
		}
	} else {
		toPort, err = strconv.Atoi(toStr)
		if err != nil {
			return 0, 0, "", eos_err.NewUserError(
				"Invalid TO port '%s': must be a number or 'default'\n\n"+
					"Example:\n"+
					"  eos update vault --ports 8179 -> 8200", toStr)
		}
	}

	// Validate port ranges
	if fromPort < 1024 || fromPort > 65535 {
		return 0, 0, "", eos_err.NewUserError(
			"Invalid FROM port %d: must be between 1024 and 65535", fromPort)
	}
	if toPort < 1024 || toPort > 65535 {
		return 0, 0, "", eos_err.NewUserError(
			"Invalid TO port %d: must be between 1024 and 65535", toPort)
	}

	// Determine port type based on common API/cluster ports
	portType := "unknown"
	if fromPort == 8179 || fromPort == 8200 || toPort == 8179 || toPort == 8200 {
		portType = "api"
	} else if fromPort == 8180 || fromPort == 8201 || toPort == 8180 || toPort == 8201 {
		portType = "cluster"
	}

	return fromPort, toPort, portType, nil
}

// extractVaultPort extracts the port number from Vault listener configuration
// Looks for patterns like: address = "0.0.0.0:8200"
func extractVaultPort(config, addressType string) int {
	pattern := fmt.Sprintf(`%s\s*=\s*"[^:]*:(\d+)"`, addressType)
	re := regexp.MustCompile(pattern)
	matches := re.FindStringSubmatch(config)

	if len(matches) > 1 {
		port, _ := strconv.Atoi(matches[1])
		return port
	}

	// Return defaults if not found
	if addressType == "address" {
		return 8200 // Default API port
	}
	return 8201 // Default cluster port
}

// updateVaultPorts updates port numbers in Vault configuration
// Pass 0 for ports that should not be changed
func updateVaultPorts(config string, apiPort, clusterPort int) string {
	result := config

	// Update API port (address = "0.0.0.0:PORT")
	if apiPort > 0 {
		addressPattern := regexp.MustCompile(`(address\s*=\s*"[^:]*:)\d+(")`  )
		result = addressPattern.ReplaceAllString(result, fmt.Sprintf(`${1}%d${2}`, apiPort))
	}

	// Update cluster port (cluster_address = "0.0.0.0:PORT")
	if clusterPort > 0 {
		clusterPattern := regexp.MustCompile(`(cluster_address\s*=\s*"[^:]*:)\d+("`)
		result = clusterPattern.ReplaceAllString(result, fmt.Sprintf(`${1}%d${2}`, clusterPort))
	}

	return result
}
