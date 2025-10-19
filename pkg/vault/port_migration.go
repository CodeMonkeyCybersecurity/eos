// pkg/vault/port_migration.go
// Vault port migration business logic

package vault

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// PortMigrationConfig contains configuration for port migration
type PortMigrationConfig struct {
	PortsArg   string // Raw input: "8179 -> default"
	DryRun     bool
	ConfigPath string
}

// PortMigrationResult contains the result of a port migration
type PortMigrationResult struct {
	Success        bool
	PortType       string // "api" or "cluster"
	PortLabel      string // "API" or "Cluster"
	OldAPIPort     int
	OldClusterPort int
	NewAPIPort     int
	NewClusterPort int
	BackupPath     string
	Changed        bool
}

// ParsedPortMigration represents a parsed port migration request
type ParsedPortMigration struct {
	FromPort int
	ToPort   int
	PortType string // "api", "cluster", or "unknown"
}

// ParsePortMigration parses port migration syntax: "FROM -> TO"
// Returns: ParsedPortMigration or error
func ParsePortMigration(portsArg string) (*ParsedPortMigration, error) {
	// ASSESS - Parse the input syntax
	parts := strings.Split(portsArg, "->")
	if len(parts) != 2 {
		return nil, eos_err.NewUserError(
			"Invalid port syntax: must be 'FROM -> TO'\n\n" +
				"Examples:\n" +
				"  8179 -> default\n" +
				"  8179 -> 8200\n" +
				"  8180 -> 8201")
	}

	fromStr := strings.TrimSpace(parts[0])
	toStr := strings.TrimSpace(parts[1])

	// Parse FROM port
	if fromStr == "default" {
		return nil, eos_err.NewUserError(
			"FROM port cannot be 'default' - specify the current port number.\n\n" +
				"Example:\n" +
				"  eos update vault --ports 8179 -> default")
	}

	fromPort, err := strconv.Atoi(fromStr)
	if err != nil {
		return nil, eos_err.NewUserError(
			"Invalid FROM port '%s': must be a number\n\n"+
				"Example:\n"+
				"  eos update vault --ports 8179 -> default", fromStr)
	}

	// Validate FROM port
	if err := ValidatePort(fromPort); err != nil {
		return nil, eos_err.NewUserError("Invalid FROM port %d: must be between 1024 and 65535", fromPort)
	}

	// Parse TO port
	var toPort int
	if toStr == "default" {
		// Determine which default based on FROM port
		switch fromPort {
		case 8179, 8200:
			toPort = shared.PortVault // API default
		case 8180, 8201:
			toPort = shared.PortVaultCluster // Cluster default
		default:
			// Default to API port if ambiguous
			toPort = shared.PortVault
		}
	} else {
		toPort, err = strconv.Atoi(toStr)
		if err != nil {
			return nil, eos_err.NewUserError(
				"Invalid TO port '%s': must be a number or 'default'\n\n"+
					"Example:\n"+
					"  eos update vault --ports 8179 -> 8200", toStr)
		}
	}

	// Validate TO port
	if err := ValidatePort(toPort); err != nil {
		return nil, eos_err.NewUserError("Invalid TO port %d: must be between 1024 and 65535", toPort)
	}

	// Determine port type based on common API/cluster ports
	portType := "unknown"
	if fromPort == 8179 || fromPort == 8200 || toPort == 8179 || toPort == 8200 {
		portType = "api"
	} else if fromPort == 8180 || fromPort == 8201 || toPort == 8180 || toPort == 8201 {
		portType = "cluster"
	}

	return &ParsedPortMigration{
		FromPort: fromPort,
		ToPort:   toPort,
		PortType: portType,
	}, nil
}

// MigrateVaultPorts performs the complete port migration operation
// Follows Assess -> Intervene -> Evaluate pattern
func MigrateVaultPorts(rc *eos_io.RuntimeContext, config *PortMigrationConfig) (*PortMigrationResult, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Parse migration request
	parsed, err := ParsePortMigration(config.PortsArg)
	if err != nil {
		return nil, err
	}

	logger.Info("Parsed port migration",
		zap.Int("from_port", parsed.FromPort),
		zap.Int("to_port", parsed.ToPort),
		zap.String("port_type", parsed.PortType))

	// ASSESS - Read current configuration
	currentConfig, err := os.ReadFile(config.ConfigPath)
	if err != nil {
		return nil, eos_err.NewUserError(
			"Failed to read Vault configuration: %v\n\n"+
				"Make sure Vault is installed:\n"+
				"  sudo eos create vault", err)
	}

	// ASSESS - Extract current ports
	currentPorts, err := ExtractPorts(string(currentConfig))
	if err != nil {
		return nil, fmt.Errorf("failed to parse current configuration: %w", err)
	}

	logger.Info("Current Vault configuration",
		zap.Int("current_api_port", currentPorts.APIPort),
		zap.Int("current_cluster_port", currentPorts.ClusterPort))

	// ASSESS - Determine which port type we're migrating
	var actualFromPort, actualToPort int
	var portLabel string
	var portType string

	if parsed.PortType == "api" || parsed.FromPort == currentPorts.APIPort {
		actualFromPort = currentPorts.APIPort
		actualToPort = parsed.ToPort
		portLabel = "API"
		portType = "api"
	} else if parsed.PortType == "cluster" || parsed.FromPort == currentPorts.ClusterPort {
		actualFromPort = currentPorts.ClusterPort
		actualToPort = parsed.ToPort
		portLabel = "Cluster"
		portType = "cluster"
	} else {
		return nil, eos_err.NewUserError(
			"Port %d not found in current configuration.\n\n"+
				"Current ports:\n"+
				"  API: %d\n"+
				"  Cluster: %d\n\n"+
				"Use one of these as FROM port.", parsed.FromPort, currentPorts.APIPort, currentPorts.ClusterPort)
	}

	// ASSESS - Verify FROM port matches
	if parsed.FromPort != actualFromPort {
		return nil, eos_err.NewUserError(
			"Port mismatch: You specified FROM port %d, but current %s port is %d.\n\n"+
				"Current configuration:\n"+
				"  API: %d\n"+
				"  Cluster: %d\n\n"+
				"Use: eos update vault --ports %d -> %d",
			parsed.FromPort, portLabel, actualFromPort,
			currentPorts.APIPort, currentPorts.ClusterPort,
			actualFromPort, parsed.ToPort)
	}

	logger.Info("Port migration validated",
		zap.String("type", portLabel),
		zap.Int("from", actualFromPort),
		zap.Int("to", actualToPort))

	// Check if change is needed
	if actualFromPort == actualToPort {
		logger.Info("Port is already set to requested value - no changes needed")
		return &PortMigrationResult{
			Success:        true,
			PortType:       portType,
			PortLabel:      portLabel,
			OldAPIPort:     currentPorts.APIPort,
			OldClusterPort: currentPorts.ClusterPort,
			NewAPIPort:     currentPorts.APIPort,
			NewClusterPort: currentPorts.ClusterPort,
			Changed:        false,
		}, nil
	}

	// Return early if dry run
	if config.DryRun {
		result := &PortMigrationResult{
			Success:        true,
			PortType:       portType,
			PortLabel:      portLabel,
			OldAPIPort:     currentPorts.APIPort,
			OldClusterPort: currentPorts.ClusterPort,
			Changed:        true,
		}

		if portType == "api" {
			result.NewAPIPort = actualToPort
			result.NewClusterPort = currentPorts.ClusterPort
		} else {
			result.NewAPIPort = currentPorts.APIPort
			result.NewClusterPort = actualToPort
		}

		return result, nil
	}

	// INTERVENE - Backup current configuration
	logger.Info("Backing up current configuration")
	backupPath := fmt.Sprintf("%s.backup.%d", config.ConfigPath, os.Getpid())
	if err := os.WriteFile(backupPath, currentConfig, 0640); err != nil {
		logger.Warn("Failed to create backup", zap.Error(err))
	} else {
		logger.Info("Configuration backed up", zap.String("backup", backupPath))
	}

	// INTERVENE - Update configuration
	logger.Info("Updating Vault configuration")
	var newConfig string
	if portType == "api" {
		newConfig = UpdateConfigPorts(string(currentConfig), actualToPort, 0)
	} else {
		newConfig = UpdateConfigPorts(string(currentConfig), 0, actualToPort)
	}

	if err := os.WriteFile(config.ConfigPath, []byte(newConfig), 0640); err != nil {
		return nil, fmt.Errorf("failed to write updated configuration: %w", err)
	}

	logger.Info("Configuration updated", zap.String("config", config.ConfigPath))

	// INTERVENE - Restart Vault service
	logger.Info("Restarting Vault service")
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"restart", "vault"},
		Capture: true,
	})
	if err != nil {
		logger.Error("Failed to restart Vault", zap.String("output", output))
		logger.Info("Attempting to restore backup", zap.String("backup", backupPath))
		if restoreErr := os.WriteFile(config.ConfigPath, currentConfig, 0640); restoreErr != nil {
			logger.Error("Failed to restore backup", zap.Error(restoreErr))
		}
		return nil, fmt.Errorf("failed to restart Vault service: %w\nOutput: %s", err, output)
	}

	logger.Info("Vault service restarted successfully")

	// EVALUATE - Verify service is running
	logger.Info("Verifying Vault service status")

	statusOutput, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"status", "vault", "--no-pager"},
		Capture: true,
	})

	if err != nil {
		logger.Warn("Failed to check service status (non-critical)", zap.Error(err))
	} else if strings.Contains(statusOutput, "Active: active") {
		logger.Info("Vault service is active")
	} else {
		logger.Warn("Vault service may not be fully started", zap.String("status", statusOutput))
	}

	// Build result
	result := &PortMigrationResult{
		Success:        true,
		PortType:       portType,
		PortLabel:      portLabel,
		OldAPIPort:     currentPorts.APIPort,
		OldClusterPort: currentPorts.ClusterPort,
		BackupPath:     backupPath,
		Changed:        true,
	}

	if portType == "api" {
		result.NewAPIPort = actualToPort
		result.NewClusterPort = currentPorts.ClusterPort
	} else {
		result.NewAPIPort = currentPorts.APIPort
		result.NewClusterPort = actualToPort
	}

	return result, nil
}
