// pkg/consul/update.go

package consul

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// PortMigration represents a port migration configuration
type PortMigration struct {
	FromPort int
	ToPort   int
	PortType string // "http", "dns", or "unknown"
}

// CurrentPortConfig represents the current Consul port configuration
type CurrentPortConfig struct {
	HTTPPort int
	DNSPort  int
}

// UpdatePortsConfig holds configuration for port update operation
type UpdatePortsConfig struct {
	PortMigration *PortMigration
	DryRun        bool
	ConfigPath    string
}

// UpdateConsulPorts performs the complete port update workflow
// ASSESS → INTERVENE → EVALUATE pattern
func UpdateConsulPorts(rc *eos_io.RuntimeContext, config *UpdatePortsConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting Consul port update",
		zap.Int("from_port", config.PortMigration.FromPort),
		zap.Int("to_port", config.PortMigration.ToPort),
		zap.String("port_type", config.PortMigration.PortType),
		zap.Bool("dry_run", config.DryRun))

	// ASSESS: Read and validate current configuration
	currentConfig, configContent, err := assessCurrentConfiguration(rc, config.ConfigPath)
	if err != nil {
		return err
	}

	logger.Info("Current Consul configuration",
		zap.Int("current_http_port", currentConfig.HTTPPort),
		zap.Int("current_dns_port", currentConfig.DNSPort))

	// Validate the port migration request
	actualFromPort, actualToPort, portLabel, portType, err := validatePortMigration(
		config.PortMigration, currentConfig)
	if err != nil {
		return err
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

	// Dry run mode - show what would be done
	if config.DryRun {
		displayDryRunChanges(logger, portLabel, actualFromPort, actualToPort, config.ConfigPath)
		return nil
	}

	// INTERVENE: Apply the changes
	if err := applyPortChanges(rc, config.ConfigPath, configContent, portType,
		actualFromPort, actualToPort, currentConfig); err != nil {
		return err
	}

	// EVALUATE: Verify the changes
	if err := verifyPortChanges(rc, portLabel, actualFromPort, actualToPort,
		portType, currentConfig.DNSPort, currentConfig.HTTPPort); err != nil {
		return err
	}

	logger.Info("Consul port configuration updated successfully")
	return nil
}

// ParsePortMigrationSyntax parses port migration syntax: "FROM -> TO"
func ParsePortMigrationSyntax(portsArg string) (*PortMigration, error) {
	// Split on "->"
	parts := strings.Split(portsArg, "->")
	if len(parts) != 2 {
		return nil, eos_err.NewUserError(
			"Invalid port syntax: must be 'FROM -> TO'\n\n" +
				"Examples:\n" +
				"  8161 -> default\n" +
				"  8161 -> 8500\n" +
				"  8389 -> 8600")
	}

	fromStr := strings.TrimSpace(parts[0])
	toStr := strings.TrimSpace(parts[1])

	// Parse FROM port
	var fromPort int
	if fromStr == "default" {
		return nil, eos_err.NewUserError(
			"FROM port cannot be 'default' - specify the current port number.\n\n" +
				"Example:\n" +
				"  eos update consul --ports 8161 -> default")
	}
	var err error
	fromPort, err = strconv.Atoi(fromStr)
	if err != nil {
		return nil, eos_err.NewUserError(
			"Invalid FROM port '%s': must be a number\n\n"+
				"Example:\n"+
				"  eos update consul --ports 8161 -> default", fromStr)
	}

	// Parse TO port
	var toPort int
	if toStr == "default" {
		// Determine which default based on FROM port
		switch fromPort {
		case 8161, 8500:
			toPort = shared.PortConsul // HTTP default
		case 8389, 8600:
			toPort = shared.PortConsulDNS // DNS default
		default:
			// Default to HTTP port if ambiguous
			toPort = shared.PortConsul
		}
	} else {
		toPort, err = strconv.Atoi(toStr)
		if err != nil {
			return nil, eos_err.NewUserError(
				"Invalid TO port '%s': must be a number or 'default'\n\n"+
					"Example:\n"+
					"  eos update consul --ports 8161 -> 8500", toStr)
		}
	}

	// Validate port ranges
	if fromPort < 1024 || fromPort > 65535 {
		return nil, eos_err.NewUserError(
			"Invalid FROM port %d: must be between 1024 and 65535", fromPort)
	}
	if toPort < 1024 || toPort > 65535 {
		return nil, eos_err.NewUserError(
			"Invalid TO port %d: must be between 1024 and 65535", toPort)
	}

	// Determine port type based on common HTTP/DNS ports
	portType := "unknown"
	if fromPort == 8161 || fromPort == 8500 || toPort == 8161 || toPort == 8500 {
		portType = "http"
	} else if fromPort == 8389 || fromPort == 8600 || toPort == 8389 || toPort == 8600 {
		portType = "dns"
	}

	return &PortMigration{
		FromPort: fromPort,
		ToPort:   toPort,
		PortType: portType,
	}, nil
}

// assessCurrentConfiguration reads and parses the current Consul config
func assessCurrentConfiguration(rc *eos_io.RuntimeContext, configPath string) (*CurrentPortConfig, []byte, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Reading current Consul configuration", zap.String("path", configPath))

	currentConfig, err := os.ReadFile(configPath)
	if err != nil {
		return nil, nil, eos_err.NewUserError(
			"Failed to read Consul configuration: %v\n\n"+
				"Make sure Consul is installed:\n"+
				"  sudo eos create consul", err)
	}

	config := &CurrentPortConfig{
		HTTPPort: ExtractHTTPPort(string(currentConfig)),
		DNSPort:  ExtractDNSPort(string(currentConfig)),
	}

	return config, currentConfig, nil
}

// validatePortMigration validates the requested port migration against current config
func validatePortMigration(migration *PortMigration, currentConfig *CurrentPortConfig) (int, int, string, string, error) {
	// Determine which port type we're migrating
	var actualFromPort, actualToPort int
	var portLabel string
	portType := migration.PortType

	if portType == "http" || migration.FromPort == currentConfig.HTTPPort {
		actualFromPort = currentConfig.HTTPPort
		actualToPort = migration.ToPort
		portLabel = "HTTP"
		portType = "http"
	} else if portType == "dns" || migration.FromPort == currentConfig.DNSPort {
		actualFromPort = currentConfig.DNSPort
		actualToPort = migration.ToPort
		portLabel = "DNS"
		portType = "dns"
	} else {
		return 0, 0, "", "", eos_err.NewUserError(
			"Port %d not found in current configuration.\n\n"+
				"Current ports:\n"+
				"  HTTP: %d\n"+
				"  DNS: %d\n\n"+
				"Use one of these as FROM port.", migration.FromPort, currentConfig.HTTPPort, currentConfig.DNSPort)
	}

	// Verify FROM port matches
	if migration.FromPort != actualFromPort {
		return 0, 0, "", "", eos_err.NewUserError(
			"Port mismatch: You specified FROM port %d, but current %s port is %d.\n\n"+
				"Current configuration:\n"+
				"  HTTP: %d\n"+
				"  DNS: %d\n\n"+
				"Use: eos update consul --ports %d -> %d",
			migration.FromPort, portLabel, actualFromPort,
			currentConfig.HTTPPort, currentConfig.DNSPort,
			actualFromPort, migration.ToPort)
	}

	return actualFromPort, actualToPort, portLabel, portType, nil
}

// displayDryRunChanges shows what would be changed in dry-run mode
func displayDryRunChanges(logger otelzap.LoggerWithCtx, portLabel string, fromPort, toPort int, configPath string) {
	logger.Info("================================================================================")
	logger.Info("DRY RUN MODE - No changes will be made")
	logger.Info("================================================================================")
	logger.Info("")
	logger.Info("Would perform the following changes:")
	logger.Info(fmt.Sprintf("  • %s Port: %d → %d", portLabel, fromPort, toPort))
	logger.Info("")
	logger.Info("Would update: " + configPath)
	logger.Info("Would restart: consul.service")
	logger.Info("")
	logger.Info("Run without --dry-run to apply changes")
}

// applyPortChanges backs up config, updates it, and restarts the service
func applyPortChanges(rc *eos_io.RuntimeContext, configPath string, currentConfig []byte,
	portType string, _ int, actualToPort int, _ *CurrentPortConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	// INTERVENE: Backup current configuration
	logger.Info("Backing up current configuration")
	backupPath := fmt.Sprintf("%s.backup.%d", configPath, os.Getpid())
	if err := os.WriteFile(backupPath, currentConfig, ConsulConfigPerm); err != nil {
		logger.Warn("Failed to create backup", zap.Error(err))
	} else {
		logger.Info("Configuration backed up", zap.String("backup", backupPath))
	}

	// Update configuration
	logger.Info("Updating Consul configuration")
	var newConfig string
	if portType == "http" {
		newConfig = UpdatePortsInConfig(string(currentConfig), actualToPort, 0)
	} else {
		newConfig = UpdatePortsInConfig(string(currentConfig), 0, actualToPort)
	}

	if err := os.WriteFile(configPath, []byte(newConfig), ConsulConfigPerm); err != nil {
		return fmt.Errorf("failed to write updated configuration: %w", err)
	}

	logger.Info("Configuration updated", zap.String("config", configPath))

	// Restart Consul service
	logger.Info("Restarting Consul service")
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"restart", "consul"},
		Capture: true,
		Logger:  logger.ZapLogger(),
	})
	if err != nil {
		logger.Error("Failed to restart Consul", zap.String("output", output))
		logger.Info("Attempting to restore backup", zap.String("backup", backupPath))
		_ = os.WriteFile(configPath, currentConfig, ConsulConfigPerm)
		return fmt.Errorf("failed to restart Consul service: %w\nOutput: %s\n"+
			"Remediation:\n"+
			"  1. Check configuration syntax: consul validate %s\n"+
			"  2. Check service status: systemctl status consul\n"+
			"  3. Restore backup: sudo cp %s %s",
			err, output, configPath, backupPath, configPath)
	}

	logger.Info("Consul service restarted successfully")
	return nil
}

// verifyPortChanges verifies the new configuration is working
func verifyPortChanges(rc *eos_io.RuntimeContext, portLabel string, actualFromPort, actualToPort int,
	portType string, currentDNSPort, currentHTTPPort int) error {
	logger := otelzap.Ctx(rc.Ctx)

	// EVALUATE: Verify new port is accessible
	logger.Info("Verifying Consul is accessible on new port")

	// Wait a moment for Consul to start
	logger.Info("Waiting for Consul to initialize...")
	_, _ = execute.Run(rc.Ctx, execute.Options{
		Command: "sleep",
		Args:    []string{"3"},
		Capture: true,
		Logger:  logger.ZapLogger(),
	})

	// Check status
	statusOutput, _ := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"status", "consul", "--no-pager"},
		Capture: true,
		Logger:  logger.ZapLogger(),
	})

	if strings.Contains(statusOutput, "Active: active") {
		logger.Info("Consul service is active")
	} else {
		logger.Warn("Consul service may not be fully started", zap.String("status", statusOutput))
	}

	// Display success summary
	displaySuccessSummary(logger, portLabel, actualFromPort, actualToPort, portType, currentDNSPort, currentHTTPPort)

	return nil
}

// displaySuccessSummary shows the final success message
func displaySuccessSummary(logger otelzap.LoggerWithCtx, portLabel string, actualFromPort, actualToPort int,
	portType string, currentDNSPort, currentHTTPPort int) {
	logger.Info("================================================================================")
	logger.Info("Consul port configuration updated successfully")
	logger.Info("================================================================================")
	logger.Info(fmt.Sprintf("  %s Port: %d → %d", portLabel, actualFromPort, actualToPort))
	logger.Info("")
	logger.Info("Consul is now listening on:")
	if portType == "http" {
		logger.Info(fmt.Sprintf("  • HTTP: http://%s:%d", shared.GetInternalHostname(), actualToPort))
		logger.Info(fmt.Sprintf("  • DNS: %s:%d", shared.GetInternalHostname(), currentDNSPort))
		logger.Info("")
		logger.Info("Update CONSUL_HTTP_ADDR environment variable:")
		logger.Info(fmt.Sprintf("  export CONSUL_HTTP_ADDR=http://%s:%d", shared.GetInternalHostname(), actualToPort))
		logger.Info("")
		logger.Info("Or add to your shell profile:")
		logger.Info(fmt.Sprintf("  echo 'export CONSUL_HTTP_ADDR=http://%s:%d' >> ~/.bashrc", shared.GetInternalHostname(), actualToPort))
	} else {
		logger.Info(fmt.Sprintf("  • HTTP: http://%s:%d", shared.GetInternalHostname(), currentHTTPPort))
		logger.Info(fmt.Sprintf("  • DNS: %s:%d", shared.GetInternalHostname(), actualToPort))
	}
	logger.Info("")
	logger.Info("Code Monkey Cybersecurity - 'Cybersecurity. With humans.'")
	logger.Info("================================================================================")
}

// ExtractHTTPPort extracts the HTTP port from Consul configuration
// Looks for: ports { http = 8500 }
func ExtractHTTPPort(config string) int {
	pattern := `ports\s*\{[^}]*http\s*=\s*(\d+)`
	re := regexp.MustCompile(pattern)
	matches := re.FindStringSubmatch(config)

	if len(matches) > 1 {
		port, _ := strconv.Atoi(matches[1])
		return port
	}

	return 8500 // Default HTTP port
}

// ExtractDNSPort extracts the DNS port from Consul configuration
// Looks for: ports { dns = 8600 }
func ExtractDNSPort(config string) int {
	pattern := `ports\s*\{[^}]*dns\s*=\s*(\d+)`
	re := regexp.MustCompile(pattern)
	matches := re.FindStringSubmatch(config)

	if len(matches) > 1 {
		port, _ := strconv.Atoi(matches[1])
		return port
	}

	return 8600 // Default DNS port
}

// UpdatePortsInConfig updates port numbers in Consul configuration
// Pass 0 for ports that should not be changed
func UpdatePortsInConfig(config string, httpPort, dnsPort int) string {
	result := config

	// Update HTTP port in ports block
	if httpPort > 0 {
		httpPattern := regexp.MustCompile(`(ports\s*\{[^}]*http\s*=\s*)\d+`)
		result = httpPattern.ReplaceAllString(result, fmt.Sprintf(`${1}%d`, httpPort))
	}

	// Update DNS port in ports block
	if dnsPort > 0 {
		dnsPattern := regexp.MustCompile(`(ports\s*\{[^}]*dns\s*=\s*)\d+`)
		result = dnsPattern.ReplaceAllString(result, fmt.Sprintf(`${1}%d`, dnsPort))
	}

	return result
}
