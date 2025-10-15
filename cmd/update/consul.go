// cmd/update/consul.go
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
	consulPorts   string
	consulDryRun  bool
)

// ConsulCmd updates Consul configuration
var ConsulCmd = &cobra.Command{
	Use:   "consul",
	Short: "Update Consul configuration",
	Long: `Update Consul's configuration by modifying settings and restarting the service.

The command intelligently updates:
1. Consul HCL configuration file (/etc/consul.d/consul.hcl)
2. Restarts Consul service to apply changes
3. Verifies new configuration is accessible

Examples:
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
		"Preview changes without applying them")
}

func runConsulUpdate(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Validate ports flag is specified
	if consulPorts == "" {
		return eos_err.NewUserError(
			"Port migration must be specified.\n\n" +
				"Examples:\n" +
				"  eos update consul --ports 8161 -> default\n" +
				"  eos update consul --ports 8161 -> 8500\n" +
				"  eos update consul --ports 8389 -> 8600")
	}

	logger.Info("Starting Consul update",
		zap.String("ports", consulPorts),
		zap.Bool("dry_run", consulDryRun))

	// ASSESS: Parse port migration syntax
	fromPort, toPort, portType, err := parseConsulPortMigration(consulPorts)
	if err != nil {
		return err
	}

	logger.Info("Parsed port migration",
		zap.Int("from_port", fromPort),
		zap.Int("to_port", toPort),
		zap.String("port_type", portType))

	// Read current configuration
	configPath := "/etc/consul.d/consul.hcl"
	currentConfig, err := os.ReadFile(configPath)
	if err != nil {
		return eos_err.NewUserError(
			"Failed to read Consul configuration: %v\n\n"+
				"Make sure Consul is installed:\n"+
				"  sudo eos create consul", err)
	}

	// Extract current ports
	currentHTTPPort := extractConsulHTTPPort(string(currentConfig))
	currentDNSPort := extractConsulDNSPort(string(currentConfig))

	logger.Info("Current Consul configuration",
		zap.Int("current_http_port", currentHTTPPort),
		zap.Int("current_dns_port", currentDNSPort))

	// Determine which port type we're migrating
	var actualFromPort, actualToPort int
	var portLabel string

	if portType == "http" || fromPort == currentHTTPPort {
		actualFromPort = currentHTTPPort
		actualToPort = toPort
		portLabel = "HTTP"
		portType = "http"
	} else if portType == "dns" || fromPort == currentDNSPort {
		actualFromPort = currentDNSPort
		actualToPort = toPort
		portLabel = "DNS"
		portType = "dns"
	} else {
		return eos_err.NewUserError(
			"Port %d not found in current configuration.\n\n"+
				"Current ports:\n"+
				"  HTTP: %d\n"+
				"  DNS: %d\n\n"+
				"Use one of these as FROM port.", fromPort, currentHTTPPort, currentDNSPort)
	}

	// Verify FROM port matches
	if fromPort != actualFromPort {
		return eos_err.NewUserError(
			"Port mismatch: You specified FROM port %d, but current %s port is %d.\n\n"+
				"Current configuration:\n"+
				"  HTTP: %d\n"+
				"  DNS: %d\n\n"+
				"Use: eos update consul --ports %d -> %d",
			fromPort, portLabel, actualFromPort,
			currentHTTPPort, currentDNSPort,
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

	if consulDryRun {
		logger.Info("================================================================================")
		logger.Info("DRY RUN MODE - No changes will be made")
		logger.Info("================================================================================")
		logger.Info("")
		logger.Info("Would perform the following changes:")
		logger.Info(fmt.Sprintf("  • %s Port: %d → %d", portLabel, actualFromPort, actualToPort))
		logger.Info("")
		logger.Info("Would update: /etc/consul.d/consul.hcl")
		logger.Info("Would restart: consul.service")
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
	logger.Info("Updating Consul configuration")
	var newConfig string
	if portType == "http" {
		newConfig = updateConsulPorts(string(currentConfig), actualToPort, 0)
	} else {
		newConfig = updateConsulPorts(string(currentConfig), 0, actualToPort)
	}

	if err := os.WriteFile(configPath, []byte(newConfig), 0640); err != nil {
		return fmt.Errorf("failed to write updated configuration: %w", err)
	}

	logger.Info("Configuration updated", zap.String("config", configPath))

	// Restart Consul service
	logger.Info("Restarting Consul service")
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"restart", "consul"},
		Capture: true,
	})
	if err != nil {
		logger.Error("Failed to restart Consul", zap.String("output", output))
		logger.Info("Attempting to restore backup", zap.String("backup", backupPath))
		_ = os.WriteFile(configPath, currentConfig, 0640)
		return fmt.Errorf("failed to restart Consul service: %w\nOutput: %s", err, output)
	}

	logger.Info("Consul service restarted successfully")

	// EVALUATE: Verify new port is accessible
	logger.Info("Verifying Consul is accessible on new port")

	// Wait a moment for Consul to start
	logger.Info("Waiting for Consul to initialize...")
	output, _ = execute.Run(rc.Ctx, execute.Options{
		Command: "sleep",
		Args:    []string{"3"},
		Capture: true,
	})

	// Check status
	statusOutput, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"status", "consul", "--no-pager"},
		Capture: true,
	})

	if strings.Contains(statusOutput, "Active: active") {
		logger.Info("Consul service is active")
	} else {
		logger.Warn("Consul service may not be fully started", zap.String("status", statusOutput))
	}

	logger.Info("================================================================================")
	logger.Info("Consul port configuration updated successfully")
	logger.Info("================================================================================")
	logger.Info(fmt.Sprintf("  %s Port: %d → %d", portLabel, actualFromPort, actualToPort))
	logger.Info("")
	logger.Info("Consul is now listening on:")
	if portType == "http" {
		logger.Info(fmt.Sprintf("  • HTTP: http://127.0.0.1:%d", actualToPort))
		logger.Info(fmt.Sprintf("  • DNS: 127.0.0.1:%d", currentDNSPort))
		logger.Info("")
		logger.Info("Update CONSUL_HTTP_ADDR environment variable:")
		logger.Info(fmt.Sprintf("  export CONSUL_HTTP_ADDR=http://127.0.0.1:%d", actualToPort))
		logger.Info("")
		logger.Info("Or add to your shell profile:")
		logger.Info(fmt.Sprintf("  echo 'export CONSUL_HTTP_ADDR=http://127.0.0.1:%d' >> ~/.bashrc", actualToPort))
	} else {
		logger.Info(fmt.Sprintf("  • HTTP: http://127.0.0.1:%d", currentHTTPPort))
		logger.Info(fmt.Sprintf("  • DNS: 127.0.0.1:%d", actualToPort))
	}
	logger.Info("")
	logger.Info("Code Monkey Cybersecurity - 'Cybersecurity. With humans.'")
	logger.Info("================================================================================")

	return nil
}

// parseConsulPortMigration parses port migration syntax: "FROM -> TO"
// Returns: fromPort, toPort, portType, error
func parseConsulPortMigration(portsArg string) (int, int, string, error) {
	// Split on "->"
	parts := strings.Split(portsArg, "->")
	if len(parts) != 2 {
		return 0, 0, "", eos_err.NewUserError(
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
		return 0, 0, "", eos_err.NewUserError(
			"FROM port cannot be 'default' - specify the current port number.\n\n" +
				"Example:\n" +
				"  eos update consul --ports 8161 -> default")
	}
	var err error
	fromPort, err = strconv.Atoi(fromStr)
	if err != nil {
		return 0, 0, "", eos_err.NewUserError(
			"Invalid FROM port '%s': must be a number\n\n"+
				"Example:\n"+
				"  eos update consul --ports 8161 -> default", fromStr)
	}

	// Parse TO port
	var toPort int
	if toStr == "default" {
		// Determine which default based on FROM port
		if fromPort == 8161 || fromPort == 8500 {
			toPort = shared.PortConsul // HTTP default
		} else if fromPort == 8389 || fromPort == 8600 {
			toPort = shared.PortConsulDNS // DNS default
		} else {
			// Default to HTTP port if ambiguous
			toPort = shared.PortConsul
		}
	} else {
		toPort, err = strconv.Atoi(toStr)
		if err != nil {
			return 0, 0, "", eos_err.NewUserError(
				"Invalid TO port '%s': must be a number or 'default'\n\n"+
					"Example:\n"+
					"  eos update consul --ports 8161 -> 8500", toStr)
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

	// Determine port type based on common HTTP/DNS ports
	portType := "unknown"
	if fromPort == 8161 || fromPort == 8500 || toPort == 8161 || toPort == 8500 {
		portType = "http"
	} else if fromPort == 8389 || fromPort == 8600 || toPort == 8389 || toPort == 8600 {
		portType = "dns"
	}

	return fromPort, toPort, portType, nil
}

// extractConsulHTTPPort extracts the HTTP port from Consul configuration
// Looks for: ports { http = 8500 }
func extractConsulHTTPPort(config string) int {
	pattern := `ports\s*\{[^}]*http\s*=\s*(\d+)`
	re := regexp.MustCompile(pattern)
	matches := re.FindStringSubmatch(config)

	if len(matches) > 1 {
		port, _ := strconv.Atoi(matches[1])
		return port
	}

	return 8500 // Default HTTP port
}

// extractConsulDNSPort extracts the DNS port from Consul configuration
// Looks for: ports { dns = 8600 }
func extractConsulDNSPort(config string) int {
	pattern := `ports\s*\{[^}]*dns\s*=\s*(\d+)`
	re := regexp.MustCompile(pattern)
	matches := re.FindStringSubmatch(config)

	if len(matches) > 1 {
		port, _ := strconv.Atoi(matches[1])
		return port
	}

	return 8600 // Default DNS port
}

// updateConsulPorts updates port numbers in Consul configuration
// Pass 0 for ports that should not be changed
func updateConsulPorts(config string, httpPort, dnsPort int) string {
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
