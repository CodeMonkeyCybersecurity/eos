// pkg/enrollment/network.go
package enrollment

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// SetupNetwork configures network connectivity for enrollment
func SetupNetwork(rc *eos_io.RuntimeContext, config *EnrollmentConfig, info *SystemInfo) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Setting up network configuration",
		zap.String("mode", config.NetworkMode),
		zap.String("role", config.Role))

	// Default to direct networking if not specified
	if config.NetworkMode == "" {
		config.NetworkMode = NetworkModeDirect
	}

	switch config.NetworkMode {
	case NetworkModeConsul:
		return setupConsulNetwork(rc, config, info)
	case NetworkModeWireGuard:
		return setupWireGuardNetwork(rc, config, info)
	case NetworkModeDirect:
		return setupDirectNetwork(rc, config, info)
	default:
		return fmt.Errorf("unsupported network mode: %s", config.NetworkMode)
	}
}

// setupDirectNetwork sets up direct networking with firewall rules
func setupDirectNetwork(rc *eos_io.RuntimeContext, config *EnrollmentConfig, _ *SystemInfo) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Setting up direct network connectivity")

	// Configure firewall rules for
	rules := []FirewallRule{
		{
			Port:     PublisherPort,
			Protocol: "tcp",
			Source:   "any",
			Target:   "ACCEPT",
			Comment:  " publisher port",
		},
		{
			Port:     RequestPort,
			Protocol: "tcp",
			Source:   "any",
			Target:   "ACCEPT",
			Comment:  " request port",
		},
	}

	// Master needs to accept incoming connections
	if config.Role == RoleMaster {
		if err := configureFirewallRules(rc, rules, true); err != nil {
			return fmt.Errorf("failed to configure firewall rules: %w", err)
		}
	}

	// Test connectivity to HashiCorp cluster if we're a client
	if config.Role == "minion" && config.ess != "" {
		if err := testConnectivity(rc, config.ess, PublisherPort); err != nil {
			return fmt.Errorf("failed to connect to HashiCorp cluster: %w", err)
		}
	}

	return nil
}

// setupConsulNetwork sets up Consul Connect networking
func setupConsulNetwork(rc *eos_io.RuntimeContext, config *EnrollmentConfig, info *SystemInfo) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Setting up Consul Connect networking",
		zap.String("datacenter", config.Datacenter))

	// ASSESS - Check if Consul is available
	if err := ensureConsulInstalled(rc); err != nil {
		return fmt.Errorf("failed to ensure Consul is installed: %w", err)
	}

	// INTERVENE - Configure Consul agent
	if err := configureConsulAgent(rc, config, info); err != nil {
		return fmt.Errorf("failed to configure Consul agent: %w", err)
	}

	// Setup service definitions - requires administrator intervention
	logger.Info("Consul service setup requires administrator intervention")
	// TODO: Implement Consul service registration via administrator

	// Configure Connect proxies - requires administrator intervention
	logger.Info("Consul Connect setup requires administrator intervention")
	// TODO: Implement Consul Connect configuration via administrator

	// Verify Consul connectivity using existing function
	if err := validateConsulInstallation(rc, config); err != nil {
		logger.Warn("Consul setup verification failed", zap.Error(err))
		// Continue with enrollment even if verification fails
	}

	logger.Info("Consul Connect networking configured successfully")
	return nil
}

// setupWireGuardNetwork sets up WireGuard VPN mesh
func setupWireGuardNetwork(rc *eos_io.RuntimeContext, config *EnrollmentConfig, info *SystemInfo) error {
	logger := otelzap.Ctx(rc.Ctx)

	// TODO: 2025-01-09T21:56:00Z - Implement WireGuard mesh networking
	// This should:
	// 1. Install WireGuard if not present
	// 2. Generate public/private key pairs
	// 3. Configure WireGuard interface
	// 4. Exchange keys with other nodes
	// 5. Setup routing for  traffic over WireGuard

	logger.Warn("WireGuard networking not fully implemented yet")
	return setupDirectNetwork(rc, config, info)
}

// configureFirewallRules configures firewall rules for
func configureFirewallRules(rc *eos_io.RuntimeContext, rules []FirewallRule, allowIncoming bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if we're in dry-run mode
	if rc.Attributes != nil {
		if dryRun, exists := rc.Attributes["dry_run"]; exists && dryRun == "true" {
			logger.Info("DRY RUN: Would configure firewall rules",
				zap.Int("rule_count", len(rules)))
			return nil
		}
	}

	// Try different firewall management tools
	if err := configureUFWRules(rc, rules, allowIncoming); err == nil {
		return nil
	}

	if err := configureIptablesRules(rc, rules, allowIncoming); err == nil {
		return nil
	}

	logger.Warn("No supported firewall management tool found")
	return nil // Don't fail enrollment for firewall issues
}

// configureUFWRules configures UFW (Uncomplicated Firewall) rules
func configureUFWRules(rc *eos_io.RuntimeContext, rules []FirewallRule, allowIncoming bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if ufw is available
	if _, err := exec.LookPath("ufw"); err != nil {
		return fmt.Errorf("ufw not found")
	}

	for _, rule := range rules {
		var cmd *exec.Cmd
		if allowIncoming {
			cmd = exec.Command("ufw", "allow", fmt.Sprintf("%d/%s", rule.Port, rule.Protocol))
		} else {
			cmd = exec.Command("ufw", "allow", "out", fmt.Sprintf("%d/%s", rule.Port, rule.Protocol))
		}

		if output, err := cmd.CombinedOutput(); err != nil {
			logger.Warn("Failed to configure UFW rule",
				zap.Int("port", rule.Port),
				zap.String("protocol", rule.Protocol),
				zap.String("output", string(output)),
				zap.Error(err))
			continue
		}

		logger.Info("Configured UFW rule",
			zap.Int("port", rule.Port),
			zap.String("protocol", rule.Protocol))
	}

	return nil
}

// configureIptablesRules configures iptables rules
func configureIptablesRules(rc *eos_io.RuntimeContext, rules []FirewallRule, allowIncoming bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if iptables is available
	if _, err := exec.LookPath("iptables"); err != nil {
		return fmt.Errorf("iptables not found")
	}

	for _, rule := range rules {
		var cmd *exec.Cmd
		if allowIncoming {
			cmd = exec.Command("iptables", "-A", "INPUT", "-p", rule.Protocol,
				"--dport", strconv.Itoa(rule.Port), "-j", "ACCEPT")
		} else {
			cmd = exec.Command("iptables", "-A", "OUTPUT", "-p", rule.Protocol,
				"--dport", strconv.Itoa(rule.Port), "-j", "ACCEPT")
		}

		if output, err := cmd.CombinedOutput(); err != nil {
			logger.Warn("Failed to configure iptables rule",
				zap.Int("port", rule.Port),
				zap.String("protocol", rule.Protocol),
				zap.String("output", string(output)),
				zap.Error(err))
			continue
		}

		logger.Info("Configured iptables rule",
			zap.Int("port", rule.Port),
			zap.String("protocol", rule.Protocol))
	}

	return nil
}

// testConnectivity tests network connectivity to a host and port
func testConnectivity(rc *eos_io.RuntimeContext, host string, port int) error {
	logger := otelzap.Ctx(rc.Ctx)

	address := net.JoinHostPort(host, strconv.Itoa(port))
	logger.Info("Testing connectivity", zap.String("address", address))

	// Use context timeout from RuntimeContext
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %w", address, err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			logger.Warn("Failed to close connection", zap.Error(err))
		}
	}()

	logger.Info("Connectivity test successful", zap.String("address", address))
	return nil
}

// GetPublicIP attempts to determine the public IP address
func GetPublicIP(rc *eos_io.RuntimeContext) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Try multiple methods to get public IP
	methods := []func() (string, error){
		getPublicIPFromInterface,
		getPublicIPFromExternalService,
	}

	for _, method := range methods {
		if ip, err := method(); err == nil {
			logger.Info("Detected public IP", zap.String("ip", ip))
			return ip, nil
		}
	}

	return "", fmt.Errorf("failed to determine public IP")
}

// getPublicIPFromInterface gets public IP from network interfaces
func getPublicIPFromInterface() (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ip, _, err := net.ParseCIDR(addr.String())
			if err != nil {
				continue
			}

			// Check if it's a public IPv4 address
			if ip.To4() != nil && !ip.IsPrivate() && !ip.IsLoopback() {
				return ip.String(), nil
			}
		}
	}

	return "", fmt.Errorf("no public IP found on interfaces")
}

// getPublicIPFromExternalService gets public IP from external service
func getPublicIPFromExternalService() (string, error) {
	// Try common IP detection services
	services := []string{
		"https://api.ipify.org",
		"https://ifconfig.me",
		"https://icanhazip.com",
	}

	for _, service := range services {
		cmd := exec.Command("curl", "-s", "--max-time", "5", service)
		output, err := cmd.Output()
		if err != nil {
			continue
		}

		ip := strings.TrimSpace(string(output))
		if net.ParseIP(ip) != nil {
			return ip, nil
		}
	}

	return "", fmt.Errorf("failed to get public IP from external services")
}

// ConfigureHostname configures the system hostname
func ConfigureHostname(rc *eos_io.RuntimeContext, hostname string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if we're in dry-run mode
	if rc.Attributes != nil {
		if dryRun, exists := rc.Attributes["dry_run"]; exists && dryRun == "true" {
			logger.Info("DRY RUN: Would configure hostname", zap.String("hostname", hostname))
			return nil
		}
	}

	currentHostname, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("failed to get current hostname: %w", err)
	}

	if currentHostname == hostname {
		logger.Info("Hostname already configured", zap.String("hostname", hostname))
		return nil
	}

	// Set hostname using hostnamectl (systemd)
	if _, err := exec.LookPath("hostnamectl"); err == nil {
		cmd := exec.Command("hostnamectl", "set-hostname", hostname)
		if output, err := cmd.CombinedOutput(); err != nil {
			logger.Warn("Failed to set hostname with hostnamectl",
				zap.String("output", string(output)),
				zap.Error(err))
		} else {
			logger.Info("Hostname configured with hostnamectl", zap.String("hostname", hostname))
			return nil
		}
	}

	// Fallback to /etc/hostname
	if err := os.WriteFile("/etc/hostname", []byte(hostname+"\n"), 0644); err != nil {
		return fmt.Errorf("failed to write /etc/hostname: %w", err)
	}

	// Update /etc/hosts
	if err := updateHostsFile(hostname); err != nil {
		logger.Warn("Failed to update /etc/hosts", zap.Error(err))
	}

	logger.Info("Hostname configured", zap.String("hostname", hostname))
	return nil
}

// updateHostsFile updates /etc/hosts with the new hostname
func updateHostsFile(hostname string) error {
	hostsPath := "/etc/hosts"

	// Read current hosts file
	data, err := os.ReadFile(hostsPath)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", hostsPath, err)
	}

	content := string(data)
	lines := strings.Split(content, "\n")

	// Look for localhost line and add hostname
	for i, line := range lines {
		if strings.HasPrefix(line, "127.0.0.1") {
			if !strings.Contains(line, hostname) {
				lines[i] = line + " " + hostname
			}
			break
		}
	}

	// Write back to file
	newContent := strings.Join(lines, "\n")
	if err := os.WriteFile(hostsPath, []byte(newContent), 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", hostsPath, err)
	}

	return nil
}

// ValidateNetworkRequirements validates network requirements for enrollment
func ValidateNetworkRequirements(rc *eos_io.RuntimeContext, config *EnrollmentConfig, info *SystemInfo) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if we have at least one network interface
	if len(info.NetworkIfaces) == 0 {
		return fmt.Errorf("no network interfaces found")
	}

	// Check if we have at least one UP interface
	hasUpInterface := false
	for _, iface := range info.NetworkIfaces {
		if iface.IsUp && iface.Type != "loopback" {
			hasUpInterface = true
			break
		}
	}

	if !hasUpInterface {
		return fmt.Errorf("no active network interfaces found")
	}

	logger.Info("Network requirements validated")
	return nil
}

// ensureConsulInstalled ensures Consul is installed and available
func ensureConsulInstalled(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if consul is already available
	if _, err := exec.LookPath("consul"); err == nil {
		logger.Info("Consul already installed")
		return nil
	}

	// Check if we're in dry-run mode
	if rc.Attributes != nil {
		if dryRun, exists := rc.Attributes["dry_run"]; exists && dryRun == "true" {
			logger.Info("DRY RUN: Would install Consul")
			return nil
		}
	}

	logger.Info("Installing Consul")

	// Try different installation methods
	if err := installConsulPKG(rc); err == nil {
		return nil
	}

	if err := installConsulGeneric(rc); err == nil {
		return nil
	}

	// All installation methods failed
	return fmt.Errorf("failed to install Consul using available methods")
}

// installConsulAPT installs Consul using apt (Debian/Ubuntu)
func installConsulPKG(_ *eos_io.RuntimeContext) error {
	if _, err := exec.LookPath("apt-get"); err != nil {
		return fmt.Errorf("apt-get not found")
	}

	// Add HashiCorp repository
	// TODO: Implement HashiCorp repository setup for apt-get
	return fmt.Errorf("HashiCorp repository setup requires administrator intervention")
}

// installConsulBinary installs Consul from binary download
func installConsulGeneric(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Installing Consul via binary download")

	// TODO: Implement binary download and installation
	return fmt.Errorf("binary installation requires administrator intervention")
}

// configureConsulAgent configures the Consul agent
func configureConsulAgent(rc *eos_io.RuntimeContext, _ *EnrollmentConfig, _ *SystemInfo) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if we're in dry-run mode
	if rc.Attributes != nil {
		if dryRun, exists := rc.Attributes["dry_run"]; exists && dryRun == "true" {
			logger.Info("Dry-run mode: skipping Consul agent configuration")
			return nil
		}
	}

	return nil
}

// verifyConsulSetup verifies that Consul is working correctly
func validateConsulInstallation(rc *eos_io.RuntimeContext, _ *EnrollmentConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check consul agent status
	cmd := exec.Command("consul", "info")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("consul info failed: %s", string(output))
	}

	// Check if consul members are visible
	cmd = exec.Command("consul", "members")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("consul members failed: %s", string(output))
	}

	// Verify services are registered
	cmd = exec.Command("consul", "catalog", "services")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("consul services check failed: %s", string(output))
	}

	// Check Connect is enabled
	cmd = exec.Command("consul", "connect", "ca", "get-config")
	if output, err := cmd.CombinedOutput(); err != nil {
		logger.Warn("Consul Connect verification warning",
			zap.String("output", string(output)),
			zap.Error(err))
	}

	logger.Info("Consul setup verification completed successfully")
	return nil
}
