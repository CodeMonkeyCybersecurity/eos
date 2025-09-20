// pkg/enrollment/network.go
package enrollment

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
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
func setupDirectNetwork(rc *eos_io.RuntimeContext, config *EnrollmentConfig, info *SystemInfo) error {
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

	// Setup service definitions
	if err := setupConsulServices(rc, config); err != nil {
		return fmt.Errorf("failed to setup Consul services: %w", err)
	}

	// Configure Connect proxies
	if err := setupConsulConnect(rc, config); err != nil {
		return fmt.Errorf("failed to setup Consul Connect: %w", err)
	}

	// EVALUATE - Verify Consul connectivity
	if err := verifyConsulSetup(rc, config); err != nil {
		return fmt.Errorf("Consul setup verification failed: %w", err)
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

	address := fmt.Sprintf("%s:%d", host, port)
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
	if err := installConsulAPT(rc); err == nil {
		return nil
	}

	if err := installConsulYUM(rc); err == nil {
		return nil
	}

	if err := installConsulBinary(rc); err == nil {
		return nil
	}

	return fmt.Errorf("failed to install Consul using available methods")
}

// installConsulAPT installs Consul using apt (Debian/Ubuntu)
func installConsulAPT(rc *eos_io.RuntimeContext) error {
	if _, err := exec.LookPath("apt-get"); err != nil {
		return fmt.Errorf("apt-get not found")
	}

	// Add HashiCorp repository
	commands := [][]string{
		{"curl", "-fsSL", "https://apt.releases.hashicorp.com/gpg", "|", "apt-key", "add", "-"},
		{"apt-add-repository", "deb [arch=amd64] https://apt.releases.hashicorp.com $(lsb_release -cs) main"},
		{"apt-get", "update"},
		{"apt-get", "install", "-y", "consul"},
	}

	for _, cmdArgs := range commands {
		cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("command failed: %s, output: %s", strings.Join(cmdArgs, " "), string(output))
		}
	}

	return nil
}

// installConsulYUM installs Consul using yum/dnf (RHEL/CentOS/Fedora)
func installConsulYUM(rc *eos_io.RuntimeContext) error {
	packageManager := "dnf"
	if _, err := exec.LookPath("dnf"); err != nil {
		packageManager = "yum"
		if _, err := exec.LookPath("yum"); err != nil {
			return fmt.Errorf("neither dnf nor yum found")
		}
	}

	// Add HashiCorp repository
	repoContent := `[hashicorp]
name=Hashicorp Stable - $basearch
baseurl=https://rpm.releases.hashicorp.com/RHEL/$releasever/$basearch/stable
enabled=1
gpgcheck=1
gpgkey=https://rpm.releases.hashicorp.com/gpg
`

	if err := os.WriteFile("/etc/yum.repos.d/hashicorp.repo", []byte(repoContent), 0644); err != nil {
		return fmt.Errorf("failed to write repo file: %w", err)
	}

	// Install consul
	cmd := exec.Command(packageManager, "install", "-y", "consul")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s install failed: %s", packageManager, string(output))
	}

	return nil
}

// installConsulBinary installs Consul from binary download
func installConsulBinary(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Download and install latest Consul binary
	arch := "amd64"
	// Detect architecture from runtime
	if runtime.GOARCH == "arm64" {
		arch = "arm64"
	}

	downloadURL := fmt.Sprintf("https://releases.hashicorp.com/consul/1.17.0/consul_1.17.0_linux_%s.zip", arch)

	// Download consul
	cmd := exec.Command("curl", "-L", "-o", "/tmp/consul.zip", downloadURL)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to download consul: %s", string(output))
	}

	// Extract and install
	commands := [][]string{
		{"unzip", "/tmp/consul.zip", "-d", "/tmp/"},
		{"mv", "/tmp/consul", "/usr/local/bin/consul"},
		{"chmod", "+x", "/usr/local/bin/consul"},
		{"rm", "/tmp/consul.zip"},
	}

	for _, cmdArgs := range commands {
		cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
		if output, err := cmd.CombinedOutput(); err != nil {
			logger.Warn("Command failed",
				zap.String("command", strings.Join(cmdArgs, " ")),
				zap.String("output", string(output)))
		}
	}

	// Verify installation
	if _, err := exec.LookPath("consul"); err != nil {
		return fmt.Errorf("consul installation failed")
	}

	return nil
}

// configureConsulAgent configures the Consul agent
func configureConsulAgent(rc *eos_io.RuntimeContext, config *EnrollmentConfig, info *SystemInfo) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if we're in dry-run mode
	if rc.Attributes != nil {
		if dryRun, exists := rc.Attributes["dry_run"]; exists && dryRun == "true" {
			logger.Info("DRY RUN: Would configure Consul agent")
			return nil
		}
	}

	// Create consul directories
	dirs := []string{"/etc/consul", "/var/lib/consul", "/var/log/consul"}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	// Generate Consul configuration
	consulConfig := generateConsulConfig(config, info)

	// Write consul configuration
	configPath := "/etc/consul/consul.json"
	if err := os.WriteFile(configPath, []byte(consulConfig), 0640); err != nil {
		return fmt.Errorf("failed to write consul config: %w", err)
	}

	// Create systemd service file
	if err := createConsulSystemdService(rc); err != nil {
		logger.Warn("Failed to create systemd service", zap.Error(err))
	}

	// Start and enable consul service
	if err := startConsulService(rc); err != nil {
		return fmt.Errorf("failed to start consul service: %w", err)
	}

	logger.Info("Consul agent configured successfully")
	return nil
}

// generateConsulConfig generates Consul agent configuration
func generateConsulConfig(config *EnrollmentConfig, info *SystemInfo) string {
	datacenter := config.Datacenter
	if datacenter == "" {
		datacenter = "dc1"
	}

	// Determine if this should be a server node
	isServer := config.Role == RoleMaster

	consulConfig := fmt.Sprintf(`{
  "datacenter": "%s",
  "data_dir": "/var/lib/consul",
  "log_level": "INFO",
  "node_name": "%s",
  "server": %t,
  "bootstrap_expect": %d,
  "retry_join": [
    "provider=consul addr=%s"
  ],
  "client_addr": "0.0.0.0",
  "bind_addr": "{{ GetInterfaceIP \"eth0\" }}",
  "connect": {
    "enabled": true
  },
  "ports": {
    "grpc": 8502
  },
  "ui_config": {
    "enabled": true
  },
  "acl": {
    "enabled": true,
    "default_policy": "allow",
    "down_policy": "extend-cache"
  },
  "encrypt": "ENCRYPT_KEY_PLACEHOLDER"
}`, datacenter, info.Hostname, isServer, getBootstrapExpect(isServer), getess(config))

	return consulConfig
}

// getBootstrapExpected returns expected number of servers for bootstrapping
func getBootstrapExpect(isServer bool) int {
	if isServer {
		return 1 // For simplicity, assume single server bootstrap
	}
	return 0
}

// getess gets the master address for joining
func getess(config *EnrollmentConfig) string {
	if config.ess != "" {
		return config.ess
	}
	return "127.0.0.1"
}

// createConsulSystemdService creates systemd service for Consul
func createConsulSystemdService(rc *eos_io.RuntimeContext) error {
	serviceContent := `[Unit]
Description=Consul
Documentation=https://www.consul.io/
Requires=network-online.target
After=network-online.target
ConditionFileNotEmpty=/etc/consul/consul.json

[Service]
Type=notify
User=consul
Group=consul
ExecStart=/usr/local/bin/consul agent -config-dir=/etc/consul
ExecReload=/bin/kill -HUP $MAINPID
KillMode=process
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
`

	if err := os.WriteFile("/etc/systemd/system/consul.service", []byte(serviceContent), 0644); err != nil {
		return fmt.Errorf("failed to write systemd service: %w", err)
	}

	// Reload systemd
	cmd := exec.Command("systemctl", "daemon-reload")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to reload systemd: %s", string(output))
	}

	return nil
}

// startConsulService starts the Consul service
func startConsulService(rc *eos_io.RuntimeContext) error {
	commands := [][]string{
		{"systemctl", "enable", "consul"},
		{"systemctl", "start", "consul"},
	}

	for _, cmdArgs := range commands {
		cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("command %s failed: %s", strings.Join(cmdArgs, " "), string(output))
		}
	}

	return nil
}

// setupConsulServices configures service definitions for
func setupConsulServices(rc *eos_io.RuntimeContext, config *EnrollmentConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if we're in dry-run mode
	if rc.Attributes != nil {
		if dryRun, exists := rc.Attributes["dry_run"]; exists && dryRun == "true" {
			logger.Info("DRY RUN: Would setup Consul services")
			return nil
		}
	}

	// Configure service definitions based on role
	var services []string

	for _, service := range services {
		if err := registerConsulService(rc, service, config); err != nil {
			return fmt.Errorf("failed to register service %s: %w", service, err)
		}
	}

	logger.Info("Consul services configured", zap.Strings("services", services))
	return nil
}

// registerConsulService registers a service with Consul
func registerConsulService(rc *eos_io.RuntimeContext, serviceName string, config *EnrollmentConfig) error {
	port := RequestPort
	if serviceName == "-master" {
		port = PublisherPort
	}

	serviceDefinition := fmt.Sprintf(`{
  "service": {
    "name": "%s",
    "port": %d,
    "tags": [
      "",
      "eos-managed",
      "%s"
    ],
    "check": {
      "tcp": "localhost:%d",
      "interval": "10s"
    },
    "connect": {
      "sidecar_service": {}
    }
  }
}`, serviceName, port, config.Datacenter, port)

	servicePath := fmt.Sprintf("/etc/consul/%s.json", serviceName)
	if err := os.WriteFile(servicePath, []byte(serviceDefinition), 0644); err != nil {
		return fmt.Errorf("failed to write service definition: %w", err)
	}

	// Reload consul to pick up new service
	cmd := exec.Command("consul", "reload")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to reload consul: %s", string(output))
	}

	return nil
}

// setupConsulConnect configures Consul Connect proxies
func setupConsulConnect(rc *eos_io.RuntimeContext, config *EnrollmentConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if we're in dry-run mode
	if rc.Attributes != nil {
		if dryRun, exists := rc.Attributes["dry_run"]; exists && dryRun == "true" {
			logger.Info("DRY RUN: Would setup Consul Connect proxies")
			return nil
		}
	}

	// Configure Connect proxy for  services
	var services []string
	if config.Role == RoleMaster {
		services = []string{"-master"}
	}

	for _, service := range services {
		if err := startConnectProxy(rc, service); err != nil {
			logger.Warn("Failed to start Connect proxy",
				zap.String("service", service),
				zap.Error(err))
		}
	}

	logger.Info("Consul Connect proxies configured")
	return nil
}

// startConnectProxy starts a Connect proxy for a service
func startConnectProxy(rc *eos_io.RuntimeContext, serviceName string) error {
	// Create systemd service for the proxy
	proxyServiceContent := fmt.Sprintf(`[Unit]
Description=Consul Connect Proxy for %s
Requires=consul.service
After=consul.service

[Service]
Type=exec
ExecStart=/usr/local/bin/consul connect proxy -sidecar-for %s
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
`, serviceName, serviceName)

	servicePath := fmt.Sprintf("/etc/systemd/system/consul-connect-%s.service", serviceName)
	if err := os.WriteFile(servicePath, []byte(proxyServiceContent), 0644); err != nil {
		return fmt.Errorf("failed to write proxy service: %w", err)
	}

	// Enable and start the proxy service
	commands := [][]string{
		{"systemctl", "daemon-reload"},
		{"systemctl", "enable", fmt.Sprintf("consul-connect-%s", serviceName)},
		{"systemctl", "start", fmt.Sprintf("consul-connect-%s", serviceName)},
	}

	for _, cmdArgs := range commands {
		cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("command %s failed: %s", strings.Join(cmdArgs, " "), string(output))
		}
	}

	return nil
}

// verifyConsulSetup verifies that Consul is working correctly
func verifyConsulSetup(rc *eos_io.RuntimeContext, config *EnrollmentConfig) error {
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
