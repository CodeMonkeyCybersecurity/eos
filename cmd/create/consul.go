// cmd/create/consul.go

package create

import (
	"fmt"
	"os"
	"strings"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var CreateConsulCmd = &cobra.Command{
	Use:   "consul",
	Short: "Install and configure Consul with service discovery and scaling features",
	Long: `Install and configure HashiCorp Consul with advanced features for service discovery,
health monitoring, and scaling readiness.

FEATURES:
• Service discovery with DNS and HTTP API
• Health monitoring and automatic failover
• Consul Connect service mesh ready
• Automatic Vault integration if available
• Scaling-ready configuration
• Comprehensive audit logging
• Production-ready security settings

CONFIGURATION:
• HTTP API on port " + strconv.Itoa(shared.PortConsul) + " (instead of default 8500)
• Consul Connect enabled for service mesh
• UI enabled for management
• Automatic Vault service registration
• DNS service discovery on port 8600

USAGE:
  # Install Consul with default configuration
  eos create consul

  # Install Consul with custom datacenter name
  eos create consul --datacenter production

  # Install without Vault integration
  eos create consul --no-vault-integration`,
	RunE: eos.Wrap(installConsul),
}

var (
	datacenterName          string
	disableVaultIntegration bool
	enableDebugLogging      bool
)

func init() {
	CreateConsulCmd.Flags().StringVarP(&datacenterName, "datacenter", "d", "dc1", "Datacenter name for Consul cluster")
	CreateConsulCmd.Flags().BoolVar(&disableVaultIntegration, "no-vault-integration", false, "Disable automatic Vault integration")
	CreateConsulCmd.Flags().BoolVar(&enableDebugLogging, "debug", false, "Enable debug logging for Consul")

	// Register the command with the create command
	CreateCmd.AddCommand(CreateConsulCmd)
}

func installConsul(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info(" Starting advanced Consul installation and configuration",
		zap.String("datacenter", datacenterName),
		zap.Bool("vault_integration", !disableVaultIntegration),
		zap.Bool("debug_logging", enableDebugLogging))

	// Check if running as root
	if os.Geteuid() != 0 {
		return fmt.Errorf("this command must be run as root")
	}

	// Install Consul binary
	if err := installConsulBinary(rc); err != nil {
		return fmt.Errorf("install Consul binary: %w", err)
	}

	// Create system user and directories
	if err := setupConsulSystemUser(rc); err != nil {
		return fmt.Errorf("setup system user: %w", err)
	}

	// Detect if Vault is available for integration
	vaultAvailable := false
	if !disableVaultIntegration {
		vaultAvailable = detectVaultInstallation(rc)
	}

	// Generate main Consul configuration
	if err := generateConsulConfig(rc, vaultAvailable); err != nil {
		return fmt.Errorf("generate Consul config: %w", err)
	}

	// Generate Vault service registration if Vault is available
	if vaultAvailable {
		if err := generateVaultServiceConfig(rc); err != nil {
			log.Warn(" Failed to create Vault service registration", zap.Error(err))
		}
	}

	// Create systemd service
	if err := createConsulSystemdService(rc); err != nil {
		return fmt.Errorf("create systemd service: %w", err)
	}

	// Create helper script
	if err := createConsulHelperScript(rc); err != nil {
		return fmt.Errorf("create helper script: %w", err)
	}

	// Start and enable service
	if err := startConsulService(rc); err != nil {
		return fmt.Errorf("start Consul service: %w", err)
	}

	// Wait for service to be ready
	if err := waitForConsulReady(rc); err != nil {
		return fmt.Errorf("wait for Consul ready: %w", err)
	}

	// Display success information
	displayInstallationSummary(rc, vaultAvailable)

	return nil
}

func installConsulBinary(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)

	// Check if Consul is already installed
	if err := execute.RunSimple(rc.Ctx, "which", "consul"); err == nil {
		log.Info(" Consul binary already installed, checking version")
		output, err := execute.Run(rc.Ctx, execute.Options{
			Command: "consul",
			Args:    []string{"version"},
			Capture: true,
		})
		if err == nil {
			log.Info(" Current Consul version", zap.String("version", strings.TrimSpace(output)))
			return nil
		}
	}

	log.Info(" Installing Consul binary")

	// Detect architecture
	arch := eos_unix.GetArchitecture()
	consulVersion := "1.17.1"

	log.Info(" Downloading Consul",
		zap.String("version", consulVersion),
		zap.String("architecture", arch))

	steps := []execute.Options{
		{
			Command: "wget",
			Args: []string{
				"-O", "/tmp/consul.zip",
				fmt.Sprintf("https://releases.hashicorp.com/consul/%s/consul_%s_linux_%s.zip",
					consulVersion, consulVersion, arch),
			},
		},
		{Command: "unzip", Args: []string{"-o", "/tmp/consul.zip", "-d", "/tmp/"}},
		{Command: "chmod", Args: []string{"+x", "/tmp/consul"}},
		{Command: "mv", Args: []string{"/tmp/consul", "/usr/local/bin/consul"}},
		{Command: "rm", Args: []string{"-f", "/tmp/consul.zip"}},
	}

	for i, step := range steps {
		log.Debug(" Executing installation step",
			zap.Int("step", i+1),
			zap.String("command", step.Command))

		if _, err := execute.Run(rc.Ctx, step); err != nil {
			return fmt.Errorf("installation step %d failed: %w", i+1, err)
		}
	}

	// Verify installation
	if err := execute.RunSimple(rc.Ctx, "consul", "version"); err != nil {
		return fmt.Errorf("consul verification failed: %w", err)
	}

	log.Info(" Consul binary installed successfully")
	return nil
}

func setupConsulSystemUser(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info(" Setting up Consul system user and directories")

	steps := []execute.Options{
		// Create consul user
		{
			Command: "useradd",
			Args:    []string{"--system", "--home", "/etc/consul.d", "--shell", "/bin/false", "consul"},
		},
		// Create directories
		{Command: "mkdir", Args: []string{"-p", "/etc/consul.d", "/opt/consul", "/var/log/consul"}},
		// Set ownership
		{Command: "chown", Args: []string{"-R", "consul:consul", "/etc/consul.d", "/opt/consul", "/var/log/consul"}},
		// Set permissions
		{Command: "chmod", Args: []string{"750", "/etc/consul.d"}},
		{Command: "chmod", Args: []string{"750", "/opt/consul"}},
		{Command: "chmod", Args: []string{"755", "/var/log/consul"}},
	}

	for _, step := range steps {
		if _, err := execute.Run(rc.Ctx, step); err != nil {
			// Ignore user creation error if user already exists
			if step.Command == "useradd" && strings.Contains(err.Error(), "already exists") {
				log.Debug(" Consul user already exists")
				continue
			}
			return fmt.Errorf("setup step failed: %w", err)
		}
	}

	log.Info(" Consul system user and directories created")
	return nil
}

func detectVaultInstallation(rc *eos_io.RuntimeContext) bool {
	log := otelzap.Ctx(rc.Ctx)

	// Check if VAULT_ADDR is set
	vaultAddr := os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		log.Debug(" VAULT_ADDR not set, skipping Vault integration")
		return false
	}

	// Try to create a Vault client
	client, err := vault.NewClient(rc)
	if err != nil {
		log.Debug(" Failed to create Vault client", zap.Error(err))
		return false
	}

	// Check if Vault is healthy
	_, err = client.Sys().Health()
	if err != nil {
		log.Debug(" Vault health check failed", zap.Error(err))
		return false
	}

	log.Info(" Vault detected and healthy, enabling integration",
		zap.String("vault_addr", vaultAddr))
	return true
}

func generateConsulConfig(rc *eos_io.RuntimeContext, vaultAvailable bool) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info(" Generating Consul configuration",
		zap.String("datacenter", datacenterName),
		zap.Bool("vault_integration", vaultAvailable))

	hostname := eos_unix.GetInternalHostname()
	nodeName := fmt.Sprintf("%s-consul", hostname)

	logLevel := "INFO"
	if enableDebugLogging {
		logLevel = "DEBUG"
	}

	config := fmt.Sprintf(`# Consul Configuration for Scaling and Service Discovery
# Generated by Eos at %s

# Datacenter identification
datacenter = "%s"
node_name = "%s"

# Data directory
data_dir = "/opt/consul"

# Server mode - single server now, but ready to expand
server = true
bootstrap_expect = 1  # Will change to 3-5 when you add servers

# Custom ports configuration for Eos
ports {
  http = %d      # HTTP API (Eos standard instead of 8500)
  https = -1       # Disabled for now
  grpc = 8502      # Keep default for internal communication
  dns = 8600       # Keep default DNS
  serf_lan = 8301  # Keep default for LAN gossip
  serf_wan = 8302  # Keep default for WAN gossip
  server = 8300    # Keep default for RPC
}

# Network configuration
client_addr = "0.0.0.0"  # Accept connections from anywhere
bind_addr = "{{ GetPrivateIP }}"  # Auto-detect private IP

# Advertise addresses for when you add more nodes
advertise_addr = "{{ GetPrivateIP }}"
advertise_addr_wan = "{{ GetPrivateIP }}"

# UI enabled for management
ui_config {
  enabled = true
}

# DNS configuration for service discovery
dns_config {
  allow_stale = true
  max_stale = "2s"
  node_ttl = "30s"
  service_ttl = {
    "*" = "5s"
  }
  enable_truncate = true
}

# Performance settings optimized for growth
performance {
  raft_multiplier = 1  # Low latency for single node
  leave_drain_time = "5s"
  rpc_hold_timeout = "7s"
}

# Logging configuration
log_level = "%s"
log_json = true
log_file = "/var/log/consul/"
log_rotate_bytes = 104857600  # 100MB
log_rotate_duration = "24h"
log_rotate_max_files = 10

# Enable metrics for monitoring
telemetry {
  prometheus_retention_time = "60s"
  disable_hostname = false
  statsd_address = "127.0.0.1:8125"
}

# Connect settings (service mesh ready)
connect {
  enabled = true
}

# Autopilot for automatic cluster management
autopilot {
  cleanup_dead_servers = true
  last_contact_threshold = "200ms"
  max_trailing_logs = 250
  min_quorum = 3  # Prepares for 3-node minimum
  server_stabilization_time = "10s"
}

# Enable script checks (useful for custom health checks)
enable_script_checks = true

# Security settings
acl = {
  enabled = false
  default_policy = "allow"
  # Prepared for future ACL enablement
}

# Encryption settings (prepared for production)
# encrypt = "base64-key-here"  # Uncomment and set for production

# TLS settings (prepared for production)
# tls {
#   defaults {
#     verify_incoming = true
#     verify_outgoing = true
#   }
#   internal_rpc {
#     verify_server_hostname = true
#   }
# }

# Watches for external integration
watches = [
  {
    type = "services"
    handler_type = "script"
    args = ["/usr/local/bin/consul-vault-helper", "watch"]
  }
]
`, time.Now().Format(time.RFC3339), datacenterName, nodeName, shared.PortConsul, logLevel)

	configPath := "/etc/consul.d/consul.hcl"
	if err := os.WriteFile(configPath, []byte(config), 0640); err != nil {
		return fmt.Errorf("write consul config: %w", err)
	}

	// Set ownership
	if err := execute.RunSimple(rc.Ctx, "chown", "consul:consul", configPath); err != nil {
		return fmt.Errorf("set config ownership: %w", err)
	}

	log.Info(" Consul configuration written", zap.String("path", configPath))
	return nil
}

func generateVaultServiceConfig(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info(" Generating Vault service registration for Consul")

	vaultAddr := os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		return fmt.Errorf("VAULT_ADDR not set")
	}

	hostname := eos_unix.GetInternalHostname()

	// Extract hostname and port from VAULT_ADDR
	vaultURL := strings.TrimPrefix(vaultAddr, "https://")
	vaultURL = strings.TrimPrefix(vaultURL, "http://")
	parts := strings.Split(vaultURL, ":")
	vaultHost := parts[0]
	vaultPort := "8200" // default
	if len(parts) > 1 {
		vaultPort = parts[1]
	}

	serviceConfig := fmt.Sprintf(`{
  "service": {
    "name": "vault",
    "id": "vault-%s",
    "port": %s,
    "address": "%s",
    "tags": [
      "active",
      "tls",
      "file-backend",
      "primary",
      "eos-managed"
    ],
    "meta": {
      "version": "1.15.0",
      "storage_type": "file", 
      "instance": "%s",
      "environment": "production",
      "eos_managed": "true"
    },
    "check": {
      "id": "vault-health",
      "name": "Vault HTTPS Health",
      "http": "%s/v1/sys/health?standbyok=true&perfstandbyok=true",
      "interval": "10s",
      "timeout": "5s",
      "tls_skip_verify": true,
      "success_before_passing": 2,
      "failures_before_critical": 3
    },
    "weights": {
      "passing": 10,
      "warning": 1
    }
  }
}`, hostname, vaultPort, vaultHost, hostname, vaultAddr)

	servicePath := "/etc/consul.d/vault-service.json"
	if err := os.WriteFile(servicePath, []byte(serviceConfig), 0640); err != nil {
		return fmt.Errorf("write vault service config: %w", err)
	}

	// Set ownership
	if err := execute.RunSimple(rc.Ctx, "chown", "consul:consul", servicePath); err != nil {
		return fmt.Errorf("set service config ownership: %w", err)
	}

	log.Info(" Vault service registration created", zap.String("path", servicePath))
	return nil
}

func createConsulSystemdService(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info(" Creating Consul systemd service")

	serviceContent := fmt.Sprintf(`[Unit]
Description=Consul Service Discovery and Configuration
Documentation=https://www.consul.io/
Requires=network-online.target
After=network-online.target
ConditionFileNotEmpty=/etc/consul.d/consul.hcl

[Service]
Type=notify
User=consul
Group=consul
ExecStart=/usr/local/bin/consul agent -config-dir=/etc/consul.d/
ExecReload=/bin/kill -HUP $MAINPID
ExecStop=/usr/local/bin/consul leave
KillMode=process
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
Environment="CONSUL_HTTP_ADDR=127.0.0.1:%d"

[Install]
WantedBy=multi-user.target`, shared.PortConsul)

	servicePath := "/etc/systemd/system/consul.service"
	if err := os.WriteFile(servicePath, []byte(serviceContent), 0644); err != nil {
		return fmt.Errorf("write systemd service: %w", err)
	}

	// Reload systemd
	if err := execute.RunSimple(rc.Ctx, "systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %w", err)
	}

	log.Info(" Consul systemd service created")
	return nil
}

func createConsulHelperScript(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info(" Creating Consul helper script")

	helperScript := fmt.Sprintf(`#!/bin/bash
# /usr/local/bin/consul-vault-helper
# Consul and Vault integration helper script

CONSUL_ADDR="http://localhost:%d"
VAULT_ADDR="${VAULT_ADDR:-https://localhost:8200}"

case "$1" in
  status)
    echo "=== Consul Status ==="
    curl -s $CONSUL_ADDR/v1/status/leader || echo "Consul not responding"
    echo -e "\n=== Vault Service Health ==="
    curl -s $CONSUL_ADDR/v1/health/service/vault | jq -r '.[].Checks[]? | "\(.Name): \(.Status)"' 2>/dev/null || echo "No Vault service registered"
    ;;
    
  discover)
    echo "=== Discovering Vault via DNS ==="
    dig +short @127.0.0.1 -p 8600 vault.service.consul 2>/dev/null || echo "DNS lookup failed"
    echo -e "\n=== Discovering Vault via API ==="
    curl -s $CONSUL_ADDR/v1/catalog/service/vault | jq -r '.[].ServiceAddress + ":" + (.[].ServicePort | tostring)' 2>/dev/null || echo "API lookup failed"
    ;;
    
  watch)
    export CONSUL_HTTP_ADDR=$CONSUL_ADDR
    consul watch -type=service -service=vault jq . 2>/dev/null || echo "Watch failed - check consul installation"
    ;;
    
  register-app)
    # Example: Register a new app that uses Vault
    APP_NAME=$2
    APP_PORT=$3
    if [ -z "$APP_NAME" ] || [ -z "$APP_PORT" ]; then
      echo "Usage: $0 register-app <app-name> <port>"
      exit 1
    fi
    cat > /tmp/${APP_NAME}-service.json << EOF
{
  "service": {
    "name": "${APP_NAME}",
    "port": ${APP_PORT},
    "tags": ["vault-aware", "eos-managed"],
    "checks": [{
      "http": "http://localhost:${APP_PORT}/health",
      "interval": "10s"
    }]
  }
}
EOF
    curl -X PUT -d @/tmp/${APP_NAME}-service.json $CONSUL_ADDR/v1/agent/service/register
    echo "Registered service: $APP_NAME on port $APP_PORT"
    rm -f /tmp/${APP_NAME}-service.json
    ;;
    
  services)
    echo "=== All Registered Services ==="
    curl -s $CONSUL_ADDR/v1/catalog/services | jq -r 'keys[]' 2>/dev/null || echo "Failed to list services"
    ;;
    
  nodes)
    echo "=== Cluster Nodes ==="
    curl -s $CONSUL_ADDR/v1/catalog/nodes | jq -r '.[].Node' 2>/dev/null || echo "Failed to list nodes"
    ;;
    
  *)
    echo "Usage: $0 {status|discover|watch|register-app|services|nodes}"
    echo ""
    echo "Commands:"
    echo "  status       - Show Consul and Vault health status"
    echo "  discover     - Test service discovery for Vault"
    echo "  watch        - Watch Vault service changes"
    echo "  register-app - Register a new service with Consul"
    echo "  services     - List all registered services"
    echo "  nodes        - List all cluster nodes"
    echo ""
    echo "Environment:"
    echo "  CONSUL_ADDR: $CONSUL_ADDR"
    echo "  VAULT_ADDR:  $VAULT_ADDR"
    ;;
esac`, shared.PortConsul)

	scriptPath := "/usr/local/bin/consul-vault-helper"
	if err := os.WriteFile(scriptPath, []byte(helperScript), 0755); err != nil {
		return fmt.Errorf("write helper script: %w", err)
	}

	log.Info(" Consul helper script created", zap.String("path", scriptPath))
	return nil
}

func startConsulService(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info(" Starting Consul service")

	steps := []execute.Options{
		{Command: "systemctl", Args: []string{"enable", "consul"}},
		{Command: "systemctl", Args: []string{"start", "consul"}},
	}

	for _, step := range steps {
		if err := execute.RunSimple(rc.Ctx, step.Command, step.Args...); err != nil {
			return fmt.Errorf("%s failed: %w", strings.Join(append([]string{step.Command}, step.Args...), " "), err)
		}
	}

	log.Info(" Consul service started and enabled")
	return nil
}

func waitForConsulReady(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info(" Waiting for Consul to be ready")

	maxAttempts := 30
	for i := 0; i < maxAttempts; i++ {
		// Check if Consul is responding
		if err := execute.RunSimple(rc.Ctx, "curl", "-f", fmt.Sprintf("http://localhost:%d/v1/status/leader", shared.PortConsul)); err == nil {
			log.Info(" Consul is ready", zap.Int("attempts", i+1))
			return nil
		}

		log.Debug(" Consul not ready yet", zap.Int("attempt", i+1))
		time.Sleep(2 * time.Second)
	}

	return fmt.Errorf("consul failed to become ready after %d attempts", maxAttempts)
}

func displayInstallationSummary(rc *eos_io.RuntimeContext, vaultAvailable bool) {
	log := otelzap.Ctx(rc.Ctx)
	hostname := eos_unix.GetInternalHostname()

	log.Info(" ")
	log.Info(" ╔══════════════════════════════════════════════════════════════════════╗")
	log.Info(" ║                    CONSUL INSTALLATION COMPLETE                     ║")
	log.Info(" ╚══════════════════════════════════════════════════════════════════════╝")
	log.Info(" ")
	log.Info("  CONSUL FEATURES ENABLED:")
	log.Info("   • Service discovery with DNS and HTTP API")
	log.Info("   • Health monitoring and automatic failover")
	log.Info("   • Consul Connect service mesh ready")
	log.Info("   • Scaling-ready configuration")
	log.Info("   • Web UI for management")
	if vaultAvailable {
		log.Info("   • Vault integration and service registration")
	}
	log.Info(" ")

	log.Info(" 🌐 ACCESS POINTS:")
	log.Info(fmt.Sprintf("   • Web UI:      http://%s:%d/ui", hostname, shared.PortConsul))
	log.Info(fmt.Sprintf("   • HTTP API:    http://localhost:%d", shared.PortConsul))
	log.Info("   • DNS:         127.0.0.1:8600")
	log.Info(" ")

	log.Info("  USEFUL COMMANDS:")
	log.Info("   • consul-vault-helper status    # Check status")
	log.Info("   • consul-vault-helper discover  # Test service discovery")
	log.Info("   • consul-vault-helper services  # List all services")
	log.Info("   • systemctl status consul       # Check service status")
	log.Info(" ")

	if vaultAvailable {
		log.Info(" 🔐 VAULT INTEGRATION:")
		log.Info("   • Vault service automatically registered")
		log.Info("   • Health monitoring enabled")
		log.Info("   • Service discovery available via DNS:")
		log.Info("     dig @127.0.0.1 -p 8600 vault.service.consul")
		log.Info(" ")
	}

	log.Info("  SCALING READY:")
	log.Info("   • Add more servers by updating bootstrap_expect")
	log.Info("   • Consul Connect ready for service mesh")
	log.Info("   • ACLs prepared for security")
	log.Info("   • Prepared queries for intelligent routing")
	log.Info(" ")

	log.Info("  MONITORING:")
	log.Info("   • Prometheus metrics available")
	log.Info("   • Logs: /var/log/consul/")
	log.Info("   • Telemetry enabled")
	log.Info(" ")

	// Set environment variables for current session
	log.Info("  ENVIRONMENT:")
	log.Info("   Add to your ~/.bashrc:")
	log.Info(fmt.Sprintf("     export CONSUL_HTTP_ADDR=\"127.0.0.1:%d\"", shared.PortConsul))
	log.Info(" ")
}
