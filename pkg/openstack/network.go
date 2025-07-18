package openstack

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/telemetry"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// configureNetworking sets up OpenStack networking based on the chosen type
func configureNetworking(rc *eos_io.RuntimeContext, config *Config) error {
	ctx, span := telemetry.Start(rc.Ctx, "openstack.configureNetworking")
	defer span.End()
	rc = &eos_io.RuntimeContext{Ctx: ctx}

	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Configuring OpenStack networking",
		zap.String("type", string(config.NetworkType)))

	// Install networking packages
	if err := installNetworkingPackages(rc, config); err != nil {
		return fmt.Errorf("failed to install networking packages: %w", err)
	}

	// Configure based on network type
	switch config.NetworkType {
	case NetworkProvider:
		return configureProviderNetwork(rc, config)
	case NetworkTenant:
		return configureTenantNetwork(rc, config)
	case NetworkHybrid:
		return configureHybridNetwork(rc, config)
	default:
		return fmt.Errorf("unknown network type: %s", config.NetworkType)
	}
}

// installNetworkingPackages installs required networking packages
func installNetworkingPackages(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	packages := []string{
		"openvswitch-switch",
		"bridge-utils",
		"neutron-openvswitch-agent",
		"neutron-l3-agent",
		"neutron-dhcp-agent",
		"neutron-metadata-agent",
		"conntrack",
		"dnsmasq",
		"dnsmasq-utils",
		"ipset",
	}

	// Add ML2 plugin
	packages = append(packages, "neutron-plugin-ml2")

	// Add LinuxBridge agent if not using OVS exclusively
	if config.NetworkType == NetworkHybrid {
		packages = append(packages, "neutron-linuxbridge-agent")
	}

	logger.Info("Installing networking packages", zap.Int("count", len(packages)))
	installCmd := exec.CommandContext(rc.Ctx, "apt-get", "install", "-y")
	installCmd.Args = append(installCmd.Args, packages...)
	installCmd.Stdout = os.Stdout
	installCmd.Stderr = os.Stderr

	if err := installCmd.Run(); err != nil {
		return fmt.Errorf("failed to install networking packages: %w", err)
	}

	// Start and enable OVS
	if err := startOpenVSwitch(rc); err != nil {
		return fmt.Errorf("failed to start Open vSwitch: %w", err)
	}

	return nil
}

// configureProviderNetwork sets up provider (external) networks
func configureProviderNetwork(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Configuring provider network",
		zap.String("interface", config.ProviderInterface),
		zap.String("physnet", config.ProviderPhysnet))

	// Create OVS bridge for provider network
	bridgeName := fmt.Sprintf("br-%s", config.ProviderPhysnet)
	if err := createOVSBridge(rc, bridgeName); err != nil {
		return fmt.Errorf("failed to create OVS bridge: %w", err)
	}

	// Add physical interface to bridge
	if config.ProviderInterface != "" {
		if err := addInterfaceToOVSBridge(rc, bridgeName, config.ProviderInterface); err != nil {
			return fmt.Errorf("failed to add interface to bridge: %w", err)
		}

		// Migrate IP configuration from physical interface to bridge
		if err := migrateIPConfiguration(rc, config.ProviderInterface, bridgeName); err != nil {
			logger.Warn("Failed to migrate IP configuration",
				zap.String("from", config.ProviderInterface),
				zap.String("to", bridgeName),
				zap.Error(err))
		}
	}

	// Configure Neutron OVS agent
	if err := configureNeutronOVSAgent(rc, config); err != nil {
		return fmt.Errorf("failed to configure Neutron OVS agent: %w", err)
	}

	// Configure L3 agent for provider networks
	if err := configureL3Agent(rc, config, false); err != nil {
		return fmt.Errorf("failed to configure L3 agent: %w", err)
	}

	// Configure DHCP agent
	if err := configureDHCPAgent(rc, config); err != nil {
		return fmt.Errorf("failed to configure DHCP agent: %w", err)
	}

	// Configure metadata agent
	if err := configureMetadataAgent(rc, config); err != nil {
		return fmt.Errorf("failed to configure metadata agent: %w", err)
	}

	logger.Info("Provider network configuration completed")
	return nil
}

// configureTenantNetwork sets up tenant (overlay) networks
func configureTenantNetwork(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Configuring tenant network")

	// Create integration bridge
	if err := createOVSBridge(rc, "br-int"); err != nil {
		return fmt.Errorf("failed to create integration bridge: %w", err)
	}

	// Create tunnel bridge for VXLAN
	if err := createOVSBridge(rc, "br-tun"); err != nil {
		return fmt.Errorf("failed to create tunnel bridge: %w", err)
	}

	// Configure Neutron OVS agent for tunneling
	if err := configureNeutronOVSAgent(rc, config); err != nil {
		return fmt.Errorf("failed to configure Neutron OVS agent: %w", err)
	}

	// Configure L3 agent with NAT
	if err := configureL3Agent(rc, config, true); err != nil {
		return fmt.Errorf("failed to configure L3 agent: %w", err)
	}

	// Configure DHCP agent
	if err := configureDHCPAgent(rc, config); err != nil {
		return fmt.Errorf("failed to configure DHCP agent: %w", err)
	}

	// Configure metadata agent
	if err := configureMetadataAgent(rc, config); err != nil {
		return fmt.Errorf("failed to configure metadata agent: %w", err)
	}

	logger.Info("Tenant network configuration completed")
	return nil
}

// configureHybridNetwork sets up both provider and tenant networks
func configureHybridNetwork(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Configuring hybrid network")

	// Configure provider network components
	if err := configureProviderNetwork(rc, config); err != nil {
		return fmt.Errorf("provider network configuration failed: %w", err)
	}

	// Add tenant network components
	if err := createOVSBridge(rc, "br-tun"); err != nil {
		return fmt.Errorf("failed to create tunnel bridge: %w", err)
	}

	// Update OVS agent configuration for hybrid mode
	if err := updateOVSAgentForHybrid(rc, config); err != nil {
		return fmt.Errorf("failed to update OVS agent for hybrid: %w", err)
	}

	logger.Info("Hybrid network configuration completed")
	return nil
}

// startOpenVSwitch starts and enables the Open vSwitch service
func startOpenVSwitch(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting Open vSwitch")

	// Enable and start OVS
	enableCmd := exec.CommandContext(rc.Ctx, "systemctl", "enable", "openvswitch-switch")
	if err := enableCmd.Run(); err != nil {
		return fmt.Errorf("failed to enable OVS: %w", err)
	}

	startCmd := exec.CommandContext(rc.Ctx, "systemctl", "start", "openvswitch-switch")
	if err := startCmd.Run(); err != nil {
		return fmt.Errorf("failed to start OVS: %w", err)
	}

	// Wait for OVS to be ready
	for i := 0; i < 10; i++ {
		checkCmd := exec.CommandContext(rc.Ctx, "ovs-vsctl", "show")
		if err := checkCmd.Run(); err == nil {
			logger.Info("Open vSwitch is ready")
			return nil
		}
		logger.Debug("Waiting for OVS to be ready", zap.Int("attempt", i+1))
		exec.CommandContext(rc.Ctx, "sleep", "1").Run()
	}

	return fmt.Errorf("OVS failed to start properly")
}

// createOVSBridge creates an Open vSwitch bridge
func createOVSBridge(rc *eos_io.RuntimeContext, bridgeName string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Creating OVS bridge", zap.String("bridge", bridgeName))

	// Check if bridge already exists
	checkCmd := exec.CommandContext(rc.Ctx, "ovs-vsctl", "br-exists", bridgeName)
	if checkCmd.Run() == nil {
		logger.Debug("Bridge already exists", zap.String("bridge", bridgeName))
		return nil
	}

	// Create bridge
	createCmd := exec.CommandContext(rc.Ctx, "ovs-vsctl", "add-br", bridgeName)
	if err := createCmd.Run(); err != nil {
		return fmt.Errorf("failed to create bridge %s: %w", bridgeName, err)
	}

	// Bring bridge up
	upCmd := exec.CommandContext(rc.Ctx, "ip", "link", "set", bridgeName, "up")
	if err := upCmd.Run(); err != nil {
		return fmt.Errorf("failed to bring up bridge %s: %w", bridgeName, err)
	}

	return nil
}

// addInterfaceToOVSBridge adds a physical interface to an OVS bridge
func addInterfaceToOVSBridge(rc *eos_io.RuntimeContext, bridge, iface string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Adding interface to OVS bridge",
		zap.String("interface", iface),
		zap.String("bridge", bridge))

	// Check if interface is already part of bridge
	checkCmd := exec.CommandContext(rc.Ctx, "ovs-vsctl", "port-to-br", iface)
	output, _ := checkCmd.Output()
	if strings.TrimSpace(string(output)) == bridge {
		logger.Debug("Interface already in bridge")
		return nil
	}

	// Add interface to bridge
	addCmd := exec.CommandContext(rc.Ctx, "ovs-vsctl", "add-port", bridge, iface)
	if err := addCmd.Run(); err != nil {
		return fmt.Errorf("failed to add interface to bridge: %w", err)
	}

	return nil
}

// configureNeutronOVSAgent configures the Neutron OVS agent
func configureNeutronOVSAgent(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Configuring Neutron OVS agent")

	configFile := "/etc/neutron/plugins/ml2/openvswitch_agent.ini"
	
	// Generate OVS agent configuration
	ovsConfig := generateOVSAgentConfig(config)

	// Write configuration
	if err := os.WriteFile(configFile, []byte(ovsConfig), 0640); err != nil {
		return fmt.Errorf("failed to write OVS agent config: %w", err)
	}

	// Set ownership
	uid, gid, err := eos_unix.LookupUser(rc.Ctx, "neutron")
	if err == nil {
		if err := os.Chown(configFile, uid, gid); err != nil {
			logger.Warn("Failed to set ownership on OVS agent config", zap.Error(err))
		}
	}

	// Restart OVS agent
	restartCmd := exec.CommandContext(rc.Ctx, "systemctl", "restart", "neutron-openvswitch-agent")
	if err := restartCmd.Run(); err != nil {
		return fmt.Errorf("failed to restart OVS agent: %w", err)
	}

	return nil
}

// configureL3Agent configures the Neutron L3 agent
func configureL3Agent(rc *eos_io.RuntimeContext, config *Config, enableNAT bool) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Configuring Neutron L3 agent", zap.Bool("nat", enableNAT))

	l3Config := fmt.Sprintf(`[DEFAULT]
interface_driver = openvswitch
external_network_bridge =
gateway_external_network_id =
router_delete_namespaces = true
metadata_proxy_socket = /var/lib/neutron/metadata_proxy

[agent]
enable_metadata_proxy = true
`)

	if enableNAT {
		l3Config += `
[AGENT]
# Enable NAT for tenant networks
enable_snat = true
`
	}

	configFile := "/etc/neutron/l3_agent.ini"
	if err := os.WriteFile(configFile, []byte(l3Config), 0640); err != nil {
		return fmt.Errorf("failed to write L3 agent config: %w", err)
	}

	// Set ownership
	uid, gid, err := eos_unix.LookupUser(rc.Ctx, "neutron")
	if err == nil {
		if err := os.Chown(configFile, uid, gid); err != nil {
			logger.Warn("Failed to set ownership on L3 agent config", zap.Error(err))
		}
	}

	// Enable IP forwarding
	if err := enableIPForwarding(rc); err != nil {
		return fmt.Errorf("failed to enable IP forwarding: %w", err)
	}

	// Restart L3 agent
	restartCmd := exec.CommandContext(rc.Ctx, "systemctl", "restart", "neutron-l3-agent")
	if err := restartCmd.Run(); err != nil {
		return fmt.Errorf("failed to restart L3 agent: %w", err)
	}

	return nil
}

// configureDHCPAgent configures the Neutron DHCP agent
func configureDHCPAgent(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Configuring Neutron DHCP agent")

	dhcpConfig := `[DEFAULT]
interface_driver = openvswitch
dhcp_driver = neutron.agent.linux.dhcp.Dnsmasq
enable_isolated_metadata = true
force_metadata = true
dhcp_delete_namespaces = true

[AGENT]
# DHCP agent specific configuration
`

	configFile := "/etc/neutron/dhcp_agent.ini"
	if err := os.WriteFile(configFile, []byte(dhcpConfig), 0640); err != nil {
		return fmt.Errorf("failed to write DHCP agent config: %w", err)
	}

	// Set ownership
	uid, gid, err := eos_unix.LookupUser(rc.Ctx, "neutron")
	if err == nil {
		if err := os.Chown(configFile, uid, gid); err != nil {
			logger.Warn("Failed to set ownership on DHCP agent config", zap.Error(err))
		}
	}

	// Configure dnsmasq
	dnsmasqConfig := `dhcp-option-force=26,1500
log-dhcp
log-queries
log-facility=/var/log/neutron/dnsmasq.log`

	dnsmasqDir := "/etc/neutron/dnsmasq"
	if err := os.MkdirAll(dnsmasqDir, 0755); err != nil {
		return fmt.Errorf("failed to create dnsmasq directory: %w", err)
	}

	dnsmasqConfigFile := filepath.Join(dnsmasqDir, "neutron-dnsmasq.conf")
	if err := os.WriteFile(dnsmasqConfigFile, []byte(dnsmasqConfig), 0644); err != nil {
		return fmt.Errorf("failed to write dnsmasq config: %w", err)
	}

	// Restart DHCP agent
	restartCmd := exec.CommandContext(rc.Ctx, "systemctl", "restart", "neutron-dhcp-agent")
	if err := restartCmd.Run(); err != nil {
		return fmt.Errorf("failed to restart DHCP agent: %w", err)
	}

	return nil
}

// configureMetadataAgent configures the Neutron metadata agent
func configureMetadataAgent(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Configuring Neutron metadata agent")

	metadataSecret := generateToken()
	metadataConfig := fmt.Sprintf(`[DEFAULT]
nova_metadata_host = %s
metadata_proxy_shared_secret = %s
metadata_workers = 2
metadata_backlog = 4096

[cache]
enabled = true
backend = oslo_cache.memcache_pool
memcache_servers = %s
`, getControllerIP(config), metadataSecret, getMemcacheServers(config))

	configFile := "/etc/neutron/metadata_agent.ini"
	if err := os.WriteFile(configFile, []byte(metadataConfig), 0640); err != nil {
		return fmt.Errorf("failed to write metadata agent config: %w", err)
	}

	// Set ownership
	uid, gid, err := eos_unix.LookupUser(rc.Ctx, "neutron")
	if err == nil {
		if err := os.Chown(configFile, uid, gid); err != nil {
			logger.Warn("Failed to set ownership on metadata agent config", zap.Error(err))
		}
	}

	// Restart metadata agent
	restartCmd := exec.CommandContext(rc.Ctx, "systemctl", "restart", "neutron-metadata-agent")
	if err := restartCmd.Run(); err != nil {
		return fmt.Errorf("failed to restart metadata agent: %w", err)
	}

	return nil
}

// Helper functions

func generateOVSAgentConfig(config *Config) string {
	bridgeMappings := ""
	if config.NetworkType == NetworkProvider || config.NetworkType == NetworkHybrid {
		bridgeMappings = fmt.Sprintf("%s:br-%s", config.ProviderPhysnet, config.ProviderPhysnet)
	}

	tunnelTypes := ""
	if config.NetworkType == NetworkTenant || config.NetworkType == NetworkHybrid {
		tunnelTypes = "vxlan"
	}

	return fmt.Sprintf(`[ovs]
bridge_mappings = %s
local_ip = %s

[agent]
tunnel_types = %s
l2_population = true
arp_responder = true

[securitygroup]
firewall_driver = openvswitch
enable_security_group = true
enable_ipset = true
`, bridgeMappings, getLocalIP(nil), tunnelTypes)
}

func updateOVSAgentForHybrid(rc *eos_io.RuntimeContext, config *Config) error {
	// In hybrid mode, we need to ensure both provider and tenant configs are present
	// This would merge configurations appropriately
	return configureNeutronOVSAgent(rc, config)
}

func migrateIPConfiguration(rc *eos_io.RuntimeContext, fromIface, toIface string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Migrating IP configuration",
		zap.String("from", fromIface),
		zap.String("to", toIface))

	// Get current IP addresses
	showCmd := exec.CommandContext(rc.Ctx, "ip", "addr", "show", fromIface)
	output, err := showCmd.Output()
	if err != nil {
		return fmt.Errorf("failed to get IP addresses: %w", err)
	}

	// Parse and migrate IPs (simplified - production would be more robust)
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "inet ") && !strings.Contains(line, "127.0.0.1") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				ip := fields[1]
				// Add IP to bridge
				addCmd := exec.CommandContext(rc.Ctx, "ip", "addr", "add", ip, "dev", toIface)
				if err := addCmd.Run(); err != nil {
					logger.Warn("Failed to add IP to bridge",
						zap.String("ip", ip),
						zap.Error(err))
				}
			}
		}
	}

	// Remove IPs from original interface
	flushCmd := exec.CommandContext(rc.Ctx, "ip", "addr", "flush", "dev", fromIface)
	if err := flushCmd.Run(); err != nil {
		logger.Warn("Failed to flush IPs from interface", zap.Error(err))
	}

	return nil
}

func enableIPForwarding(rc *eos_io.RuntimeContext) error {
	// Enable IP forwarding
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0644); err != nil {
		return err
	}

	// Make it persistent
	sysctlConfig := `net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
`

	if err := os.WriteFile("/etc/sysctl.d/99-openstack.conf", []byte(sysctlConfig), 0644); err != nil {
		return err
	}

	// Apply sysctl settings
	sysctlCmd := exec.CommandContext(rc.Ctx, "sysctl", "-p", "/etc/sysctl.d/99-openstack.conf")
	return sysctlCmd.Run()
}

func getControllerIP(config *Config) string {
	if config.IsControllerNode() {
		return "127.0.0.1"
	}
	return config.ControllerAddress
}