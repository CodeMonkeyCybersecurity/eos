package display

import (
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/openstack"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

// ShowInstallationSummary displays the final installation summary
func ShowInstallationSummary(rc *eos_io.RuntimeContext, config *openstack.Config) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("OpenStack installation completed successfully")

	// Display banner
	fmt.Println("\n╔══════════════════════════════════════════════════════════════════════════════╗")
	fmt.Println("║                       OPENSTACK INSTALLATION COMPLETE                          ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════════════════════╝")
	fmt.Println()

	// Deployment summary
	fmt.Println(" Deployment Summary")
	fmt.Println("════════════════════")
	fmt.Printf("   • Mode:              %s\n", formatMode(config.Mode))
	fmt.Printf("   • Version:           %s (Caracal)\n", "2024.1")
	fmt.Printf("   • Network Type:      %s\n", formatNetworkType(config.NetworkType))
	fmt.Printf("   • Storage Backend:   %s\n", formatStorageBackend(config.StorageBackend))
	fmt.Printf("   • Dashboard:         %s\n", formatEnabled(config.EnableDashboard))
	fmt.Printf("   • SSL/TLS:           %s\n", formatEnabled(config.EnableSSL))
	fmt.Println()

	// Service endpoints
	fmt.Println(" Service Endpoints")
	fmt.Println("═══════════════════")
	displayEndpoints(config)
	fmt.Println()

	// Access credentials
	fmt.Println("🔑 Access Credentials")
	fmt.Println("════════════════════")
	fmt.Println("   Admin User:")
	fmt.Println("   • Username: admin")
	fmt.Println("   • Password: [Set during installation]")
	fmt.Println("   • Project:  admin")
	fmt.Println("   • Domain:   Default")
	fmt.Println()
	fmt.Println("   Environment File:")
	fmt.Println("   • Admin:    /etc/openstack/admin-openrc.sh")
	fmt.Println("   • Demo:     /etc/openstack/demo-openrc.sh")
	fmt.Println()

	// Enabled services
	fmt.Println(" Enabled Services")
	fmt.Println("══════════════════")
	displayEnabledServices(config)
	fmt.Println()

	// Integration status
	if config.VaultIntegration || config.ConsulIntegration {
		fmt.Println(" Integrations")
		fmt.Println("══════════════")
		if config.VaultIntegration {
			fmt.Printf("   • Vault:   ✓ Enabled (%s)\n", config.VaultAddress)
		}
		if config.ConsulIntegration {
			fmt.Printf("   • Consul:  ✓ Enabled (%s)\n", config.ConsulAddress)
		}
		fmt.Println()
	}

	// Quick commands
	fmt.Println("⚡ Quick Commands")
	fmt.Println("════════════════")
	fmt.Println("   Source credentials:    source /etc/openstack/admin-openrc.sh")
	fmt.Println("   List services:         openstack service list")
	fmt.Println("   List endpoints:        openstack endpoint list")
	fmt.Println("   List projects:         openstack project list")
	fmt.Println("   List users:            openstack user list")
	fmt.Println("   List images:           openstack image list")
	fmt.Println("   List flavors:          openstack flavor list")
	fmt.Println("   List networks:         openstack network list")
	fmt.Println()

	// Next steps
	fmt.Println(" Next Steps")
	fmt.Println("════════════")
	displayNextSteps(config)
	fmt.Println()

	// Support information
	fmt.Println(" Tips")
	fmt.Println("══════")
	fmt.Println("   • Check service status:  eos read openstack status")
	fmt.Println("   • View logs:             journalctl -u <service-name>")
	fmt.Println("   • Update configuration:  eos update openstack")
	if config.EnableDashboard {
		fmt.Printf("   • Access dashboard:      %s\n", getDashboardURL(config))
	}
	fmt.Println()

	// Footer
	fmt.Println("═══════════════════════════════════════════════════════════════════════════════")
	fmt.Printf("Installation completed at: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Println("═══════════════════════════════════════════════════════════════════════════════")
}

// ShowInstallationPlan displays what will be installed
func ShowInstallationPlan(rc *eos_io.RuntimeContext, config *openstack.Config) {
	fmt.Println("\n OpenStack Installation Plan")
	fmt.Println("══════════════════════════════")
	fmt.Println()

	// Basic configuration
	fmt.Println("Configuration:")
	fmt.Printf("  • Deployment Mode:    %s\n", formatMode(config.Mode))
	fmt.Printf("  • Network Type:       %s\n", formatNetworkType(config.NetworkType))
	fmt.Printf("  • Storage Backend:    %s\n", formatStorageBackend(config.StorageBackend))
	fmt.Println()

	// Services to install
	fmt.Println("Services to Install:")
	services := config.GetEnabledServices()
	for _, service := range services {
		fmt.Printf("  • %s - %s\n", service, getServiceDescription(service))
	}
	fmt.Println()

	// System requirements
	fmt.Println("System Requirements:")
	displaySystemRequirements(config.Mode)
	fmt.Println()

	// Network configuration
	if config.NetworkType == openstack.NetworkProvider {
		fmt.Println("Network Configuration:")
		fmt.Printf("  • Provider Interface: %s\n", config.ProviderInterface)
		fmt.Printf("  • Physical Network:   %s\n", config.ProviderPhysnet)
		fmt.Println()
	}

	// Storage configuration
	fmt.Println("Storage Configuration:")
	switch config.StorageBackend {
	case openstack.StorageLVM:
		fmt.Println("  • LVM volume group will be created")
		fmt.Println("  • Thin provisioning enabled")
	case openstack.StorageCeph:
		fmt.Printf("  • Ceph monitors: %s\n", strings.Join(config.CephMonitors, ", "))
		fmt.Printf("  • Pool: %s\n", config.CephPool)
	case openstack.StorageNFS:
		fmt.Printf("  • NFS server: %s\n", config.NFSServer)
		fmt.Printf("  • NFS path: %s\n", config.NFSExportPath)
	}
	fmt.Println()

	// Time estimate
	fmt.Println("Estimated Installation Time:")
	fmt.Printf("  • %s\n", getTimeEstimate(config.Mode))
	fmt.Println()
}

// ShowExistingInstallation displays information about an existing installation
func ShowExistingInstallation(rc *eos_io.RuntimeContext, status *openstack.InstallationStatus) {
	fmt.Println("\nExisting OpenStack Installation Detected")
	fmt.Println("═══════════════════════════════════════════")
	fmt.Println()

	fmt.Printf("Version:      %s\n", status.Version)
	fmt.Printf("Mode:         %s\n", formatMode(status.Mode))
	fmt.Printf("Installed:    %s\n", status.LastUpdated.Format("2006-01-02 15:04:05"))
	fmt.Printf("Health:       %s\n", status.HealthStatus)
	fmt.Println()

	if len(status.Services) > 0 {
		fmt.Println("Services:")
		for _, svc := range status.Services {
			statusIcon := ""
			if svc.Healthy {
				statusIcon = ""
			} else if svc.Running {
				statusIcon = ""
			}
			fmt.Printf("  %s %s - %s\n", statusIcon, svc.Name, svc.Message)
		}
		fmt.Println()
	}

	fmt.Println("Options:")
	fmt.Println("  • Use --force to reinstall")
	fmt.Println("  • Use 'eos update openstack' to update configuration")
	fmt.Println("  • Use 'eos delete openstack' to remove installation")
}

// Helper functions

func formatMode(mode openstack.DeploymentMode) string {
	switch mode {
	case openstack.ModeAllInOne:
		return "All-in-One"
	case openstack.ModeController:
		return "Controller Node"
	case openstack.ModeCompute:
		return "Compute Node"
	case openstack.ModeStorage:
		return "Storage Node"
	default:
		return string(mode)
	}
}

func formatNetworkType(nt openstack.NetworkType) string {
	switch nt {
	case openstack.NetworkProvider:
		return "Provider Networks"
	case openstack.NetworkTenant:
		return "Tenant Networks (VXLAN)"
	case openstack.NetworkHybrid:
		return "Hybrid (Provider + Tenant)"
	default:
		return string(nt)
	}
}

func formatStorageBackend(sb openstack.StorageBackend) string {
	switch sb {
	case openstack.StorageLVM:
		return "LVM (Local)"
	case openstack.StorageCeph:
		return "Ceph (Distributed)"
	case openstack.StorageNFS:
		return "NFS (Network)"
	default:
		return string(sb)
	}
}

func formatEnabled(enabled bool) string {
	if enabled {
		return "✓ Enabled"
	}
	return "✗ Disabled"
}

func displayEndpoints(config *openstack.Config) {
	endpoints := []struct {
		name string
		port int
		path string
	}{
		{"Identity (Keystone)", openstack.PortKeystone, "/v3"},
		{"Image (Glance)", openstack.PortGlance, ""},
		{"Compute (Nova)", openstack.PortNovaAPI, "/v2.1"},
		{"Network (Neutron)", openstack.PortNeutron, ""},
		{"Block Storage (Cinder)", openstack.PortCinder, "/v3"},
	}

	// Public endpoints
	fmt.Println("   Public:")
	for _, ep := range endpoints {
		if shouldShowEndpoint(config, ep.name) {
			fmt.Printf("   • %-22s %s:%d%s\n", ep.name+":", config.PublicEndpoint, ep.port, ep.path)
		}
	}

	if config.EnableDashboard {
		dashPort := openstack.PortHorizon
		if config.EnableSSL {
			dashPort = openstack.PortHorizonSSL
		}
		fmt.Printf("   • %-22s %s:%d\n", "Dashboard (Horizon):", config.PublicEndpoint, dashPort)
	}

	// Only show internal/admin for controller nodes
	if config.Mode == openstack.ModeController || config.Mode == openstack.ModeAllInOne {
		fmt.Println("\n   Internal:")
		for _, ep := range endpoints {
			if shouldShowEndpoint(config, ep.name) {
				fmt.Printf("   • %-22s %s:%d%s\n", ep.name+":", config.InternalEndpoint, ep.port, ep.path)
			}
		}
	}
}

func shouldShowEndpoint(config *openstack.Config, serviceName string) bool {
	// Always show Keystone
	if strings.Contains(serviceName, "Keystone") {
		return true
	}

	// Check if service is enabled
	services := config.GetEnabledServices()
	for _, svc := range services {
		if strings.Contains(strings.ToLower(serviceName), strings.ToLower(string(svc))) {
			return true
		}
	}

	return false
}

func displayEnabledServices(config *openstack.Config) {
	services := config.GetEnabledServices()
	serviceDescriptions := map[openstack.Service]string{
		openstack.ServiceKeystone: "Identity Service",
		openstack.ServiceGlance:   "Image Service",
		openstack.ServiceNova:     "Compute Service",
		openstack.ServiceNeutron:  "Networking Service",
		openstack.ServiceCinder:   "Block Storage Service",
		openstack.ServiceSwift:    "Object Storage Service",
		openstack.ServiceHorizon:  "Dashboard",
		openstack.ServiceHeat:     "Orchestration Service",
	}

	for i, service := range services {
		desc := serviceDescriptions[service]
		if desc == "" {
			desc = "OpenStack Service"
		}
		fmt.Printf("   %d. %s (%s)\n", i+1, service, desc)
	}
}

func displayNextSteps(config *openstack.Config) {
	steps := []string{
		"Source admin credentials to use OpenStack CLI",
		"Verify all services are running: openstack service list",
	}

	if config.NetworkType == openstack.NetworkProvider {
		steps = append(steps, "Create external network: openstack network create --external public")
	}

	steps = append(steps,
		"Upload cloud images: openstack image create --file <image> <name>",
		"Create flavors if needed: openstack flavor create",
		"Create security groups and rules",
		"Launch your first instance!",
	)

	if config.EnableDashboard {
		steps = append(steps, fmt.Sprintf("Access Horizon dashboard at %s", getDashboardURL(config)))
	}

	for i, step := range steps {
		fmt.Printf("   %d. %s\n", i+1, step)
	}
}

func getDashboardURL(config *openstack.Config) string {
	if !config.EnableDashboard {
		return ""
	}

	protocol := "http"
	port := openstack.PortHorizon
	if config.EnableSSL {
		protocol = "https"
		port = openstack.PortHorizonSSL
	}

	return fmt.Sprintf("%s://%s:%d", protocol,
		strings.TrimPrefix(strings.TrimPrefix(config.PublicEndpoint, "http://"), "https://"),
		port)
}

func getServiceDescription(service openstack.Service) string {
	descriptions := map[openstack.Service]string{
		openstack.ServiceKeystone: "Identity and authentication service",
		openstack.ServiceGlance:   "Image storage and retrieval service",
		openstack.ServiceNova:     "Compute virtualization service",
		openstack.ServiceNeutron:  "Software-defined networking service",
		openstack.ServiceCinder:   "Block storage service",
		openstack.ServiceSwift:    "Object storage service",
		openstack.ServiceHorizon:  "Web-based dashboard interface",
		openstack.ServiceHeat:     "Orchestration and automation service",
	}

	if desc, ok := descriptions[service]; ok {
		return desc
	}
	return "OpenStack service"
}

func displaySystemRequirements(mode openstack.DeploymentMode) {
	requirements := map[openstack.DeploymentMode]struct {
		cpu    string
		memory string
		disk   string
	}{
		openstack.ModeAllInOne: {
			cpu:    "4+ cores (8+ recommended)",
			memory: "16 GB minimum (32 GB recommended)",
			disk:   "100 GB minimum (200 GB recommended)",
		},
		openstack.ModeController: {
			cpu:    "4+ cores",
			memory: "8 GB minimum (16 GB recommended)",
			disk:   "50 GB minimum",
		},
		openstack.ModeCompute: {
			cpu:    "4+ cores (with virtualization support)",
			memory: "8 GB minimum (16+ GB recommended)",
			disk:   "50 GB minimum (plus instance storage)",
		},
		openstack.ModeStorage: {
			cpu:    "2+ cores",
			memory: "4 GB minimum",
			disk:   "100 GB minimum (plus storage volumes)",
		},
	}

	if req, ok := requirements[mode]; ok {
		fmt.Printf("  • CPU:    %s\n", req.cpu)
		fmt.Printf("  • Memory: %s\n", req.memory)
		fmt.Printf("  • Disk:   %s\n", req.disk)
	}
}

func getTimeEstimate(mode openstack.DeploymentMode) string {
	estimates := map[openstack.DeploymentMode]string{
		openstack.ModeAllInOne:   "20-30 minutes",
		openstack.ModeController: "15-20 minutes",
		openstack.ModeCompute:    "10-15 minutes",
		openstack.ModeStorage:    "10-15 minutes",
	}

	if estimate, ok := estimates[mode]; ok {
		return estimate
	}
	return "15-30 minutes"
}
