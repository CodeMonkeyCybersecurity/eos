package openstack

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

// InteractiveConfig prompts the user for configuration details
func InteractiveConfig(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting interactive configuration")

	reader := bufio.NewReader(os.Stdin)

	fmt.Println("\n OpenStack Interactive Configuration")
	fmt.Println("══════════════════════════════════════")
	fmt.Println("We'll guide you through the configuration process.")
	fmt.Println("Press Enter to accept the default value [shown in brackets].")

	// Deployment mode
	if err := promptDeploymentMode(reader, config); err != nil {
		return err
	}

	// Network configuration
	if err := promptNetworkConfig(reader, config); err != nil {
		return err
	}

	// Storage configuration
	if err := promptStorageConfig(reader, config); err != nil {
		return err
	}

	// Endpoint configuration
	if err := promptEndpointConfig(reader, config); err != nil {
		return err
	}

	// Authentication
	if err := promptAuthentication(reader, config); err != nil {
		return err
	}

	// Features
	if err := promptFeatures(reader, config); err != nil {
		return err
	}

	// Integration options
	if err := promptIntegrations(reader, config); err != nil {
		return err
	}

	// Summary
	displayConfigSummary(config)

	// Confirm
	fmt.Print("\nProceed with this configuration? [Y/n]: ")
	confirm, _ := reader.ReadString('\n')
	confirm = strings.TrimSpace(strings.ToLower(confirm))

	if confirm == "n" || confirm == "no" {
		return eos_err.NewUserError("Configuration cancelled by user")
	}

	logger.Info("Interactive configuration completed")
	return nil
}

// promptDeploymentMode prompts for deployment mode selection
func promptDeploymentMode(reader *bufio.Reader, config *Config) error {
	fmt.Println(" Deployment Mode")
	fmt.Println("─────────────────")
	fmt.Println("1. All-in-One (Development/Testing)")
	fmt.Println("2. Controller Node (Production)")
	fmt.Println("3. Compute Node (Add to existing cluster)")
	fmt.Println("4. Storage Node (Add storage to cluster)")

	fmt.Printf("\nSelect deployment mode [1]: ")
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	if choice == "" {
		choice = "1"
	}

	switch choice {
	case "1":
		config.Mode = ModeAllInOne
	case "2":
		config.Mode = ModeController
	case "3":
		config.Mode = ModeCompute
		// Need controller address for compute nodes
		fmt.Print("Controller node address: ")
		controller, _ := reader.ReadString('\n')
		config.ControllerAddress = strings.TrimSpace(controller)
		if config.ControllerAddress == "" {
			return eos_err.NewUserError("Controller address is required for compute nodes")
		}
	case "4":
		config.Mode = ModeStorage
		// Need controller address for storage nodes
		fmt.Print("Controller node address: ")
		controller, _ := reader.ReadString('\n')
		config.ControllerAddress = strings.TrimSpace(controller)
		if config.ControllerAddress == "" {
			return eos_err.NewUserError("Controller address is required for storage nodes")
		}
	default:
		return eos_err.NewUserError("Invalid deployment mode selection")
	}

	return nil
}

// promptNetworkConfig prompts for network configuration
func promptNetworkConfig(reader *bufio.Reader, config *Config) error {
	fmt.Println("\n Network Configuration")
	fmt.Println("───────────────────────")

	// Skip for storage nodes
	if config.Mode == ModeStorage {
		config.NetworkType = NetworkProvider // Default
		return nil
	}

	fmt.Println("1. Provider Networks (External network access)")
	fmt.Println("2. Tenant Networks (Isolated overlay networks)")
	fmt.Println("3. Hybrid (Both provider and tenant)")

	fmt.Printf("\nSelect network type [1]: ")
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	if choice == "" {
		choice = "1"
	}

	switch choice {
	case "1":
		config.NetworkType = NetworkProvider
	case "2":
		config.NetworkType = NetworkTenant
	case "3":
		config.NetworkType = NetworkHybrid
	default:
		return eos_err.NewUserError("Invalid network type selection")
	}

	// Provider network configuration
	if config.NetworkType == NetworkProvider || config.NetworkType == NetworkHybrid {
		fmt.Print("Provider network interface (e.g., eth1): ")
		iface, _ := reader.ReadString('\n')
		config.ProviderInterface = strings.TrimSpace(iface)

		if config.ProviderInterface == "" {
			// Try to detect available interfaces
			interfaces := detectNetworkInterfaces()
			if len(interfaces) > 0 {
				fmt.Println("\nAvailable interfaces:")
				for i, iface := range interfaces {
					fmt.Printf("%d. %s\n", i+1, iface)
				}
				fmt.Print("Select interface number: ")
				choice, _ := reader.ReadString('\n')
				choice = strings.TrimSpace(choice)
				// Parse choice and set interface
			}
		}

		fmt.Printf("Provider physical network name [physnet1]: ")
		physnet, _ := reader.ReadString('\n')
		config.ProviderPhysnet = strings.TrimSpace(physnet)
		if config.ProviderPhysnet == "" {
			config.ProviderPhysnet = "physnet1"
		}
	}

	// Management network
	fmt.Printf("Management network CIDR [10.0.0.0/24]: ")
	mgmtNet, _ := reader.ReadString('\n')
	config.ManagementNetwork = strings.TrimSpace(mgmtNet)
	if config.ManagementNetwork == "" {
		config.ManagementNetwork = "10.0.0.0/24"
	}

	return nil
}

// promptStorageConfig prompts for storage configuration
func promptStorageConfig(reader *bufio.Reader, config *Config) error {
	fmt.Println("\n Storage Configuration")
	fmt.Println("───────────────────────")

	// Skip for compute-only nodes
	if config.Mode == ModeCompute {
		config.StorageBackend = StorageLVM // Default
		return nil
	}

	fmt.Println("1. LVM (Local storage)")
	fmt.Println("2. Ceph (Distributed storage)")
	fmt.Println("3. NFS (Network storage)")

	fmt.Printf("\nSelect storage backend [1]: ")
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	if choice == "" {
		choice = "1"
	}

	switch choice {
	case "1":
		config.StorageBackend = StorageLVM
		fmt.Printf("LVM volume group name [cinder-volumes]: ")
		vg, _ := reader.ReadString('\n')
		config.LVMVolumeGroup = strings.TrimSpace(vg)
		if config.LVMVolumeGroup == "" {
			config.LVMVolumeGroup = "cinder-volumes"
		}

	case "2":
		config.StorageBackend = StorageCeph
		fmt.Print("Ceph monitor addresses (comma-separated): ")
		monitors, _ := reader.ReadString('\n')
		monitors = strings.TrimSpace(monitors)
		if monitors != "" {
			config.CephMonitors = strings.Split(monitors, ",")
			for i := range config.CephMonitors {
				config.CephMonitors[i] = strings.TrimSpace(config.CephMonitors[i])
			}
		}

		fmt.Printf("Ceph pool name [volumes]: ")
		pool, _ := reader.ReadString('\n')
		config.CephPool = strings.TrimSpace(pool)
		if config.CephPool == "" {
			config.CephPool = "volumes"
		}

	case "3":
		config.StorageBackend = StorageNFS
		fmt.Print("NFS server address: ")
		server, _ := reader.ReadString('\n')
		config.NFSServer = strings.TrimSpace(server)
		if config.NFSServer == "" {
			return eos_err.NewUserError("NFS server address is required")
		}

		fmt.Printf("NFS export path [/openstack/volumes]: ")
		path, _ := reader.ReadString('\n')
		config.NFSExportPath = strings.TrimSpace(path)
		if config.NFSExportPath == "" {
			config.NFSExportPath = "/openstack/volumes"
		}

	default:
		return eos_err.NewUserError("Invalid storage backend selection")
	}

	return nil
}

// promptEndpointConfig prompts for endpoint configuration
func promptEndpointConfig(reader *bufio.Reader, config *Config) error {
	fmt.Println("\n Endpoint Configuration")
	fmt.Println("────────────────────────")

	// Get hostname if not set
	hostname, _ := os.Hostname()

	// Public endpoint
	fmt.Printf("Public endpoint URL [http://%s]: ", hostname)
	public, _ := reader.ReadString('\n')
	config.PublicEndpoint = strings.TrimSpace(public)
	if config.PublicEndpoint == "" {
		config.PublicEndpoint = fmt.Sprintf("http://%s", hostname)
	}

	// Internal endpoint
	fmt.Printf("Internal endpoint URL [%s]: ", config.PublicEndpoint)
	internal, _ := reader.ReadString('\n')
	config.InternalEndpoint = strings.TrimSpace(internal)
	if config.InternalEndpoint == "" {
		config.InternalEndpoint = config.PublicEndpoint
	}

	// Admin endpoint
	fmt.Printf("Admin endpoint URL [%s]: ", config.InternalEndpoint)
	admin, _ := reader.ReadString('\n')
	config.AdminEndpoint = strings.TrimSpace(admin)
	if config.AdminEndpoint == "" {
		config.AdminEndpoint = config.InternalEndpoint
	}

	return nil
}

// promptAuthentication prompts for authentication settings
func promptAuthentication(reader *bufio.Reader, config *Config) error {
	fmt.Println("\n🔐 Authentication")
	fmt.Println("────────────────")

	// Admin password
	if config.AdminPassword == "" {
		for {
			fmt.Print("Admin password (8+ characters): ")
			password, _ := reader.ReadString('\n')
			password = strings.TrimSpace(password)

			if len(password) < 8 {
				fmt.Println(" Password must be at least 8 characters")
				continue
			}

			fmt.Print("Confirm admin password: ")
			confirm, _ := reader.ReadString('\n')
			confirm = strings.TrimSpace(confirm)

			if password != confirm {
				fmt.Println(" Passwords do not match")
				continue
			}

			config.AdminPassword = password
			break
		}
	}

	// Admin email
	fmt.Printf("Admin email [admin@example.com]: ")
	email, _ := reader.ReadString('\n')
	config.AdminEmail = strings.TrimSpace(email)
	if config.AdminEmail == "" {
		config.AdminEmail = "admin@example.com"
	}

	// Service passwords (auto-generate if not provided)
	if config.ServicePassword == "" {
		config.ServicePassword = generateSecurePassword()
		fmt.Println("✓ Generated service password")
	}
	if config.DBPassword == "" {
		config.DBPassword = generateSecurePassword()
		fmt.Println("✓ Generated database password")
	}
	if config.RabbitMQPassword == "" {
		config.RabbitMQPassword = generateSecurePassword()
		fmt.Println("✓ Generated RabbitMQ password")
	}

	return nil
}

// promptFeatures prompts for feature selection
func promptFeatures(reader *bufio.Reader, config *Config) error {
	fmt.Println("\n✨ Features")
	fmt.Println("──────────")

	// Dashboard
	if config.Mode == ModeController || config.Mode == ModeAllInOne {
		fmt.Printf("Enable Horizon dashboard? [Y/n]: ")
		dashboard, _ := reader.ReadString('\n')
		dashboard = strings.TrimSpace(strings.ToLower(dashboard))
		config.EnableDashboard = dashboard != "n" && dashboard != "no"
	}

	// SSL/TLS
	fmt.Printf("Enable SSL/TLS for endpoints? [y/N]: ")
	ssl, _ := reader.ReadString('\n')
	ssl = strings.TrimSpace(strings.ToLower(ssl))
	config.EnableSSL = ssl == "y" || ssl == "yes"

	if config.EnableSSL {
		fmt.Print("SSL certificate path: ")
		cert, _ := reader.ReadString('\n')
		config.SSLCertPath = strings.TrimSpace(cert)

		fmt.Print("SSL key path: ")
		key, _ := reader.ReadString('\n')
		config.SSLKeyPath = strings.TrimSpace(key)

		if config.SSLCertPath == "" || config.SSLKeyPath == "" {
			fmt.Println("SSL enabled but no certificates provided")
			fmt.Println("   Self-signed certificates will be generated")
		}
	}

	// Services selection
	if config.Mode == ModeController || config.Mode == ModeAllInOne {
		fmt.Println("\nSelect additional services to enable:")
		fmt.Printf("Enable Swift (Object Storage)? [y/N]: ")
		swift, _ := reader.ReadString('\n')
		swift = strings.TrimSpace(strings.ToLower(swift))

		fmt.Printf("Enable Heat (Orchestration)? [y/N]: ")
		heat, _ := reader.ReadString('\n')
		heat = strings.TrimSpace(strings.ToLower(heat))

		// Build enabled services list
		services := []Service{
			ServiceKeystone,
			ServiceGlance,
			ServiceNova,
			ServiceNeutron,
			ServiceCinder,
		}

		if swift == "y" || swift == "yes" {
			services = append(services, ServiceSwift)
		}
		if heat == "y" || heat == "yes" {
			services = append(services, ServiceHeat)
		}
		if config.EnableDashboard {
			services = append(services, ServiceHorizon)
		}

		config.EnabledServices = services
	}

	return nil
}

// promptIntegrations prompts for integration options
func promptIntegrations(reader *bufio.Reader, config *Config) error {
	fmt.Println("\n Integrations")
	fmt.Println("──────────────")

	// Vault integration
	fmt.Printf("Enable Vault integration for secrets? [y/N]: ")
	vault, _ := reader.ReadString('\n')
	vault = strings.TrimSpace(strings.ToLower(vault))
	config.VaultIntegration = vault == "y" || vault == "yes"

	if config.VaultIntegration {
		fmt.Print("Vault server address: ")
		addr, _ := reader.ReadString('\n')
		config.VaultAddress = strings.TrimSpace(addr)
		if config.VaultAddress == "" {
			// Try to detect from environment
			if envAddr := os.Getenv("VAULT_ADDR"); envAddr != "" {
				config.VaultAddress = envAddr
				fmt.Printf("✓ Using Vault address from environment: %s\n", envAddr)
			}
		}
	}

	// Consul integration
	fmt.Printf("Enable Consul integration for service discovery? [y/N]: ")
	consul, _ := reader.ReadString('\n')
	consul = strings.TrimSpace(strings.ToLower(consul))
	config.ConsulIntegration = consul == "y" || consul == "yes"

	if config.ConsulIntegration {
		fmt.Print("Consul server address: ")
		addr, _ := reader.ReadString('\n')
		config.ConsulAddress = strings.TrimSpace(addr)
		if config.ConsulAddress == "" {
			// Try to detect from environment
			if envAddr := os.Getenv("CONSUL_HTTP_ADDR"); envAddr != "" {
				config.ConsulAddress = envAddr
				fmt.Printf("✓ Using Consul address from environment: %s\n", envAddr)
			}
		}
	}

	// LDAP/AD integration
	fmt.Printf("Enable LDAP/AD authentication? [y/N]: ")
	ldap, _ := reader.ReadString('\n')
	ldap = strings.TrimSpace(strings.ToLower(ldap))

	if ldap == "y" || ldap == "yes" {
		// This would prompt for LDAP configuration
		// Simplified for this example
		fmt.Println("LDAP configuration will be required post-installation")
	}

	return nil
}

// displayConfigSummary shows a summary of the configuration
func displayConfigSummary(config *Config) {
	fmt.Println("\n📊 Configuration Summary")
	fmt.Println("═══════════════════════")

	fmt.Printf("Deployment Mode:    %s\n", formatMode(config.Mode))
	fmt.Printf("Network Type:       %s\n", formatNetworkType(config.NetworkType))
	fmt.Printf("Storage Backend:    %s\n", formatStorageBackend(config.StorageBackend))
	fmt.Printf("Dashboard:          %s\n", formatBool(config.EnableDashboard))
	fmt.Printf("SSL/TLS:            %s\n", formatBool(config.EnableSSL))

	if config.ProviderInterface != "" {
		fmt.Printf("Provider Interface: %s\n", config.ProviderInterface)
	}

	fmt.Println("\nEndpoints:")
	fmt.Printf("  Public:   %s\n", config.PublicEndpoint)
	fmt.Printf("  Internal: %s\n", config.InternalEndpoint)
	fmt.Printf("  Admin:    %s\n", config.AdminEndpoint)

	if config.VaultIntegration || config.ConsulIntegration {
		fmt.Println("\nIntegrations:")
		if config.VaultIntegration {
			fmt.Printf("  Vault:  %s\n", config.VaultAddress)
		}
		if config.ConsulIntegration {
			fmt.Printf("  Consul: %s\n", config.ConsulAddress)
		}
	}

	fmt.Println("\nServices to Install:")
	for _, svc := range config.GetEnabledServices() {
		fmt.Printf("  • %s\n", svc)
	}
}

// Helper functions

func detectNetworkInterfaces() []string {
	// This would detect available network interfaces
	// Simplified for this example
	return []string{"eth0", "eth1", "ens3", "ens4"}
}

func formatBool(b bool) string {
	if b {
		return "Enabled"
	}
	return "Disabled"
}
