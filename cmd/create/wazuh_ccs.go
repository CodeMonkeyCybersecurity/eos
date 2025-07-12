// cmd/create/wazuh_ccs.go
package create

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/wazuh_mssp"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/wazuh_mssp/customer"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CreateWazuhCCSCmd creates the Wazuh MSSP platform
var CreateWazuhCCSCmd = &cobra.Command{
	Use:   "wazuh-ccs",
	Short: "Deploy Wazuh MSSP multi-tenant platform",
	Long: `Deploy a multi-tenant Wazuh deployment platform for Managed Security Service Providers (MSSPs).

This command can:
- Initialize the MSSP infrastructure (--init)
- Add new customers (--add-customer)
- Provision the complete platform

The platform includes:
- Multi-tenant Wazuh deployments with KVM isolation
- Cross-Cluster Search (CCS) for centralized SOC operations
- Self-service customer onboarding through Authentik SSO
- Automated provisioning with Temporal workflows
- Event-driven architecture with NATS and Benthos`,
	RunE: eos_cli.Wrap(runCreateWazuhCCS),
}

func init() {
	CreateCmd.AddCommand(CreateWazuhCCSCmd)

	// Platform initialization flags
	CreateWazuhCCSCmd.Flags().Bool("init", false, "Initialize MSSP infrastructure")
	CreateWazuhCCSCmd.Flags().String("platform-name", "wazuh-mssp", "Platform name")
	CreateWazuhCCSCmd.Flags().String("environment", "production", "Environment (dev/staging/production)")
	CreateWazuhCCSCmd.Flags().String("datacenter", "dc1", "Datacenter name")
	CreateWazuhCCSCmd.Flags().String("domain", "", "Platform domain (required)")

	// Network configuration
	CreateWazuhCCSCmd.Flags().String("platform-cidr", "10.0.0.0/16", "Platform network CIDR")
	CreateWazuhCCSCmd.Flags().String("customer-cidr", "10.100.0.0/16", "Customer network CIDR")
	CreateWazuhCCSCmd.Flags().Int("vlan-start", 100, "Starting VLAN ID")
	CreateWazuhCCSCmd.Flags().Int("vlan-end", 999, "Ending VLAN ID")

	// Resource configuration
	CreateWazuhCCSCmd.Flags().Int("nomad-servers", 3, "Number of Nomad servers")
	CreateWazuhCCSCmd.Flags().Int("nomad-clients", 5, "Number of Nomad clients")
	CreateWazuhCCSCmd.Flags().Int("temporal-servers", 1, "Number of Temporal servers")
	CreateWazuhCCSCmd.Flags().Int("nats-servers", 3, "Number of NATS servers")

	// Customer management flags
	CreateWazuhCCSCmd.Flags().Bool("add-customer", false, "Add a new customer")
	CreateWazuhCCSCmd.Flags().String("customer-config", "", "Path to customer configuration JSON file")
	CreateWazuhCCSCmd.Flags().String("customer-id", "", "Customer ID")
	CreateWazuhCCSCmd.Flags().String("company-name", "", "Company name")
	CreateWazuhCCSCmd.Flags().String("subdomain", "", "Customer subdomain")
	CreateWazuhCCSCmd.Flags().String("tier", "pro", "Customer tier (starter/pro/enterprise)")
	CreateWazuhCCSCmd.Flags().String("admin-email", "", "Admin email address")
	CreateWazuhCCSCmd.Flags().String("admin-name", "", "Admin full name")

	// Authentik configuration
	CreateWazuhCCSCmd.Flags().String("authentik-url", "", "Authentik URL")
	CreateWazuhCCSCmd.Flags().String("authentik-token", "", "Authentik API token")
	CreateWazuhCCSCmd.Flags().Bool("authentik-enabled", true, "Enable Authentik SSO")
}

func runCreateWazuhCCS(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting Wazuh MSSP platform deployment")

	// Check what operation to perform
	init, _ := cmd.Flags().GetBool("init")
	addCustomer, _ := cmd.Flags().GetBool("add-customer")

	if init {
		return initializePlatform(rc, cmd)
	} else if addCustomer {
		return addNewCustomer(rc, cmd)
	} else {
		// Default: show help
		return cmd.Help()
	}
}

func initializePlatform(rc *eos_io.RuntimeContext, cmd *cobra.Command) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Initializing Wazuh MSSP platform")

	// Parse platform configuration
	config, err := parsePlatformConfig(rc, cmd)
	if err != nil {
		return fmt.Errorf("failed to parse platform configuration: %w", err)
	}

	// Validate configuration
	if config.Domain == "" {
		logger.Info("terminal prompt: Please enter the platform domain (e.g., mssp.example.com)")
		domain, err := func() (string, error) { return "", fmt.Errorf("interactive input not implemented") }()
		if err != nil {
			return fmt.Errorf("failed to read domain: %w", err)
		}
		config.Domain = domain
	}

	// Validate Authentik configuration if enabled
	if config.Authentik.Enabled {
		if config.Authentik.URL == "" {
			logger.Info("terminal prompt: Please enter the Authentik URL")
			url, err := func() (string, error) { return "", fmt.Errorf("interactive input not implemented") }()
			if err != nil {
				return fmt.Errorf("failed to read Authentik URL: %w", err)
			}
			config.Authentik.URL = url
		}

		if config.Authentik.Token == "" {
			logger.Info("terminal prompt: Please enter the Authentik API token")
			token, err := func() (string, error) { return "", fmt.Errorf("interactive password input not implemented") }()
			if err != nil {
				return fmt.Errorf("failed to read Authentik token: %w", err)
			}
			config.Authentik.Token = token
		}
	}

	// Install platform
	if err := wazuh_mssp.InstallPlatform(rc, config); err != nil {
		return fmt.Errorf("platform installation failed: %w", err)
	}

	// Configure platform
	if err := wazuh_mssp.ConfigurePlatform(rc, config); err != nil {
		return fmt.Errorf("platform configuration failed: %w", err)
	}

	// Verify platform
	if err := wazuh_mssp.VerifyPlatform(rc); err != nil {
		return fmt.Errorf("platform verification failed: %w", err)
	}

	logger.Info("Wazuh MSSP platform initialized successfully",
		zap.String("domain", config.Domain))

	// Show next steps
	fmt.Println("\nPlatform initialized successfully!")
	fmt.Println("\nNext steps:")
	fmt.Println("1. Add customers: eos create wazuh-ccs --add-customer --customer-config customer.json")
	fmt.Println("2. Check status: eos read wazuh-ccs --status")
	fmt.Println("3. List customers: eos list wazuh-ccs")

	return nil
}

func addNewCustomer(rc *eos_io.RuntimeContext, cmd *cobra.Command) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Adding new customer to Wazuh MSSP platform")

	// Parse customer configuration
	customerConfig, err := parseCustomerConfig(rc, cmd)
	if err != nil {
		return fmt.Errorf("failed to parse customer configuration: %w", err)
	}

	// Validate required fields
	if customerConfig.ID == "" {
		logger.Info("terminal prompt: Please enter the customer ID (e.g., cust_12345)")
		id, err := func() (string, error) { return "", fmt.Errorf("interactive input not implemented") }()
		if err != nil {
			return fmt.Errorf("failed to read customer ID: %w", err)
		}
		customerConfig.ID = id
	}

	if customerConfig.CompanyName == "" {
		logger.Info("terminal prompt: Please enter the company name")
		name, err := func() (string, error) { return "", fmt.Errorf("interactive input not implemented") }()
		if err != nil {
			return fmt.Errorf("failed to read company name: %w", err)
		}
		customerConfig.CompanyName = name
	}

	if customerConfig.Subdomain == "" {
		logger.Info("terminal prompt: Please enter the customer subdomain")
		subdomain, err := func() (string, error) { return "", fmt.Errorf("interactive input not implemented") }()
		if err != nil {
			return fmt.Errorf("failed to read subdomain: %w", err)
		}
		customerConfig.Subdomain = subdomain
	}

	if customerConfig.AdminEmail == "" {
		logger.Info("terminal prompt: Please enter the admin email address")
		email, err := func() (string, error) { return "", fmt.Errorf("interactive input not implemented") }()
		if err != nil {
			return fmt.Errorf("failed to read admin email: %w", err)
		}
		customerConfig.AdminEmail = email
	}

	if customerConfig.AdminName == "" {
		logger.Info("terminal prompt: Please enter the admin full name")
		adminName, err := func() (string, error) { return "", fmt.Errorf("interactive input not implemented") }()
		if err != nil {
			return fmt.Errorf("failed to read admin name: %w", err)
		}
		customerConfig.AdminName = adminName
	}

	// Set defaults
	if customerConfig.WazuhConfig.Version == "" {
		version, err := wazuh_mssp.GetLatestWazuhVersion(rc)
		if err != nil {
			logger.Warn("Failed to get latest Wazuh version, using default",
				zap.Error(err),
				zap.String("default", wazuh_mssp.DefaultWazuhVersion))
			version = wazuh_mssp.DefaultWazuhVersion
		}
		customerConfig.WazuhConfig.Version = version
	}

	// Set component enablement based on tier
	customerConfig.WazuhConfig.IndexerEnabled = true
	customerConfig.WazuhConfig.ServerEnabled = true
	customerConfig.WazuhConfig.DashboardEnabled = customerConfig.Tier != wazuh_mssp.TierStarter

	// Provision customer
	if err := customer.ProvisionCustomer(rc, customerConfig); err != nil {
		return fmt.Errorf("customer provisioning failed: %w", err)
	}

	logger.Info("Customer added successfully",
		zap.String("customer_id", customerConfig.ID),
		zap.String("company", customerConfig.CompanyName),
		zap.String("tier", string(customerConfig.Tier)))

	// Show access information
	fmt.Printf("\nCustomer provisioned successfully!\n")
	fmt.Printf("\nAccess Details:\n")
	fmt.Printf("- Customer ID: %s\n", customerConfig.ID)
	fmt.Printf("- Dashboard URL: https://%s.<platform-domain>\n", customerConfig.Subdomain)
	fmt.Printf("- Admin Email: %s\n", customerConfig.AdminEmail)
	fmt.Printf("\nCredentials have been stored in Vault at:\n")
	fmt.Printf("- wazuh-mssp/customers/%s/wazuh/credentials\n", customerConfig.ID)

	return nil
}

func parsePlatformConfig(rc *eos_io.RuntimeContext, cmd *cobra.Command) (*wazuh_mssp.PlatformConfig, error) {
	config := &wazuh_mssp.PlatformConfig{}

	// Basic configuration
	config.Name, _ = cmd.Flags().GetString("platform-name")
	config.Environment, _ = cmd.Flags().GetString("environment")
	config.Datacenter, _ = cmd.Flags().GetString("datacenter")
	config.Domain, _ = cmd.Flags().GetString("domain")

	// Network configuration
	config.Network.PlatformCIDR, _ = cmd.Flags().GetString("platform-cidr")
	config.Network.CustomerCIDR, _ = cmd.Flags().GetString("customer-cidr")
	config.Network.VLANRange.Start, _ = cmd.Flags().GetInt("vlan-start")
	config.Network.VLANRange.End, _ = cmd.Flags().GetInt("vlan-end")

	// Nomad configuration
	config.Nomad.ServerCount, _ = cmd.Flags().GetInt("nomad-servers")
	config.Nomad.ClientCount, _ = cmd.Flags().GetInt("nomad-clients")
	config.Nomad.ServerResources = wazuh_mssp.ResourceConfig{
		VCPUs:  2,
		Memory: "4096",
		Disk:   "50G",
	}
	config.Nomad.ClientResources = wazuh_mssp.ResourceConfig{
		VCPUs:  8,
		Memory: "16384",
		Disk:   "200G",
	}

	// Temporal configuration
	config.Temporal.ServerCount, _ = cmd.Flags().GetInt("temporal-servers")
	config.Temporal.Namespace = "default"
	config.Temporal.ServerResources = wazuh_mssp.ResourceConfig{
		VCPUs:  4,
		Memory: "8192",
		Disk:   "100G",
	}
	config.Temporal.DatabaseResources = wazuh_mssp.ResourceConfig{
		VCPUs:  2,
		Memory: "4096",
		Disk:   "50G",
	}

	// NATS configuration
	config.NATS.ServerCount, _ = cmd.Flags().GetInt("nats-servers")
	config.NATS.EnableJetStream = true
	config.NATS.ServerResources = wazuh_mssp.ResourceConfig{
		VCPUs:  2,
		Memory: "4096",
		Disk:   "100G",
	}
	config.NATS.JetStreamConfig = wazuh_mssp.JetStreamConfig{
		MaxMemory: "4GB",
		MaxFile:   "100GB",
	}

	// CCS configuration
	config.CCS.IndexerResources = wazuh_mssp.ResourceConfig{
		VCPUs:  4,
		Memory: "8192",
		Disk:   "200G",
	}
	config.CCS.DashboardResources = wazuh_mssp.ResourceConfig{
		VCPUs:  2,
		Memory: "4096",
		Disk:   "50G",
	}

	// Authentik configuration
	config.Authentik.URL, _ = cmd.Flags().GetString("authentik-url")
	config.Authentik.Token, _ = cmd.Flags().GetString("authentik-token")
	config.Authentik.Enabled, _ = cmd.Flags().GetBool("authentik-enabled")

	// Storage configuration (default)
	config.Storage.Pools = map[string]wazuh_mssp.StoragePool{
		"default": {
			Path: "/var/lib/libvirt/images",
			Size: "1TB",
		},
		"fast": {
			Path: "/mnt/ssd/libvirt/images",
			Size: "500GB",
		},
	}

	return config, nil
}

func parseCustomerConfig(rc *eos_io.RuntimeContext, cmd *cobra.Command) (*wazuh_mssp.CustomerConfig, error) {
	config := &wazuh_mssp.CustomerConfig{}

	// Check if config file is provided
	configFile, _ := cmd.Flags().GetString("customer-config")
	if configFile != "" {
		// Read config from file
		data, err := os.ReadFile(configFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}

		if err := json.Unmarshal(data, config); err != nil {
			return nil, fmt.Errorf("failed to parse config file: %w", err)
		}
	} else {
		// Parse from flags
		config.ID, _ = cmd.Flags().GetString("customer-id")
		config.CompanyName, _ = cmd.Flags().GetString("company-name")
		config.Subdomain, _ = cmd.Flags().GetString("subdomain")
		config.AdminEmail, _ = cmd.Flags().GetString("admin-email")
		config.AdminName, _ = cmd.Flags().GetString("admin-name")

		// Parse tier
		tierStr, _ := cmd.Flags().GetString("tier")
		switch tierStr {
		case "starter":
			config.Tier = wazuh_mssp.TierStarter
		case "pro":
			config.Tier = wazuh_mssp.TierPro
		case "enterprise":
			config.Tier = wazuh_mssp.TierEnterprise
		default:
			return nil, eos_err.NewUserError("invalid tier specified (must be starter/pro/enterprise)")
		}
	}

	// Set default Wazuh configuration
	config.WazuhConfig = wazuh_mssp.WazuhDeploymentConfig{
		Version:          wazuh_mssp.DefaultWazuhVersion,
		IndexerEnabled:   true,
		ServerEnabled:    true,
		DashboardEnabled: config.Tier != wazuh_mssp.TierStarter,
	}

	return config, nil
}
