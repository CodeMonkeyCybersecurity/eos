package cluster

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/wazuh"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

func RunCreateWazuhCCS(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting Wazuh MSSP platform deployment")

	// Check what operation to perform
	init, _ := cmd.Flags().GetBool("init")
	addCustomer, _ := cmd.Flags().GetBool("add-customer")

	if init {
		return InitializePlatform(rc, cmd)
	} else if addCustomer {
		return AddNewCustomer(rc, cmd)
	} else {
		// Default: show help
		return cmd.Help()
	}
}

func InitializePlatform(rc *eos_io.RuntimeContext, cmd *cobra.Command) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Initializing Wazuh MSSP platform")

	// Parse platform configuration
	config, err := ParsePlatformConfig(rc, cmd)
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
	if err := wazuh.InstallPlatform(rc, config); err != nil {
		return fmt.Errorf("platform installation failed: %w", err)
	}

	// Configure platform
	if err := wazuh.ConfigurePlatform(rc, config); err != nil {
		return fmt.Errorf("platform configuration failed: %w", err)
	}

	// Verify platform
	if err := wazuh.VerifyPlatform(rc); err != nil {
		return fmt.Errorf("platform verification failed: %w", err)
	}

	logger.Info("Wazuh MSSP platform initialized successfully",
		zap.String("domain", config.Domain))

	// Show next steps
	logger.Info("terminal prompt: \nPlatform initialized successfully!")
	logger.Info("terminal prompt: \nNext steps:")
	logger.Info("terminal prompt: 1. Add customers: eos create wazuh-ccs --add-customer --customer-config customer.json")
	logger.Info("terminal prompt: 2. Check status: eos read wazuh-ccs --status")
	logger.Info("terminal prompt: 3. List customers: eos list wazuh-ccs")

	return nil
}

func AddNewCustomer(rc *eos_io.RuntimeContext, cmd *cobra.Command) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Adding new customer to Wazuh MSSP platform")

	// Parse customer configuration
	customerConfig, err := ParseCustomerConfig(rc, cmd)
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
		version, err := wazuh.GetLatestWazuhVersion(rc)
		if err != nil {
			logger.Warn("Failed to get latest Wazuh version, using default",
				zap.Error(err),
				zap.String("default", wazuh.DefaultWazuhVersion))
			version = wazuh.DefaultWazuhVersion
		}
		customerConfig.WazuhConfig.Version = version
	}

	// Set component enablement based on tier
	customerConfig.WazuhConfig.IndexerEnabled = true
	customerConfig.WazuhConfig.ServerEnabled = true
	customerConfig.WazuhConfig.DashboardEnabled = customerConfig.Tier != wazuh.TierStarter

	// Provision customer
	if err := wazuh.ProvisionCustomer(rc, customerConfig); err != nil {
		return fmt.Errorf("customer provisioning failed: %w", err)
	}

	logger.Info("Customer added successfully",
		zap.String("customer_id", customerConfig.ID),
		zap.String("company", customerConfig.CompanyName),
		zap.String("tier", customerConfig.Tier.String()))

	// Show access information
	logger.Info("terminal prompt: Customer provisioned successfully!")
	logger.Info("terminal prompt: Access Details:")
	logger.Info(fmt.Sprintf("terminal prompt: - Customer ID: %s", customerConfig.ID))
	logger.Info(fmt.Sprintf("terminal prompt: - Dashboard URL: https://%s.<platform-domain>", customerConfig.Subdomain))
	logger.Info(fmt.Sprintf("terminal prompt: - Admin Email: %s", customerConfig.AdminEmail))
	logger.Info("terminal prompt: Credentials have been stored in Vault at:")
	logger.Info(fmt.Sprintf("terminal prompt: - wazuh-mssp/customers/%s/wazuh/credentials", customerConfig.ID))

	return nil
}

func ParsePlatformConfig(_ *eos_io.RuntimeContext, cmd *cobra.Command) (*wazuh.PlatformConfig, error) {
	config := &wazuh.PlatformConfig{}

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
	config.Nomad.ServerResources = wazuh.ResourceConfig{
		VCPUs:  2,
		Memory: "4096",
		Disk:   "50G",
	}
	config.Nomad.ClientResources = wazuh.ResourceConfig{
		VCPUs:  8,
		Memory: "16384",
		Disk:   "200G",
	}

	// Temporal configuration
	config.Temporal.ServerCount, _ = cmd.Flags().GetInt("temporal-servers")
	config.Temporal.Namespace = "default"
	config.Temporal.ServerResources = wazuh.ResourceConfig{
		VCPUs:  4,
		Memory: "8192",
		Disk:   "100G",
	}
	config.Temporal.DatabaseResources = wazuh.ResourceConfig{
		VCPUs:  2,
		Memory: "4096",
		Disk:   "50G",
	}

	// NATS configuration
	config.NATS.ServerCount, _ = cmd.Flags().GetInt("nats-servers")
	config.NATS.EnableJetStream = true
	config.NATS.ServerResources = wazuh.ResourceConfig{
		VCPUs:  2,
		Memory: "4096",
		Disk:   "100G",
	}
	config.NATS.JetStreamConfig = wazuh.JetStreamConfig{
		MaxMemory: "4GB",
		MaxFile:   "100GB",
	}

	// CCS configuration
	config.CCS.IndexerResources = wazuh.ResourceConfig{
		VCPUs:  4,
		Memory: "8192",
		Disk:   "200G",
	}
	config.CCS.DashboardResources = wazuh.ResourceConfig{
		VCPUs:  2,
		Memory: "4096",
		Disk:   "50G",
	}

	// Authentik configuration
	config.Authentik.URL, _ = cmd.Flags().GetString("authentik-url")
	config.Authentik.Token, _ = cmd.Flags().GetString("authentik-token")
	config.Authentik.Enabled, _ = cmd.Flags().GetBool("authentik-enabled")

	// Storage configuration (default)
	config.Storage.Pools = map[string]wazuh.StoragePool{
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

func ParseCustomerConfig(_ *eos_io.RuntimeContext, cmd *cobra.Command) (*wazuh.CustomerConfig, error) {
	config := &wazuh.CustomerConfig{}

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
			config.Tier = wazuh.TierStarter
		case "pro":
			config.Tier = wazuh.TierPro
		case "enterprise":
			config.Tier = wazuh.TierEnterprise
		default:
			return nil, eos_err.NewUserError("invalid tier specified (must be starter/pro/enterprise)")
		}
	}

	// Set default Wazuh configuration
	config.WazuhConfig = wazuh.WazuhDeploymentConfig{
		Version:          wazuh.DefaultWazuhVersion,
		IndexerEnabled:   true,
		ServerEnabled:    true,
		DashboardEnabled: config.Tier != wazuh.TierStarter,
	}

	return config, nil
}
