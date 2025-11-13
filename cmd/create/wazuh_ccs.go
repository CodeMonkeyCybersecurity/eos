// cmd/create/wazuh_ccs.go
package create

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/wazuh/cluster"
	"github.com/spf13/cobra"
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
	RunE: eos_cli.Wrap(cluster.RunCreateWazuhCCS),
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
