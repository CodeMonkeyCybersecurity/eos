// cmd/create/consul_native.go

package create

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/spf13/cobra"
)

var CreateConsulCmd = &cobra.Command{
	Use:   "consul",
	Short: "Install and configure HashiCorp Consul using native methods",
	Long: `Install and configure HashiCorp Consul using native installation methods.

This command installs Consul directly without using configuration management tools,
eliminating circular dependencies and simplifying the installation process.

INSTALLATION METHODS:
• Repository: Use HashiCorp's official APT repository (default)
• Binary: Download and install binary directly from releases.hashicorp.com

FEATURES:
• Service discovery with DNS and HTTP API
• Health monitoring and automatic failover
• Consul Connect service mesh ready
• Automatic Vault integration if available
• Production-ready security settings
• Idempotent installation (safe to run multiple times)

CONFIGURATION:
• HTTP API on port ` + fmt.Sprintf("%d", shared.PortConsul) + `
• DNS service discovery on port 8600
• gRPC on port 8502
• UI enabled by default
• Consul Connect enabled for service mesh

EXAMPLES:
  # Install Consul server using APT repository (recommended)
  eos create consul

  # Install Consul client (agent mode)
  eos create consul --client

  # Install specific version via binary download
  eos create consul --binary --version 1.17.1

  # Force reconfiguration of existing Consul
  eos create consul --force

  # Clean install (removes existing data)
  eos create consul --clean

  # Install with custom datacenter name
  eos create consul --datacenter production

  # Install without Vault integration
  eos create consul --no-vault-integration`,
	RunE: eos_cli.Wrap(consul.RunCreateConsul),
}

func init() {
	CreateConsulCmd.Flags().StringVarP(&consul.ConsulDatacenter, "datacenter", "d", "dc1",
		"Datacenter name for Consul cluster")
	CreateConsulCmd.Flags().StringVar(&consul.ConsulBindAddr, "bind-addr", "",
		"Network address to bind to (auto-detects primary interface if not specified)")
	CreateConsulCmd.Flags().BoolVar(&consul.ConsulServer, "server", false,
		"Install as Consul server (default if neither --server nor --client specified)")
	CreateConsulCmd.Flags().BoolVar(&consul.ConsulClient, "client", false,
		"Install as Consul client (agent mode)")
	CreateConsulCmd.Flags().BoolVar(&consul.ConsulNoVault, "no-vault-integration", false,
		"Disable automatic Vault integration")
	CreateConsulCmd.Flags().BoolVar(&consul.ConsulDebug, "debug", false,
		"Enable debug logging for Consul")
	CreateConsulCmd.Flags().BoolVar(&consul.ConsulForce, "force", false,
		"Force reconfiguration even if Consul is running (backs up existing config)")
	CreateConsulCmd.Flags().BoolVar(&consul.ConsulClean, "clean", false,
		"DESTRUCTIVE: Remove all data and perform clean installation (requires confirmation)")
	CreateConsulCmd.Flags().BoolVar(&consul.ConsulBinary, "binary", false,
		"Use direct binary download instead of APT repository")
	CreateConsulCmd.Flags().StringVar(&consul.ConsulVersion, "version", "latest",
		"Consul version to install (default: latest)")

	// Register the command with the create command
	CreateCmd.AddCommand(CreateConsulCmd)
}
