package inspect

import (
	"github.com/spf13/cobra"
)

// InspectCmd groups commands related to infrastructure inspection and analysis
var InspectCmd = &cobra.Command{
	Use:   "inspect",
	Short: "Inspect infrastructure, services, and system resources",
	Long: `Commands for analyzing and inspecting various aspects of your infrastructure.

Includes tools for:
- Docker container and network analysis
- Terraform infrastructure visualization
- KVM virtualization inspection
- Hetzner cloud resource analysis
- Service health and dependency mapping

Each inspect command provides detailed analysis with structured output
and secure integration with HashiCorp Vault for metadata storage.`,
}

func init() {
	// The terraform-graph command is already added in terraform_graph.go init()
	// Other inspect commands can be added here as they are implemented
}
