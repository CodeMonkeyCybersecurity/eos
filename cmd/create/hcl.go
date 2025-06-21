// cmd/create/hcl.go

package create

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hashicorp"
	"github.com/spf13/cobra"
)

// SupportedHCLTools is now imported from the hashicorp package

var hclCmd = &cobra.Command{
	Use:   "hcl [tool]",
	Short: "Install HashiCorp tools (terraform, vault, consul, nomad, packer, boundary)",
	Long: fmt.Sprintf(`Install HashiCorp tools using their official APT repository.

Supported tools: %s

Examples:
  eos create hcl terraform    # Install only Terraform
  eos create hcl all          # Install all supported tools

Use the specific tool commands for simpler syntax:
  eos create terraform        # Same as: eos create hcl terraform
  eos create vault           # Same as: eos create hcl vault`, hashicorp.GetSupportedToolsString()),
	Args: cobra.ExactArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		tool := args[0]

		if tool == "all" {
			return hashicorp.InstallAllTools(rc)
		}

		return hashicorp.InstallTool(rc, tool)
	}),
}

var terraformCmd = &cobra.Command{
	Use:   "terraform",
	Short: "Install Terraform",
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		return hashicorp.InstallTool(rc, "terraform")
	}),
}

var consulCmd = &cobra.Command{
	Use:   "consul",
	Short: "Install Consul",
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		return hashicorp.InstallTool(rc, "consul")
	}),
}

var nomadCmd = &cobra.Command{
	Use:   "nomad",
	Short: "Install Nomad",
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		return hashicorp.InstallTool(rc, "nomad")
	}),
}

var packerCmd = &cobra.Command{
	Use:   "packer",
	Short: "Install Packer",
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		return hashicorp.InstallTool(rc, "packer")
	}),
}

var boundaryCmd = &cobra.Command{
	Use:   "boundary",
	Short: "Install Boundary",
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		return hashicorp.InstallTool(rc, "boundary")
	}),
}

func init() {
	CreateCmd.AddCommand(hclCmd)
	CreateCmd.AddCommand(terraformCmd)
	CreateCmd.AddCommand(consulCmd)
	CreateCmd.AddCommand(nomadCmd)
	CreateCmd.AddCommand(packerCmd)
	CreateCmd.AddCommand(boundaryCmd)
}

// All helper functions have been moved to pkg/hashicorp package for better code organization,
// testability, and reusability across the codebase. The functions include:
//
// - hashicorp.InstallTool() - Install a single HashiCorp tool
// - hashicorp.InstallAllTools() - Install all supported HashiCorp tools
// - hashicorp.InstallGPGKey() - Install and verify HashiCorp GPG key
// - hashicorp.AddRepository() - Add HashiCorp package repository
// - hashicorp.VerifyInstallation() - Verify tool installation
// - hashicorp.IsToolSupported() - Check if a tool is supported
// - hashicorp.GetSupportedToolsString() - Get comma-separated list of tools
//
// This refactoring improves:
// - Code reusability across different commands
// - Testability with comprehensive unit tests
// - Separation of concerns (CLI vs business logic)
// - Error handling with structured logging and cerr wrapping
// - API consistency using the execute package for safe command execution
