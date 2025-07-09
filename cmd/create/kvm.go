// cmd/create/kvm.go

package create

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/spf13/cobra"
)

var CreateKvmCmd = &cobra.Command{
	Use:   "kvm",
	Short: "Manage KVM installation and tenant provisioning",
	Long:  `Subcommands: install, tenant, template, etc.`,
	RunE:  eos_cli.Wrap(nil), // Automatically shows help if no subcommand
}

func init() {
	CreateCmd.AddCommand(CreateKvmCmd)
	CreateKvmCmd.AddCommand(kvmInstallCmd)
	CreateKvmCmd.AddCommand(kvmTenantCmd)
	CreateKvmCmd.AddCommand(kvmTemplateCmd)
}
