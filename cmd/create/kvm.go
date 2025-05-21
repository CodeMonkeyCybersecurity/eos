// cmd/create/kvm.go

package create

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/spf13/cobra"
)

var CreateKvmCmd = &cobra.Command{
	Use:   "kvm",
	Short: "Manage KVM installation and tenant provisioning",
	Long:  `Subcommands: install, tenant, template, etc.`,
	RunE:  eoscli.Wrap(nil), // Automatically shows help if no subcommand
}

func init() {
	CreateCmd.AddCommand(CreateKvmCmd)
	CreateKvmCmd.AddCommand(NewKvmInstallCmd())
	CreateKvmCmd.AddCommand(NewKvmTenantCmd())
	CreateKvmCmd.AddCommand(NewKvmTemplateCmd())
}
