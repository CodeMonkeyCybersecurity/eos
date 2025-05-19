package create

import (
	"github.com/spf13/cobra"
)

var CreateKvmCmd = &cobra.Command{
	Use:   "kvm",
	Short: "Manage KVM installation and tenant provisioning",
	Long:  `Subcommands: install, tenant, template, etc.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return cmd.Help()
	},
}

func init() {
	CreateCmd.AddCommand(CreateKvmCmd)
	CreateKvmCmd.AddCommand(NewKvmInstallCmd())
	CreateKvmCmd.AddCommand(NewKvmTenantCmd())
	CreateKvmCmd.AddCommand(NewKvmTemplateCmd())
}
