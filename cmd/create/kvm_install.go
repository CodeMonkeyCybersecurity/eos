// cmd/create/kvm_install.go

package create

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/kvm"
	"github.com/spf13/cobra"
)

// NewCreateKvmInstallCmd returns the cobra.Command for 'eos create kvm install'
func NewKvmInstallCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Install KVM and configure hypervisor settings",
		RunE:  eos.Wrap(kvm.RunCreateKvmInstall),
	}

	cmd.Flags().Bool("yes", false, "Run non-interactively with defaults")
	cmd.Flags().String("iso", "", "Path to ISO directory")
	cmd.Flags().Bool("autostart", false, "Enable autostart for the default libvirt network")
	cmd.Flags().Bool("network-bridge", false, "Configure a bridge (br0) using Netplan")

	return cmd
}
