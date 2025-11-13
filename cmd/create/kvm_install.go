//go:build linux

// cmd/create/kvm_install.go

package create

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/kvm"
	"github.com/spf13/cobra"
)

// kvmInstallCmd installs KVM and configures hypervisor settings
var kvmInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Install KVM and configure hypervisor settings",
	Long: `Install KVM and configure hypervisor settings.

This command installs KVM (Kernel-based Virtual Machine) and sets up
the hypervisor environment with necessary configurations.

Examples:
  eos create kvm install                    # Interactive installation
  eos create kvm install --yes             # Non-interactive with defaults
  eos create kvm install --iso /path/to/iso # Specify ISO directory
  eos create kvm install --autostart       # Enable autostart for default network
  eos create kvm install --network-bridge  # Configure bridge networking`,

	RunE: eos.Wrap(kvm.RunCreateKvmInstall),
}

func init() {
	// Set up flags for kvmInstallCmd
	kvmInstallCmd.Flags().Bool("yes", false, "Run non-interactively with defaults")
	kvmInstallCmd.Flags().String("iso", "", "Path to ISO directory")
	kvmInstallCmd.Flags().Bool("autostart", false, "Enable autostart for the default libvirt network")
	kvmInstallCmd.Flags().Bool("network-bridge", false, "Configure a bridge (br0) using Netplan")
}
