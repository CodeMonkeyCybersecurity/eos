package create

import (
	"fmt"
	"os"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var (
	enableBridge bool
)

// CreateKvmCmd installs and configures KVM and libvirt.
var CreateKvmCmd = &cobra.Command{
	Use:   "kvm",
	Short: "Install and configure KVM and libvirt",
	Long:  "Installs KVM, ensures libvirtd is running, sets ACLs for an ISO directory, and optionally autostarts the default libvirt network.",
	RunE:  eos.Wrap(runDeployKVM),
}

func init() {
	CreateCmd.AddCommand(CreateKvmCmd)
	CreateKvmCmd.Flags().BoolVar(&enableBridge, "network-bridge", false, "Configure a bridge (br0) using the default network interface via Netplan")
}

func runDeployKVM(cmd *cobra.Command, args []string) error {
	log := logger.L()

	// Ensure the command is run as root.
	if os.Geteuid() != 0 {
		return fmt.Errorf("this command must be run as root")
	}

	// Install KVM.
	if err := system.InstallKVM(); err != nil {
		return err
	}

	// Configure network bridge if requested.
	if enableBridge {
		fmt.Println("🛠️  Configuring network bridge...")
		if err := system.ConfigureKVMBridge(); err != nil {
			return fmt.Errorf("failed to configure network bridge: %w", err)
		}
	}

	// Ensure that libvirtd is running.
	if err := system.EnsureLibvirtd(); err != nil {
		return err
	}

	// Prompt for ISO directory.
	isoDir := interaction.PromptConfirmOrValue("The hypervisor needs access to an ISO directory", "/srv/iso")
	if info, err := os.Stat(isoDir); err == nil && info.IsDir() {
		system.SetLibvirtACL(isoDir)
	} else {
		log.Warn("ISO directory not found or invalid", zap.String("path", isoDir))
	}

	// Ask if the user wants to autostart the default libvirt network.
	if interaction.PromptYesNo("Would you like to autostart the default libvirt network?", false) {
		system.SetLibvirtDefaultNetworkAutostart()
	} else {
		fmt.Println("Skipping network autostart. You can run 'virsh net-start default' later if needed.")
	}

	fmt.Println("✅ KVM setup completed.")
	return nil
}
