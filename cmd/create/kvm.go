package create

import (
	"fmt"
	"os"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var enableBridge bool

var CreateKvmCmd = &cobra.Command{
	Use:   "kvm",
	Short: "Install and configure KVM and libvirt",
	Long: `Installs KVM, ensures libvirtd is running, sets ACLs for an ISO directory,
and optionally autostarts the default libvirt network.`,
	RunE: eos.Wrap(runDeployKVM),
}

func init() {
	CreateCmd.AddCommand(CreateKvmCmd)
	CreateKvmCmd.Flags().BoolVar(&enableBridge, "network-bridge", false, "Configure a bridge (br0) using the default network interface via Netplan")
}

func runDeployKVM(ctx *eos.RuntimeContext, cmd *cobra.Command, args []string) error {
	log := ctx.Log.Named("kvm")

	if os.Geteuid() != 0 {
		log.Error("KVM setup must be run as root")
		return fmt.Errorf("this command must be run as root")
	}

	log.Info("📦 Installing KVM and libvirt packages...")
	if err := system.InstallKVM(); err != nil {
		log.Error("Failed to install KVM", zap.Error(err))
		return err
	}
	log.Info("✅ KVM installation complete")

	if enableBridge {
		log.Info("🛠️  Configuring network bridge...")
		if err := system.ConfigureKVMBridge(); err != nil {
			log.Error("Failed to configure network bridge", zap.Error(err))
			return fmt.Errorf("failed to configure network bridge: %w", err)
		}
		log.Info("✅ Network bridge configured")
	}

	log.Info("🔧 Ensuring libvirtd is running...")
	if err := system.EnsureLibvirtd(); err != nil {
		log.Error("libvirtd is not running", zap.Error(err))
		return err
	}
	log.Info("✅ libvirtd is active")

	isoDir := interaction.PromptConfirmOrValue("The hypervisor needs access to an ISO directory", "/srv/iso", log)
	if info, err := os.Stat(isoDir); err == nil && info.IsDir() {
		log.Info("🔐 Setting ACL for ISO directory", zap.String("path", isoDir))
		system.SetLibvirtACL(isoDir)
	} else {
		log.Warn("ISO directory not found or invalid", zap.String("path", isoDir))
	}

	if interaction.PromptYesNo("Would you like to autostart the default libvirt network?", false, log) {
		log.Info("⚙️  Enabling autostart for default libvirt network")
		system.SetLibvirtDefaultNetworkAutostart()
	} else {
		log.Info("Skipping autostart — you can run 'virsh net-start default' manually if needed.")
	}

	log.Info("✅ KVM setup completed successfully")
	return nil
}
