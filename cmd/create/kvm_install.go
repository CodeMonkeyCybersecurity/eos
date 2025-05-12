// cmd/create/kvm_install.go

package create

import (
	"fmt"
	"os"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eosio"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/kvm"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// NewCreateKvmInstallCmd returns the cobra.Command for 'eos create kvm install'
func NewKvmInstallCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Install KVM and configure hypervisor settings",
		RunE:  eos.Wrap(runCreateKvmInstall),
	}

	cmd.Flags().Bool("yes", false, "Run non-interactively with defaults")
	cmd.Flags().String("iso", "", "Path to ISO directory")
	cmd.Flags().Bool("autostart", false, "Enable autostart for the default libvirt network")
	cmd.Flags().Bool("network-bridge", false, "Configure a bridge (br0) using Netplan")

	return cmd
}

func runCreateKvmInstall(ctx *eosio.RuntimeContext, cmd *cobra.Command, args []string) error {
	log := ctx.Log.Named("kvm")

	if os.Geteuid() != 0 {
		log.Error("KVM setup must be run as root")
		return fmt.Errorf("this command must be run as root")
	}

	nonInteractive, _ := cmd.Flags().GetBool("yes")
	isoOverride, _ := cmd.Flags().GetString("iso")
	enableBridge, _ := cmd.Flags().GetBool("network-bridge")
	autostartFlag, _ := cmd.Flags().GetBool("autostart")
	autostartExplicit := cmd.Flags().Changed("autostart")

	log.Info("📦 Installing KVM and libvirt packages...")
	if err := kvm.InstallKVM(); err != nil {
		log.Error("Failed to install KVM", zap.Error(err))
		return err
	}
	log.Info("✅ KVM installation complete")

	if enableBridge {
		log.Info("🛠️  Configuring network bridge...")
		if err := kvm.ConfigureKVMBridge(); err != nil {
			log.Error("Failed to configure network bridge", zap.Error(err))
			return fmt.Errorf("failed to configure network bridge: %w", err)
		}
		log.Info("✅ Network bridge configured")
	}

	log.Info("🔧 Ensuring libvirtd is running...")
	if err := kvm.EnsureLibvirtd(); err != nil {
		log.Error("libvirtd is not running", zap.Error(err))
		return err
	}
	log.Info("✅ libvirtd is active")

	isoDir := resolveIsoDir(log, nonInteractive, isoOverride)
	if info, err := os.Stat(isoDir); err == nil && info.IsDir() {
		log.Info("🔐 Setting ACL for ISO directory", zap.String("path", isoDir))
		kvm.SetLibvirtACL(isoDir)
	} else {
		log.Warn("⚠️ ISO directory not found or invalid", zap.String("path", isoDir))
	}

	if resolveAutostart(log, nonInteractive, autostartExplicit, autostartFlag) {
		log.Info("⚙️  Enabling autostart for default libvirt network")
		kvm.SetLibvirtDefaultNetworkAutostart()
	} else {
		log.Info("Skipping autostart — you can run 'virsh net-start default' manually if needed.")
	}

	log.Info("✅ KVM setup completed successfully")
	return nil
}

func resolveIsoDir(log *zap.Logger, nonInteractive bool, isoOverride string) string {
	if isoOverride != "" {
		log.Info("ISO path provided via flag", zap.String("iso_dir", isoOverride))
		return isoOverride
	}
	if nonInteractive {
		log.Info("Using default ISO directory (non-interactive)", zap.String("iso_dir", "/srv/iso"))
		return "/srv/iso"
	}
	val := interaction.PromptConfirmOrValue("The hypervisor needs access to an ISO directory", "/srv/iso")
	log.Info("ISO directory selected", zap.String("iso_dir", val))
	return val
}

func resolveAutostart(log *zap.Logger, nonInteractive, explicitlySet bool, value bool) bool {
	if explicitlySet {
		log.Info("Autostart explicitly provided via flag", zap.Bool("autostart", value))
		return value
	}
	if nonInteractive {
		log.Info("Assuming 'no' for autostart (non-interactive)")
		return false
	}
	resp := interaction.PromptYesNo("Would you like to autostart the default libvirt network?", false)
	log.Info("User autostart choice", zap.Bool("autostart", resp))
	return resp
}
