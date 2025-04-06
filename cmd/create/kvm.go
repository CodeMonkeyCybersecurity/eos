// cmd/deploy/kvm.go
package create

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var CreateKvmCmd = &cobra.Command{
	Use:   "kvm",
	Short: "Install and configure KVM and libvirt",
	Long:  "Installs KVM, ensures libvirtd is running, sets ACLs for ISO directory, and optionally autostarts the default libvirt network.",
	RunE:  runDeployKVM,
}

func init() {
	CreateCmd.AddCommand(CreateKvmCmd)
}

func runDeployKVM(cmd *cobra.Command, args []string) error {
	log := logger.L()

	if os.Geteuid() != 0 {
		return fmt.Errorf("this command must be run as root")
	}

	if err := system.InstallKVM(); err != nil {
		return err
	}

	if err := system.EnsureLibvirtd(); err != nil {
		return err
	}

	isoDir := interaction.PromptConfirmOrValue(
		"The hypervisor needs access to an ISO directory",
		"/srv/iso",
	)

	if info, err := os.Stat(isoDir); err == nil && info.IsDir() {
		system.SetLibvirtACL(isoDir)
	} else {
		log.Warn("ISO directory not found or invalid", zap.String("path", isoDir))
	}

	if interaction.PromptYesNo("Would you like to autostart the default libvirt network?", false) {
		system.SetLibvirtDefaultNetworkAutostart()
	} else {
		fmt.Println("Skipping network autostart. You can run 'virsh net-start default' later if needed.")
	}

	fmt.Println("✅ KVM setup completed.")
	return nil
}
