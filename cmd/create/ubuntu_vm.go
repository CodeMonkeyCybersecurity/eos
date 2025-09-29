package create

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/terraform/kvm"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// NewSecureUbuntuVMCmd represents the create ubuntu-vm command
var NewSecureUbuntuVMCmd = &cobra.Command{
	Use:   "ubuntu-vm",
	Short: "Create a new Ubuntu VM with defaults (4GB RAM, 2 vCPUs, 40GB disk)",
	Long: `Create a new Ubuntu VM with hardcoded defaults.
The VM will be named eos-vm-{timestamp}-{8randomchars}.

Examples:
  # Create a VM with auto-generated name
  eos create ubuntu-vm`,
	Args: cobra.NoArgs,
	RunE: eos_cli.Wrap(createSecureUbuntuVM),
}

func init() {
	// Register the command
	CreateCmd.AddCommand(NewSecureUbuntuVMCmd)
}

// createSecureUbuntuVM - SIMPLIFIED to just create a basic VM
func createSecureUbuntuVM(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	// Generate VM name
	vmName := kvm.GenerateVMName("eos-kvm")

	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Creating Ubuntu VM with defaults (4GB RAM, 2 vCPUs, 40GB disk)",
		zap.String("name", vmName))

	// Just create the VM with hardcoded defaults
	return kvm.CreateSimpleUbuntuVM(rc, vmName)
}