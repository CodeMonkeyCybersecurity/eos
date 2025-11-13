//go:build linux

package create

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/kvm"
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

// createSecureUbuntuVM - Create VM with Consul agent by default (enable-by-default philosophy)
func createSecureUbuntuVM(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if Consul is disabled (default: false = Consul enabled)
	disableConsul, _ := cmd.Flags().GetBool("disable-consul")

	// Generate VM name
	// Check for --name/-N flag first
	customName, _ := cmd.Flags().GetString("name")
	var vmName string
	if customName != "" {
		vmName = customName
	} else {
		// Check if positional argument provided
		if len(args) > 0 {
			vmName = args[0]
		} else {
			// Auto-generate name
			vmName = kvm.GenerateVMName("eos-kvm")
		}
	}

	logger.Info("Creating Ubuntu VM with defaults (4GB RAM, 2 vCPUs, 40GB disk)",
		zap.String("name", vmName),
		zap.Bool("consul_enabled", !disableConsul))

	// ASSESS - Should we deploy Consul?
	if disableConsul {
		logger.Info("Consul agent deployment disabled by user",
			zap.String("vm_name", vmName),
			zap.String("impact", "Manual service discovery required"))

		// Create VM without Consul
		if err := kvm.CreateSimpleUbuntuVM(rc, vmName); err != nil {
			return fmt.Errorf("failed to create VM: %w", err)
		}
		return nil
	}

	// INTERVENE - Create VM with Consul agent (default behavior)
	logger.Info("Deploying VM with Consul agent for seamless service discovery (default behavior)",
		zap.String("vm_name", vmName),
		zap.String("disable_with", "Use --disable-consul to skip Consul deployment"))

	// Call the new CreateUbuntuVMWithConsul function (to be implemented)
	if err := kvm.CreateUbuntuVMWithConsul(rc, vmName); err != nil {
		return fmt.Errorf("failed to create VM with Consul: %w", err)
	}

	return nil
}
