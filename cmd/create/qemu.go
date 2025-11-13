// cmd/create/qemu.go
package create

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/services/service_installation"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var (
	qemuGuestAgent bool
	qemuDryRun     bool
)

// CreateQemuCmd creates QEMU-related resources
var CreateQemuCmd = &cobra.Command{
	Use:   "qemu",
	Short: "Create QEMU-related resources (guest agent, etc.)",
	Long: `Create and configure QEMU-related resources.

The QEMU Guest Agent is a helper daemon that exchanges information between the guest
and the host. It enables the host to issue commands to the guest operating system,
such as freezing/thawing filesystems for consistent snapshots, getting guest network
information, and safely shutting down the guest.

FLAGS:
  --guest-agent    Install QEMU Guest Agent in current VM
  --dry-run        Simulate installation without making changes

EXAMPLES:
  # Install QEMU Guest Agent (run inside VM)
  eos create qemu --guest-agent

  # Test installation without changes
  eos create qemu --guest-agent --dry-run

REQUIREMENTS:
  - Run this command inside the guest VM (not on the hypervisor)
  - Requires root/sudo access
  - Works with Ubuntu/Debian and RHEL/CentOS/Rocky Linux`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		// Determine which operation to perform
		if qemuGuestAgent {
			return installGuestAgent(rc, qemuDryRun)
		}

		// No operation specified - show help
		logger.Info("No operation specified. Use --guest-agent to install guest agent")
		return cmd.Help()
	}),
}

func init() {
	CreateQemuCmd.Flags().BoolVar(&qemuGuestAgent, "guest-agent", false, "Install QEMU Guest Agent")
	CreateQemuCmd.Flags().BoolVar(&qemuDryRun, "dry-run", false, "Simulate installation without making changes")

	CreateCmd.AddCommand(CreateQemuCmd)
}

// installGuestAgent performs the guest agent installation
func installGuestAgent(rc *eos_io.RuntimeContext, dryRun bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Installing QEMU Guest Agent",
		zap.Bool("dry_run", dryRun))

	// Build installation options
	options := &service_installation.ServiceInstallOptions{
		Name:        "qemu-guest-agent",
		Type:        service_installation.ServiceTypeQemuGuest,
		Method:      service_installation.MethodNative,
		DryRun:      dryRun,
		Environment: make(map[string]string),
		Config:      make(map[string]string),
	}

	// Perform installation
	result, err := service_installation.InstallService(rc, options)
	if err != nil {
		return fmt.Errorf("qemu guest agent installation failed: %w", err)
	}

	// Output result
	if result.Success {
		logger.Info("QEMU Guest Agent installation completed successfully",
			zap.String("version", result.Version),
			zap.Duration("duration", result.Duration))

		logger.Info("terminal prompt: QEMU Guest Agent Installation Complete!")
		logger.Info("terminal prompt:  Service Details:")
		logger.Info(fmt.Sprintf("terminal prompt:    Method: %s", result.Method))
		logger.Info(fmt.Sprintf("terminal prompt:    Duration: %s", result.Duration))

		if result.Version != "" {
			logger.Info(fmt.Sprintf("terminal prompt:    Version: %s", result.Version))
		}

		logger.Info("terminal prompt:  Features Enabled:")
		logger.Info("terminal prompt:    - Guest shutdown/reboot from host")
		logger.Info("terminal prompt:    - File system freeze/thaw for snapshots")
		logger.Info("terminal prompt:    - Guest network information")
		logger.Info("terminal prompt:    - Guest exec commands (enables Tailscale IP detection)")
		logger.Info("terminal prompt:    - Time synchronization")

		logger.Info("terminal prompt:  Next Steps:")
		logger.Info("terminal prompt:    1. Ensure VM has guest agent channel: eos update kvm --add --guest-agent --name <vm>")
		logger.Info("terminal prompt:    2. Enable guest-exec: eos update kvm --enable --guest-exec --name <vm>")
		logger.Info("terminal prompt:    3. Verify with: eos ls kvm")
	} else {
		logger.Error("QEMU Guest Agent installation failed", zap.String("error", result.Error))
		logger.Info("terminal prompt:  QEMU Guest Agent Installation Failed!")
		logger.Info(fmt.Sprintf("terminal prompt: Error: %s", result.Error))

		if len(result.Steps) > 0 {
			logger.Info("terminal prompt: Installation Steps:")
			for _, step := range result.Steps {
				status := ""
				switch step.Status {
				case "failed":
					status = "✗"
				case "running":
					status = "⏳"
				}
				logger.Info(fmt.Sprintf("terminal prompt:    %s %s (%s)", status, step.Name, step.Duration))
				if step.Error != "" {
					logger.Info(fmt.Sprintf("terminal prompt:       Error: %s", step.Error))
				}
			}
		}
	}

	return nil
}
