// cmd/create/qemu_guest.go
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

// CreateQemuGuestCmd installs QEMU Guest Agent
var CreateQemuGuestCmd = &cobra.Command{
	Use:   "qemu-guest-agent",
	Short: "Install QEMU Guest Agent",
	Long: `Install QEMU Guest Agent for enhanced VM management.

The QEMU Guest Agent is a helper daemon that exchanges information between the guest
and the host. It enables the host to issue commands to the guest operating system,
such as freezing/thawing filesystems for consistent snapshots, getting guest network
information, and safely shutting down the guest.

Examples:
  eos create qemu-guest-agent           # Install QEMU Guest Agent
  eos create qemu-guest-agent --dry-run # Test installation`,

	Aliases: []string{"qemu-ga", "qga"},

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		// Get flags
		dryRun, _ := cmd.Flags().GetBool("dry-run")

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

			logger.Info("terminal prompt: 📝 Features Enabled:")
			logger.Info("terminal prompt:    - Guest shutdown/reboot from host")
			logger.Info("terminal prompt:    - File system freeze/thaw for snapshots")
			logger.Info("terminal prompt:    - Guest network information")
			logger.Info("terminal prompt:    - Guest exec commands")
			logger.Info("terminal prompt:    - Time synchronization")

			logger.Info("terminal prompt: 💡 Hypervisor Configuration:")
			logger.Info("terminal prompt:    - For Proxmox: Enable QEMU Guest Agent in VM options")
			logger.Info("terminal prompt:    - For libvirt: Add channel device for guest agent")
			logger.Info("terminal prompt:    - Check status: eos status qemu-guest-agent")
		} else {
			logger.Error("QEMU Guest Agent installation failed", zap.String("error", result.Error))
			logger.Info("terminal prompt: ❌ QEMU Guest Agent Installation Failed!")
			logger.Info(fmt.Sprintf("terminal prompt: Error: %s", result.Error))

			if len(result.Steps) > 0 {
				logger.Info("terminal prompt: Installation Steps:")
				for _, step := range result.Steps {
					status := ""
					switch step.Status {
					case "failed":
						status = "❌"
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
	}),
}

func init() {
	CreateCmd.AddCommand(CreateQemuGuestCmd)

	CreateQemuGuestCmd.Flags().Bool("dry-run", false, "Simulate installation without making changes")
}
