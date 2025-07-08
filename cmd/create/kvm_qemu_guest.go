// cmd/create/qemu_guest.go
package create

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/service_installation"
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

		manager := service_installation.NewServiceInstallationManager()

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
		result, err := manager.InstallService(rc, options)
		if err != nil {
			return fmt.Errorf("qemu guest agent installation failed: %w", err)
		}

		// Output result
		if result.Success {
			logger.Info("QEMU Guest Agent installation completed successfully",
				zap.String("version", result.Version),
				zap.Duration("duration", result.Duration))

			fmt.Printf("\nQEMU Guest Agent Installation Complete!\n\n")
			fmt.Printf(" Service Details:\n")
			fmt.Printf("   Method: %s\n", result.Method)
			fmt.Printf("   Duration: %s\n", result.Duration)

			if result.Version != "" {
				fmt.Printf("   Version: %s\n", result.Version)
			}

			fmt.Printf("\n📝 Features Enabled:\n")
			fmt.Printf("   - Guest shutdown/reboot from host\n")
			fmt.Printf("   - File system freeze/thaw for snapshots\n")
			fmt.Printf("   - Guest network information\n")
			fmt.Printf("   - Guest exec commands\n")
			fmt.Printf("   - Time synchronization\n")

			fmt.Printf("\n💡 Hypervisor Configuration:\n")
			fmt.Printf("   - For Proxmox: Enable QEMU Guest Agent in VM options\n")
			fmt.Printf("   - For libvirt: Add channel device for guest agent\n")
			fmt.Printf("   - Check status: eos status qemu-guest-agent\n")
		} else {
			logger.Error("QEMU Guest Agent installation failed", zap.String("error", result.Error))
			fmt.Printf("\n❌ QEMU Guest Agent Installation Failed!\n")
			fmt.Printf("Error: %s\n", result.Error)

			if len(result.Steps) > 0 {
				fmt.Printf("\nInstallation Steps:\n")
				for _, step := range result.Steps {
					status := "✅"
					if step.Status == "failed" {
						status = "❌"
					} else if step.Status == "running" {
						status = "⏳"
					}
					fmt.Printf("   %s %s (%s)\n", status, step.Name, step.Duration)
					if step.Error != "" {
						fmt.Printf("      Error: %s\n", step.Error)
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
