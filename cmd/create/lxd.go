// cmd/create/lxd.go
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

// CreateLxdCmd installs LXD container hypervisor
var CreateLxdCmd = &cobra.Command{
	Use:   "lxd",
	Short: "Install LXD container hypervisor",
	Long: `Install LXD using snap for system container and virtual machine management.

LXD is a next generation system container and virtual machine manager. It offers
a unified user experience around full Linux systems running inside containers
or virtual machines.

Examples:
  eos create lxd                           # Install with defaults
  eos create lxd --channel latest/stable   # Specific channel
  eos create lxd --dry-run                 # Test installation`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		// Get flags
		channel, _ := cmd.Flags().GetString("channel")
		dryRun, _ := cmd.Flags().GetBool("dry-run")

		logger.Info("Installing LXD",
			zap.String("channel", channel),
			zap.Bool("dry_run", dryRun))

		manager := service_installation.NewServiceInstallationManager()

		// Build installation options
		options := &service_installation.ServiceInstallOptions{
			Name:        "lxd",
			Type:        service_installation.ServiceTypeLxd,
			Version:     channel,
			Method:      service_installation.MethodSnap,
			DryRun:      dryRun,
			Environment: make(map[string]string),
			Config:      make(map[string]string),
		}

		// Set defaults
		if options.Version == "" {
			options.Version = "latest/stable"
		}

		// Perform installation
		result, err := manager.InstallService(rc, options)
		if err != nil {
			return fmt.Errorf("lxd installation failed: %w", err)
		}

		// Output result
		if result.Success {
			logger.Info("LXD installation completed successfully",
				zap.String("version", result.Version),
				zap.Duration("duration", result.Duration))

			fmt.Printf("\n✅ LXD Installation Complete!\n\n")
			fmt.Printf("📦 Service Details:\n")
			fmt.Printf("   Channel: %s\n", result.Version)
			fmt.Printf("   Method: %s\n", result.Method)
			fmt.Printf("   Duration: %s\n", result.Duration)

			fmt.Printf("\n📝 Next Steps:\n")
			fmt.Printf("   1. Log out and back in for group membership to take effect\n")
			fmt.Printf("   2. Initialize LXD: lxd init\n")
			fmt.Printf("   3. Create your first container: lxc launch ubuntu:22.04 mycontainer\n")
			fmt.Printf("   4. List containers: lxc list\n")
			fmt.Printf("   5. Check status: eos status lxd\n")

			fmt.Printf("\n⚠️  Note: You may need to log out and back in for the lxd group membership to take effect.\n")
		} else {
			logger.Error("LXD installation failed", zap.String("error", result.Error))
			fmt.Printf("\n❌ LXD Installation Failed!\n")
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
	CreateCmd.AddCommand(CreateLxdCmd)

	CreateLxdCmd.Flags().String("channel", "latest/stable", "Snap channel to install from")
	CreateLxdCmd.Flags().Bool("dry-run", false, "Simulate installation without making changes")
}