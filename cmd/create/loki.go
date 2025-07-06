// cmd/create/loki.go
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

// CreateLokiCmd installs Loki log aggregation system
var CreateLokiCmd = &cobra.Command{
	Use:   "loki",
	Short: "Install Loki log aggregation system",
	Long: `Install Loki using Docker Compose with the official production configuration.

Loki is a horizontally scalable, highly available, multi-tenant log aggregation
system inspired by Prometheus. It is designed to be cost-effective and easy to
operate.

Examples:
  eos create loki                           # Install with defaults
  eos create loki --version v3.0.0         # Specific version
  eos create loki --dry-run                # Test installation`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		// Get flags
		version, _ := cmd.Flags().GetString("version")
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		workDir, _ := cmd.Flags().GetString("work-dir")

		logger.Info("Installing Loki",
			zap.String("version", version),
			zap.Bool("dry_run", dryRun))

		manager := service_installation.NewServiceInstallationManager()

		// Build installation options
		options := &service_installation.ServiceInstallOptions{
			Name:             "loki",
			Type:             service_installation.ServiceTypeLoki,
			Version:          version,
			Method:           service_installation.MethodCompose,
			DryRun:           dryRun,
			WorkingDirectory: workDir,
			Environment:      make(map[string]string),
			Config:           make(map[string]string),
		}

		// Set defaults
		if options.Version == "" {
			options.Version = "v3.0.0"
		}

		// Perform installation
		result, err := manager.InstallService(rc, options)
		if err != nil {
			return fmt.Errorf("loki installation failed: %w", err)
		}

		// Output result
		if result.Success {
			logger.Info("Loki installation completed successfully",
				zap.String("version", result.Version),
				zap.Duration("duration", result.Duration))

			fmt.Printf("\n✅ Loki Installation Complete!\n\n")
			fmt.Printf("📊 Service Details:\n")
			fmt.Printf("   Version: %s\n", result.Version)
			fmt.Printf("   Method: %s\n", result.Method)
			fmt.Printf("   Duration: %s\n", result.Duration)

			if len(result.Endpoints) > 0 {
				fmt.Printf("\n🌐 Access URLs:\n")
				for _, endpoint := range result.Endpoints {
					fmt.Printf("   %s\n", endpoint)
				}
			}

			fmt.Printf("\n📝 Next Steps:\n")
			fmt.Printf("   1. Configure promtail or other log shippers to send logs to Loki\n")
			fmt.Printf("   2. Access Grafana (if included) to view logs\n")
			fmt.Printf("   3. Check status: docker compose ps\n")
		} else {
			logger.Error("Loki installation failed", zap.String("error", result.Error))
			fmt.Printf("\n❌ Loki Installation Failed!\n")
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
	CreateCmd.AddCommand(CreateLokiCmd)

	CreateLokiCmd.Flags().StringP("version", "v", "v3.0.0", "Loki version to install")
	CreateLokiCmd.Flags().Bool("dry-run", false, "Simulate installation without making changes")
	CreateLokiCmd.Flags().String("work-dir", "", "Working directory for Loki installation")
}