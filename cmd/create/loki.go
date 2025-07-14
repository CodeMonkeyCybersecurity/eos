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
		result, err := service_installation.InstallService(rc, options)
		if err != nil {
			return fmt.Errorf("loki installation failed: %w", err)
		}

		// Output result
		if result.Success {
			logger.Info("Loki installation completed successfully",
				zap.String("version", result.Version),
				zap.Duration("duration", result.Duration))

			logger.Info("terminal prompt: Loki Installation Complete!\n")
			logger.Info("terminal prompt: 📊 Service Details:")
			logger.Info(fmt.Sprintf("terminal prompt:    Version: %s", result.Version))
			logger.Info(fmt.Sprintf("terminal prompt:    Method: %s", result.Method))
			logger.Info(fmt.Sprintf("terminal prompt:    Duration: %s", result.Duration))

			if len(result.Endpoints) > 0 {
				logger.Info("terminal prompt: 🌐 Access URLs:")
				for _, endpoint := range result.Endpoints {
					logger.Info(fmt.Sprintf("terminal prompt:    %s", endpoint))
				}
			}

			logger.Info("terminal prompt: 📝 Next Steps:")
			logger.Info("terminal prompt:    1. Configure promtail or other log shippers to send logs to Loki")
			logger.Info("terminal prompt:    2. Access Grafana (if included) to view logs")
			logger.Info("terminal prompt:    3. Check status: docker compose ps")
		} else {
			logger.Error("Loki installation failed", zap.String("error", result.Error))
			logger.Info("terminal prompt: ❌ Loki Installation Failed!")
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
	CreateCmd.AddCommand(CreateLokiCmd)

	CreateLokiCmd.Flags().StringP("version", "v", "v3.0.0", "Loki version to install")
	CreateLokiCmd.Flags().Bool("dry-run", false, "Simulate installation without making changes")
	CreateLokiCmd.Flags().String("work-dir", "", "Working directory for Loki installation")
}
