// cmd/create/ab_test_config.go
package create

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/cmd_helpers"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/pipeline/abtest"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var abTestConfigCmd = &cobra.Command{
	Use:     "ab-test-config",
	Aliases: []string{"ab-config", "prompt-ab-config"},
	Short:   "Create and deploy A/B testing configuration for prompt optimization",
	Long: `Create and deploy A/B testing configuration files and setup directories for the prompt-ab-tester service.

This command:
1. Creates required directories (/opt/delphi, /var/log/stackstorm/ab-test-reports)
2. Deploys ab-test-config.json configuration file
3. Sets proper permissions for stanley user
4. Optionally validates configuration syntax

The A/B testing configuration defines:
- Experiment parameters and time bounds
- Prompt variants with weights and descriptions
- Metrics tracking settings
- Cohort assignment strategies

Examples:
  eos create ab-test-config
  eos create ab-test-config --force
  eos create ab-test-config --validate`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		force, _ := cmd.Flags().GetBool("force")
		validate, _ := cmd.Flags().GetBool("validate")

		logger.Info("Creating A/B testing configuration")

		// Create file service container
		fileContainer, err := cmd_helpers.NewFileServiceContainer(rc)
		if err != nil {
			return fmt.Errorf("failed to initialize file operations: %w", err)
		}

		// Get Eos root directory
		eosRoot := os.Getenv("Eos_ROOT")
		if eosRoot == "" {
			eosRoot = "/usr/local/share/eos" // Default installation path
		}

		// Source and target paths
		sourceConfig := filepath.Join(eosRoot, "assets", "ab-test-config.json")
		targetConfig := "/opt/delphi/ab-test-config.json"
		targetDir := "/opt/delphi"
		reportsDir := "/var/log/stackstorm/ab-test-reports"

		// Validate source file exists
		if !fileContainer.FileExists(sourceConfig) {
			return fmt.Errorf("source A/B config file not found: %s", sourceConfig)
		}

		logger.Info("Source configuration found",
			zap.String("source", sourceConfig))

		// Validate JSON syntax if requested
		if validate {
			logger.Info("Validating configuration syntax")
			if err := abtest.ValidateConfigJSON(rc, sourceConfig); err != nil {
				return fmt.Errorf("configuration validation failed: %w", err)
			}
			logger.Info("Configuration syntax is valid")
		}

		// Check if target already exists
		if fileContainer.FileExists(targetConfig) && !force {
			return fmt.Errorf("target configuration already exists: %s (use --force to overwrite)", targetConfig)
		}

		// Create target directories
		logger.Info("Creating target directories")

		for _, dir := range []string{targetDir, reportsDir} {
			if err := os.MkdirAll(dir, 0755); err != nil {
				return fmt.Errorf("failed to create directory %s: %w", dir, err)
			}
			logger.Info("Directory created",
				zap.String("directory", dir))
		}

		// Deploy configuration file
		logger.Info("Deploying configuration file",
			zap.String("source", sourceConfig),
			zap.String("target", targetConfig))

		if err := fileContainer.CopyFile(sourceConfig, targetConfig); err != nil {
			return fmt.Errorf("failed to deploy configuration: %w", err)
		}

		// Set permissions
		logger.Info("Setting file permissions")

		// Set file permissions
		if err := os.Chmod(targetConfig, 0644); err != nil {
			logger.Warn("Failed to set file permissions",
				zap.String("file", targetConfig),
				zap.Error(err))
		}

		// Set ownership to stanley
		_, err = execute.Run(rc.Ctx, execute.Options{
			Command: "chown",
			Args:    []string{"stanley:stanley", targetConfig},
		})
		if err != nil {
			logger.Warn("Failed to set file ownership",
				zap.String("file", targetConfig),
				zap.Error(err))
		}

		// Set directory ownership
		for _, dir := range []string{targetDir, reportsDir} {
			_, err := execute.Run(rc.Ctx, execute.Options{
				Command: "chown",
				Args:    []string{"stanley:stanley", dir},
			})
			if err != nil {
				logger.Warn("Failed to set directory ownership",
					zap.String("directory", dir),
					zap.Error(err))
			}
		}

		logger.Info("A/B testing configuration deployed successfully",
			zap.String("config_file", targetConfig),
			zap.String("reports_dir", reportsDir))

		// Display next steps
		logger.Info("Next steps:")
		logger.Info("   1. Review configuration: cat /opt/delphi/ab-test-config.json")
		logger.Info("   2. Deploy prompt-ab-tester service: eos create delphi-services prompt-ab-tester")
		logger.Info("   3. Start A/B testing: eos update delphi-services-start prompt-ab-tester")
		logger.Info("   4. Monitor results: eos read delphi-services-logs prompt-ab-tester")

		return nil
	}),
}

func init() {
	abTestConfigCmd.Flags().Bool("force", false, "Overwrite existing configuration file")
	abTestConfigCmd.Flags().Bool("validate", false, "Validate configuration syntax before deployment")

	CreateCmd.AddCommand(abTestConfigCmd)
}
