// cmd/delphi/services/ab-test-config.go
package services

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// NewDeployABConfigCmd creates the deploy-ab-config command
func NewDeployABConfigCmd() *cobra.Command {
	var (
		force    bool
		validate bool
	)

	cmd := &cobra.Command{
		Use:   "deploy-ab-config",
		Short: "Deploy A/B testing configuration for prompt-ab-tester service",
		Long: `Deploy A/B testing configuration files and setup directories for the prompt-ab-tester service.

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
  eos delphi services deploy-ab-config
  eos delphi services deploy-ab-config --force
  eos delphi services deploy-ab-config --validate`,
		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)
			logger.Info("🧪 Deploying A/B testing configuration")

			// Get EOS root directory
			eosRoot := os.Getenv("EOS_ROOT")
			if eosRoot == "" {
				if pwd, err := os.Getwd(); err == nil && fileExists(filepath.Join(pwd, "assets")) {
					eosRoot = pwd
				} else {
					return fmt.Errorf("EOS_ROOT environment variable not set and cannot auto-detect Eos directory")
				}
			}

			// Source and target paths
			sourceConfig := filepath.Join(eosRoot, "assets", "ab-test-config.json")
			targetConfig := "/opt/delphi/ab-test-config.json"
			targetDir := "/opt/delphi"
			reportsDir := "/var/log/stackstorm/ab-test-reports"

			// Validate source file exists
			if !fileExists(sourceConfig) {
				return fmt.Errorf("source A/B config file not found: %s", sourceConfig)
			}

			logger.Info("📂 Source configuration found",
				zap.String("source", sourceConfig))

			// Validate JSON syntax if requested
			if validate {
				logger.Info("🔍 Validating configuration syntax")
				if err := validateABConfigJSON(sourceConfig); err != nil {
					return fmt.Errorf("configuration validation failed: %w", err)
				}
				logger.Info("✅ Configuration syntax is valid")
			}

			// Check if target already exists
			if fileExists(targetConfig) && !force {
				return fmt.Errorf("target configuration already exists: %s (use --force to overwrite)", targetConfig)
			}

			// Create target directories
			logger.Info("📁 Creating target directories")
			
			for _, dir := range []string{targetDir, reportsDir} {
				if err := os.MkdirAll(dir, 0755); err != nil {
					return fmt.Errorf("failed to create directory %s: %w", dir, err)
				}
				logger.Info("✅ Directory created",
					zap.String("directory", dir))
			}

			// Deploy configuration file
			logger.Info("📝 Deploying configuration file",
				zap.String("source", sourceConfig),
				zap.String("target", targetConfig))

			if err := copyFile(sourceConfig, targetConfig); err != nil {
				return fmt.Errorf("failed to deploy configuration: %w", err)
			}

			// Set permissions
			logger.Info("🔐 Setting file permissions")
			
			// Set file permissions
			if err := os.Chmod(targetConfig, 0644); err != nil {
				logger.Warn("Failed to set file permissions",
					zap.String("file", targetConfig),
					zap.Error(err))
			}

			// Set ownership to stanley
			_, err := execute.Run(rc.Ctx, execute.Options{
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

			logger.Info("✅ A/B testing configuration deployed successfully",
				zap.String("config_file", targetConfig),
				zap.String("reports_dir", reportsDir))

			// Display next steps
			logger.Info("🎯 Next steps:")
			logger.Info("   1. Review configuration: cat /opt/delphi/ab-test-config.json")
			logger.Info("   2. Deploy prompt-ab-tester service: eos delphi services update prompt-ab-tester")
			logger.Info("   3. Start A/B testing: systemctl start prompt-ab-tester")
			logger.Info("   4. Monitor results: eos delphi services logs prompt-ab-tester")

			return nil
		}),
	}

	cmd.Flags().BoolVarP(&force, "force", "f", false, "Overwrite existing configuration file")
	cmd.Flags().BoolVarP(&validate, "validate", "v", false, "Validate configuration syntax before deployment")

	return cmd
}

// validateABConfigJSON validates the JSON syntax and structure of A/B config
func validateABConfigJSON(configPath string) error {
	// Basic JSON validation using Python (available on most systems)
	_, err := execute.Run(context.TODO(), execute.Options{
		Command: "python3",
		Args:    []string{"-c", fmt.Sprintf("import json; json.load(open('%s'))", configPath)},
	})
	if err != nil {
		return fmt.Errorf("invalid JSON syntax in configuration file")
	}

	return nil
}