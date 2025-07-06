// cmd/setup/setup.go
package setup

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system_config"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Global flags
var (
	dryRun      bool
	force       bool
	interactive bool
	backup      bool
	jsonOutput  bool
)

// SetupCmd represents the setup command
var SetupCmd = &cobra.Command{
	Use:   "setup",
	Short: "System configuration and setup commands",
	Long: `Setup provides initial system configuration and setup commands.

Use these commands to configure system components, install tools,
and perform initial system hardening and configuration.

Examples:
  eos setup tools               # Install essential system tools
  eos setup ssh-key             # Generate SSH key pair
  eos setup mfa                 # Configure multi-factor authentication
  eos setup --list              # List available setup commands`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		// If no subcommand is provided, show help
		return cmd.Help()
	}),
}

func init() {
	// Add global flags
	SetupCmd.PersistentFlags().BoolVar(&dryRun, "dry-run", false, "Simulate setup without making changes")
	SetupCmd.PersistentFlags().BoolVarP(&force, "force", "f", false, "Force setup even if already configured")
	SetupCmd.PersistentFlags().BoolVarP(&interactive, "interactive", "i", false, "Interactive setup mode")
	SetupCmd.PersistentFlags().BoolVar(&backup, "backup", true, "Create backup before making changes")
	SetupCmd.PersistentFlags().BoolVar(&jsonOutput, "json", false, "Output in JSON format")
}

// setupConfiguration is a helper function to apply configuration
func setupConfiguration(rc *eos_io.RuntimeContext, configType system_config.ConfigurationType, manager system_config.ConfigurationManager, options *system_config.ConfigurationOptions) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Create system config manager and register the specific manager
	scm := system_config.NewSystemConfigManager()
	scm.RegisterManager(configType, manager)

	// Apply configuration
	result, err := scm.ApplyConfiguration(rc, options)
	if err != nil {
		return fmt.Errorf("configuration failed: %w", err)
	}

	// Output result
	if jsonOutput {
		// TODO: Implement JSON output
		logger.Info("JSON output not yet implemented")
	}

	if result.Success {
		logger.Info("Setup completed successfully",
			zap.String("type", string(configType)),
			zap.Duration("duration", result.Duration))

		fmt.Printf("\n✅ %s Setup Complete!\n\n", configType)
		fmt.Printf("⏱️ Duration: %s\n", result.Duration)

		if len(result.Changes) > 0 {
			fmt.Printf("\n📝 Changes Made:\n")
			for _, change := range result.Changes {
				fmt.Printf("   • %s: %s (%s)\n", change.Type, change.Target, change.Action)
			}
		}

		if len(result.Warnings) > 0 {
			fmt.Printf("\n⚠️ Warnings:\n")
			for _, warning := range result.Warnings {
				fmt.Printf("   • %s\n", warning)
			}
		}

		if len(result.Steps) > 0 {
			fmt.Printf("\n🔧 Steps Completed:\n")
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
	} else {
		logger.Error("Setup failed", zap.String("error", result.Error))
		fmt.Printf("\n❌ %s Setup Failed!\n", configType)
		fmt.Printf("Error: %s\n", result.Error)
	}

	return nil
}