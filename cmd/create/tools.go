// cmd/create/tools.go
package create

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system_config"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// SetupToolsCmd installs and configures essential system tools
var SetupToolsCmd = &cobra.Command{
	Use:   "tools",
	Short: "Install and configure essential system tools",
	Long: `Install and configure essential system tools and packages.

This command performs system updates, installs essential packages,
and configures basic system tools for development and administration.

Examples:
  eos setup tools                    # Install default tool set
  eos setup tools --interactive     # Interactive installation
  eos setup tools --npm             # Include npm and zx
  eos setup tools --dry-run         # Test installation`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		// Get flags
		installNpm, _ := cmd.Flags().GetBool("npm")
		installZx, _ := cmd.Flags().GetBool("zx")
		configureUFW, _ := cmd.Flags().GetBool("ufw")
		setupSensors, _ := cmd.Flags().GetBool("sensors")
		customPackages, _ := cmd.Flags().GetStringSlice("packages")

		logger.Info("Setting up system tools",
			zap.Bool("dry_run", dryRun),
			zap.Bool("interactive", interactive),
			zap.Bool("install_npm", installNpm))

		// Build configuration
		config := &system_config.SystemToolsConfig{
			UpdateSystem:    true,
			InstallPackages: true,
			InstallNpm:      installNpm,
			InstallZx:       installZx,
			ConfigureUFW:    configureUFW,
			SetupSensors:    setupSensors,
			Interactive:     interactive,
		}

		// Use custom packages if provided
		if len(customPackages) > 0 {
			config.Packages = customPackages
		}

		// Interactive configuration
		if interactive {
			if err := runInteractiveToolsSetup(config); err != nil {
				return fmt.Errorf("interactive setup failed: %w", err)
			}
		}

		// Use simplified function instead of manager pattern
		result, err := system_config.ConfigureSystemTools(rc, config)
		if err != nil {
			return fmt.Errorf("system tools configuration failed: %w", err)
		}

		// Display results
		if result.Success {
			logger.Info("System tools setup completed successfully",
				zap.Duration("duration", result.Duration),
				zap.Int("changes", len(result.Changes)),
				zap.Int("warnings", len(result.Warnings)))

			// Log completion information
			logger.Info("terminal prompt: System Tools Setup Complete!")
			logger.Info(fmt.Sprintf("terminal prompt: ⏱️ Duration: %s", result.Duration))

			if len(result.Changes) > 0 {
				logger.Info("terminal prompt: 📝 Changes Made:")
				for _, change := range result.Changes {
					logger.Info(fmt.Sprintf("terminal prompt:    • %s: %s (%s)", 
						change.Type, change.Target, change.Action))
				}
			}

			if len(result.Warnings) > 0 {
				logger.Info("terminal prompt: ⚠️ Warnings:")
				for _, warning := range result.Warnings {
					logger.Info(fmt.Sprintf("terminal prompt:    • %s", warning))
				}
			}
		} else {
			return fmt.Errorf("system tools configuration failed: %s", result.Error)
		}

		return nil
	}),
}

func init() {
	SetupCmd.AddCommand(SetupToolsCmd)

	SetupToolsCmd.Flags().Bool("npm", false, "Install npm and node.js tools")
	SetupToolsCmd.Flags().Bool("zx", false, "Install zx scripting tool (requires npm)")
	SetupToolsCmd.Flags().Bool("ufw", false, "Configure UFW firewall")
	SetupToolsCmd.Flags().Bool("sensors", false, "Setup hardware sensors monitoring")
	SetupToolsCmd.Flags().StringSlice("packages", nil, "Custom package list (overrides defaults)")
}

// TODO
func runInteractiveToolsSetup(config *system_config.SystemToolsConfig) error {
	logger.Info("terminal prompt: Interactive System Tools Setup")
	logger.Info("terminal prompt: =================================\n")

	// System update
	logger.Info("terminal prompt: Update system packages? [Y/n]: ")
	var updateSystem string
	fmt.Scanln(&updateSystem)
	if updateSystem == "n" || updateSystem == "N" {
		config.UpdateSystem = false
	}

	// Package installation
	logger.Info("terminal prompt: Install essential packages? [Y/n]: ")
	var installPackages string
	fmt.Scanln(&installPackages)
	if installPackages == "n" || installPackages == "N" {
		config.InstallPackages = false
	}

	// NPM installation
	logger.Info("terminal prompt: Install npm and Node.js tools? [y/N]: ")
	var installNpm string
	fmt.Scanln(&installNpm)
	if installNpm == "y" || installNpm == "Y" {
		config.InstallNpm = true

		// ZX installation
		logger.Info("terminal prompt: Install zx scripting tool? [y/N]: ")
		var installZx string
		fmt.Scanln(&installZx)
		if installZx == "y" || installZx == "Y" {
			config.InstallZx = true
		}
	}

	// UFW configuration
	logger.Info("terminal prompt: Configure UFW firewall? [y/N]: ")
	var configureUFW string
	fmt.Scanln(&configureUFW)
	if configureUFW == "y" || configureUFW == "Y" {
		config.ConfigureUFW = true
	}

	// Sensors setup
	logger.Info("terminal prompt: Setup hardware sensors monitoring? [y/N]: ")
	var setupSensors string
	fmt.Scanln(&setupSensors)
	if setupSensors == "y" || setupSensors == "Y" {
		config.SetupSensors = true
	}

	logger.Info("terminal prompt: Configuration Summary:")
	logger.Info("terminal prompt:    Update System: %t", config.UpdateSystem)
	logger.Info("terminal prompt:    Install Packages: %t", config.InstallPackages)
	logger.Info("terminal prompt:    Install NPM: %t", config.InstallNpm)
	logger.Info("terminal prompt:    Install ZX: %t", config.InstallZx)
	logger.Info("terminal prompt:    Configure UFW: %t", config.ConfigureUFW)
	logger.Info("terminal prompt:    Setup Sensors: %t", config.SetupSensors)

	logger.Info("terminal prompt: \nProceed with setup? [Y/n]: ")
	var proceed string
	fmt.Scanln(&proceed)
	if proceed == "n" || proceed == "N" {
		return fmt.Errorf("setup cancelled by user")
	}

	return nil
}
