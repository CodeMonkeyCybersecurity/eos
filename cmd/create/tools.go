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

		// Create manager
		manager := system_config.NewSystemToolsManager(rc, config)

		// Build options
		options := &system_config.ConfigurationOptions{
			Type:        system_config.ConfigTypeSystemTools,
			DryRun:      dryRun,
			Force:       force,
			Interactive: interactive,
			Backup:      backup,
			Validate:    true,
		}

		// Interactive configuration
		if interactive {
			if err := runInteractiveToolsSetup(config); err != nil {
				return fmt.Errorf("interactive setup failed: %w", err)
			}
		}

		return setupConfiguration(rc, system_config.ConfigTypeSystemTools, manager, options)
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

func runInteractiveToolsSetup(config *system_config.SystemToolsConfig) error {
	fmt.Printf("🔧 Interactive System Tools Setup\n")
	fmt.Printf("=================================\n\n")

	// System update
	fmt.Print("Update system packages? [Y/n]: ")
	var updateSystem string
	fmt.Scanln(&updateSystem)
	if updateSystem == "n" || updateSystem == "N" {
		config.UpdateSystem = false
	}

	// Package installation
	fmt.Print("Install essential packages? [Y/n]: ")
	var installPackages string
	fmt.Scanln(&installPackages)
	if installPackages == "n" || installPackages == "N" {
		config.InstallPackages = false
	}

	// NPM installation
	fmt.Print("Install npm and Node.js tools? [y/N]: ")
	var installNpm string
	fmt.Scanln(&installNpm)
	if installNpm == "y" || installNpm == "Y" {
		config.InstallNpm = true

		// ZX installation
		fmt.Print("Install zx scripting tool? [y/N]: ")
		var installZx string
		fmt.Scanln(&installZx)
		if installZx == "y" || installZx == "Y" {
			config.InstallZx = true
		}
	}

	// UFW configuration
	fmt.Print("Configure UFW firewall? [y/N]: ")
	var configureUFW string
	fmt.Scanln(&configureUFW)
	if configureUFW == "y" || configureUFW == "Y" {
		config.ConfigureUFW = true
	}

	// Sensors setup
	fmt.Print("Setup hardware sensors monitoring? [y/N]: ")
	var setupSensors string
	fmt.Scanln(&setupSensors)
	if setupSensors == "y" || setupSensors == "Y" {
		config.SetupSensors = true
	}

	fmt.Printf("\n📋 Configuration Summary:\n")
	fmt.Printf("   Update System: %t\n", config.UpdateSystem)
	fmt.Printf("   Install Packages: %t\n", config.InstallPackages)
	fmt.Printf("   Install NPM: %t\n", config.InstallNpm)
	fmt.Printf("   Install ZX: %t\n", config.InstallZx)
	fmt.Printf("   Configure UFW: %t\n", config.ConfigureUFW)
	fmt.Printf("   Setup Sensors: %t\n", config.SetupSensors)

	fmt.Print("\nProceed with setup? [Y/n]: ")
	var proceed string
	fmt.Scanln(&proceed)
	if proceed == "n" || proceed == "N" {
		return fmt.Errorf("setup cancelled by user")
	}

	return nil
}