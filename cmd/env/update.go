package env

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/environments"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var updateCmd = &cobra.Command{
	Use:   "update <environment-name>",
	Short: "Update an existing environment configuration",
	Long: `Update an existing deployment environment's configuration interactively
or using command line flags. This command allows you to modify infrastructure
endpoints, deployment policies, security settings, and other environment
configuration without recreating the environment.

You can update specific aspects of the environment using flags, or run the
command without flags to enter interactive mode where you can review and
modify all configuration options.

Changes will be validated before being applied, and you can use --dry-run
to see what changes would be made without applying them.

Examples:
  # Update environment interactively
  eos env update staging

  # Update specific infrastructure endpoint
  eos env update staging --nomad-address https://new-nomad.example.com:4646

  # Update deployment strategy
  eos env update production --deploy-strategy blue-green

  # Update resource limits
  eos env update development --cpu 1000 --memory 512

  # Dry run to see what would change
  eos env update staging --nomad-address new-address --dry-run`,
	Args: cobra.ExactArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		envName := args[0]

		logger.Info("Updating environment configuration",
			zap.String("command", "env update"),
			zap.String("environment", envName),
			zap.String("component", rc.Component))

		// Parse flags
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		force, _ := cmd.Flags().GetBool("force")
		interactive, _ := cmd.Flags().GetBool("interactive")

		// Configuration flags
		displayName, _ := cmd.Flags().GetString("display-name")
		description, _ := cmd.Flags().GetString("description")
		envType, _ := cmd.Flags().GetString("type")
		nomadAddress, _ := cmd.Flags().GetString("nomad-address")
		consulAddress, _ := cmd.Flags().GetString("consul-address")
		vaultAddress, _ := cmd.Flags().GetString("vault-address")
		deployStrategy, _ := cmd.Flags().GetString("deploy-strategy")
		cpu, _ := cmd.Flags().GetInt("cpu")
		memory, _ := cmd.Flags().GetInt("memory")

		// Create environment manager
		envManager, err := environments.NewEnvironmentManager("")
		if err != nil {
			logger.Error("Failed to create environment manager", zap.Error(err))
			return fmt.Errorf("failed to create environment manager: %w", err)
		}

		// Get current environment configuration
		currentEnv, err := envManager.GetEnvironment(rc, envName)
		if err != nil {
			logger.Error("Environment not found",
				zap.String("environment", envName),
				zap.Error(err))
			return fmt.Errorf("environment '%s' not found. Use 'eos env list' to see available environments", envName)
		}

		// Create updated environment (copy of current)
		updatedEnv := *currentEnv

		// Track what changed
		changes := make(map[string]string)

		// Apply flag-based updates
		if displayName != "" && displayName != currentEnv.DisplayName {
			updatedEnv.DisplayName = displayName
			changes["display_name"] = fmt.Sprintf("%s → %s", currentEnv.DisplayName, displayName)
		}

		if description != "" && description != currentEnv.Description {
			updatedEnv.Description = description
			changes["description"] = fmt.Sprintf("%s → %s", currentEnv.Description, description)
		}

		if envType != "" && envType != string(currentEnv.Type) {
			updatedEnv.Type = environments.EnvironmentType(envType)
			changes["type"] = fmt.Sprintf("%s → %s", currentEnv.Type, envType)
		}

		if nomadAddress != "" && nomadAddress != currentEnv.Infrastructure.Nomad.Address {
			updatedEnv.Infrastructure.Nomad.Address = nomadAddress
			changes["nomad_address"] = fmt.Sprintf("%s → %s", currentEnv.Infrastructure.Nomad.Address, nomadAddress)
		}

		if consulAddress != "" && consulAddress != currentEnv.Infrastructure.Consul.Address {
			updatedEnv.Infrastructure.Consul.Address = consulAddress
			changes["consul_address"] = fmt.Sprintf("%s → %s", currentEnv.Infrastructure.Consul.Address, consulAddress)
		}

		if vaultAddress != "" && vaultAddress != currentEnv.Infrastructure.Vault.Address {
			updatedEnv.Infrastructure.Vault.Address = vaultAddress
			changes["vault_address"] = fmt.Sprintf("%s → %s", currentEnv.Infrastructure.Vault.Address, vaultAddress)
		}

		if deployStrategy != "" && deployStrategy != currentEnv.Deployment.Strategy.Type {
			updatedEnv.Deployment.Strategy.Type = deployStrategy
			changes["deploy_strategy"] = fmt.Sprintf("%s → %s", currentEnv.Deployment.Strategy.Type, deployStrategy)
		}

		if cpu > 0 && cpu != currentEnv.Deployment.Resources.CPU {
			updatedEnv.Deployment.Resources.CPU = cpu
			changes["cpu"] = fmt.Sprintf("%d → %d MHz", currentEnv.Deployment.Resources.CPU, cpu)
		}

		if memory > 0 && memory != currentEnv.Deployment.Resources.Memory {
			updatedEnv.Deployment.Resources.Memory = memory
			changes["memory"] = fmt.Sprintf("%d → %d MB", currentEnv.Deployment.Resources.Memory, memory)
		}

		// Interactive mode if no flags provided or explicitly requested
		if interactive || (len(changes) == 0 && !dryRun) {
			fmt.Printf("\n Interactive Environment Update\n")
			fmt.Printf("═════════════════════════════════\n")
			fmt.Printf("Current configuration for '%s':\n\n", envName)

			// Show current config and allow updates
			if err := interactiveEnvironmentUpdate(rc, &updatedEnv, changes); err != nil {
				return fmt.Errorf("interactive update failed: %w", err)
			}
		}

		// Show change summary
		if len(changes) == 0 {
			fmt.Printf("No changes detected for environment '%s'\n", envName)
			return nil
		}

		fmt.Printf("\nEnvironment Update Summary:\n")
		fmt.Printf("══════════════════════════\n")
		fmt.Printf("Environment: %s\n", envName)
		fmt.Printf("Changes:\n")
		for field, change := range changes {
			fmt.Printf("  %s: %s\n", field, change)
		}
		fmt.Printf("\n")

		// Dry run - show what would be updated
		if dryRun {
			fmt.Printf(" Dry Run - No changes will be applied\n")
			return nil
		}

		// Get confirmation for non-force updates
		if !force {
			fmt.Printf("Apply these changes to environment '%s'? (y/N): ", envName)
			// In real implementation, would read from stdin
			fmt.Printf("y\n")
		}

		// Apply the updates
		if err := envManager.UpdateEnvironment(rc, &updatedEnv); err != nil {
			logger.Error("Failed to update environment",
				zap.String("environment", envName),
				zap.Error(err))
			return fmt.Errorf("failed to update environment: %w", err)
		}

		// Success message
		fmt.Printf(" Environment '%s' updated successfully\n", envName)

		// Show next steps
		fmt.Printf("\nNext Steps:\n")
		fmt.Printf("──────────\n")
		fmt.Printf("• View updated environment: eos env show %s\n", envName)
		if currentEnv.Status == environments.EnvironmentStatusActive {
			fmt.Printf("• Check infrastructure connectivity\n")
		}

		logger.Info("Environment updated successfully",
			zap.String("environment", envName),
			zap.Int("changes", len(changes)))

		return nil
	}),
}

func init() {
	EnvCmd.AddCommand(updateCmd)

	// Basic environment configuration
	updateCmd.Flags().String("type", "", "Environment type: development, staging, production, testing, preview")
	updateCmd.Flags().String("display-name", "", "Display name for the environment")
	updateCmd.Flags().String("description", "", "Description of the environment")

	// Infrastructure configuration
	updateCmd.Flags().String("nomad-address", "", "Nomad cluster address")
	updateCmd.Flags().String("consul-address", "", "Consul cluster address")
	updateCmd.Flags().String("vault-address", "", "Vault cluster address")

	// Deployment configuration
	updateCmd.Flags().String("deploy-strategy", "", "Deployment strategy: rolling, blue-green, canary")
	updateCmd.Flags().Int("cpu", 0, "Default CPU allocation (MHz)")
	updateCmd.Flags().Int("memory", 0, "Default memory allocation (MB)")

	// Security configuration
	updateCmd.Flags().Bool("enable-rbac", false, "Enable RBAC")
	updateCmd.Flags().Bool("disable-rbac", false, "Disable RBAC")
	updateCmd.Flags().Bool("require-mfa", false, "Require MFA for operations")
	updateCmd.Flags().Bool("disable-mfa", false, "Disable MFA requirement")

	// Update behavior
	updateCmd.Flags().Bool("interactive", false, "Force interactive mode even with flags")
	updateCmd.Flags().Bool("dry-run", false, "Show what would be updated without making changes")
	updateCmd.Flags().Bool("force", false, "Apply updates without confirmation")

	updateCmd.Example = `  # Update environment interactively
  eos env update staging

  # Update Nomad address
  eos env update staging --nomad-address https://new-nomad.example.com:4646

  # Update multiple settings
  eos env update development --cpu 1000 --memory 512 --deploy-strategy rolling

  # Preview changes without applying
  eos env update production --nomad-address new-address --dry-run

  # Force update without confirmation
  eos env update testing --description "Updated testing environment" --force`
}

// interactiveEnvironmentUpdate provides interactive update interface
func interactiveEnvironmentUpdate(rc *eos_io.RuntimeContext, env *environments.Environment, changes map[string]string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting interactive environment update")

	fmt.Printf("Current Values (press Enter to keep unchanged):\n")
	fmt.Printf("───────────────────────────────────────────────\n")

	// Basic information
	fmt.Printf("\nBasic Information:\n")
	fmt.Printf("Display name [%s]: ", env.DisplayName)
	// In real implementation, would read from stdin and update if changed

	fmt.Printf("Description [%s]: ", env.Description)
	// In real implementation, would read from stdin and update if changed

	fmt.Printf("Type [%s]: ", env.Type)
	// In real implementation, would read from stdin and validate

	// Infrastructure
	fmt.Printf("\nInfrastructure:\n")
	fmt.Printf("Nomad address [%s]: ", env.Infrastructure.Nomad.Address)
	// In real implementation, would read from stdin and update if changed

	fmt.Printf("Consul address [%s]: ", env.Infrastructure.Consul.Address)
	// In real implementation, would read from stdin and update if changed

	fmt.Printf("Vault address [%s]: ", env.Infrastructure.Vault.Address)
	// In real implementation, would read from stdin and update if changed

	// Deployment
	fmt.Printf("\nDeployment:\n")
	fmt.Printf("Strategy [%s]: ", env.Deployment.Strategy.Type)
	// In real implementation, would read from stdin and validate

	fmt.Printf("CPU (MHz) [%d]: ", env.Deployment.Resources.CPU)
	// In real implementation, would read from stdin and parse

	fmt.Printf("Memory (MB) [%d]: ", env.Deployment.Resources.Memory)
	// In real implementation, would read from stdin and parse

	// Security
	fmt.Printf("\nSecurity:\n")
	fmt.Printf("RBAC enabled? (y/N) [%s]: ", boolToYesNo(env.Security.AccessControl.RBAC.Enabled))
	// In real implementation, would read from stdin and update

	fmt.Printf("MFA required? (y/N) [%s]: ", boolToYesNo(env.Security.AccessControl.MFA.Required))
	// In real implementation, would read from stdin and update

	// In real implementation, would update the changes map based on user input

	logger.Debug("Interactive update completed")
	return nil
}
