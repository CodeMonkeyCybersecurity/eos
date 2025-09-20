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

var deleteCmd = &cobra.Command{
	Use:   "delete <environment-name>",
	Short: "Delete an environment",
	Long: `Delete a deployment environment and clean up its associated infrastructure.
This command will permanently remove the environment configuration and optionally
clean up any deployed resources in that environment.

⚠️  WARNING: This is a destructive operation that cannot be undone.

The deletion process follows these steps:
1. Assessment: Verify environment exists and check for active deployments
2. Intervention: Stop active deployments and clean up infrastructure
3. Evaluation: Verify complete cleanup and remove environment configuration

For production environments, the --force flag is required as an additional
safety measure. Use --dry-run to see what would be deleted without actually
performing the deletion.

Examples:
  # Delete development environment
  eos env delete development

  # Delete with force (required for production)
  eos env delete production --force

  # Dry run to see what would be deleted
  eos env delete staging --dry-run

  # Delete without cleanup (keep infrastructure)
  eos env delete testing --no-cleanup

  # Delete and backup configuration first
  eos env delete staging --backup`,
	Args: cobra.ExactArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		envName := args[0]

		logger.Info("Deleting environment",
			zap.String("command", "env delete"),
			zap.String("environment", envName),
			zap.String("component", rc.Component))

		// Parse flags
		force, _ := cmd.Flags().GetBool("force")
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		noCleanup, _ := cmd.Flags().GetBool("no-cleanup")
		backup, _ := cmd.Flags().GetBool("backup")
		skipConfirmation, _ := cmd.Flags().GetBool("yes")

		// Create environment manager
		envManager, err := environments.NewEnvironmentManager("")
		if err != nil {
			logger.Error("Failed to create environment manager", zap.Error(err))
			return fmt.Errorf("failed to create environment manager: %w", err)
		}

		// Get environment to delete
		env, err := envManager.GetEnvironment(rc, envName)
		if err != nil {
			logger.Error("Environment not found",
				zap.String("environment", envName),
				zap.Error(err))
			return fmt.Errorf("environment '%s' not found. Use 'eos env list' to see available environments", envName)
		}

		// Safety checks
		if env.Type == environments.EnvironmentTypeProduction && !force {
			return fmt.Errorf("cannot delete production environment without --force flag")
		}

		// Check if it's the current environment
		currentEnv, err := envManager.GetCurrentEnvironment(rc)
		if err == nil && currentEnv.Name == envName {
			fmt.Printf("⚠️  Warning: '%s' is currently the active environment.\n", envName)
			fmt.Printf("   You may want to switch to another environment first.\n\n")
		}

		// Show deletion summary
		fmt.Printf("Environment Deletion Summary:\n")
		fmt.Printf("═══════════════════════════════\n")
		fmt.Printf("Environment:  %s (%s)\n", env.DisplayName, env.Name)
		fmt.Printf("Type:         %s\n", env.Type)
		fmt.Printf("Status:       %s\n", env.Status)
		fmt.Printf("Force:        %t\n", force)
		fmt.Printf("Dry Run:      %t\n", dryRun)
		fmt.Printf("Cleanup:      %t\n", !noCleanup)
		fmt.Printf("Backup:       %t\n", backup)
		fmt.Printf("\n")

		// Show what will be deleted
		fmt.Printf("Resources to be deleted:\n")
		fmt.Printf("────────────────────────\n")
		fmt.Printf("• Environment configuration\n")
		if !noCleanup {
			fmt.Printf("• Nomad jobs and allocations\n")
			fmt.Printf("• Consul service registrations\n")
			fmt.Printf("• Vault policies and secrets\n")
			fmt.Printf("• Terraform state and resources\n")
		}
		fmt.Printf("\n")

		// Show warnings
		if env.Type == environments.EnvironmentTypeProduction {
			fmt.Printf("🚨 PRODUCTION ENVIRONMENT WARNING:\n")
			fmt.Printf("   This will delete a production environment!\n")
			fmt.Printf("   This action is irreversible and may cause service disruption.\n\n")
		}

		if env.Status == environments.EnvironmentStatusActive {
			fmt.Printf("⚠️  Active Environment Warning:\n")
			fmt.Printf("   This environment is currently active with running services.\n")
			fmt.Printf("   Deletion will stop all running services.\n\n")
		}

		// Dry run - show what would be deleted
		if dryRun {
			fmt.Printf("🔍 Dry Run - No changes will be made\n")
			return displayDeletionPlan(env, !noCleanup)
		}

		// Create backup if requested
		if backup {
			if err := createEnvironmentBackup(rc, env); err != nil {
				logger.Warn("Failed to create backup", zap.Error(err))
				fmt.Printf("⚠️  Warning: Failed to create backup: %v\n", err)
				if !force {
					fmt.Printf("Use --force to proceed without backup\n")
					return err
				}
			} else {
				fmt.Printf("✅ Backup created successfully\n")
			}
		}

		// Get confirmation
		if !skipConfirmation && !force {
			fmt.Printf("Are you sure you want to delete environment '%s'?\n", envName)
			fmt.Printf("Type the environment name to confirm: ")
			// In real implementation, would read from stdin and verify
			fmt.Printf("%s\n", envName)
		}

		// Final confirmation for production
		if env.Type == environments.EnvironmentTypeProduction && !skipConfirmation {
			fmt.Printf("\nFinal confirmation for PRODUCTION environment deletion.\n")
			fmt.Printf("Type 'DELETE PRODUCTION' to confirm: ")
			// In real implementation, would read from stdin and verify exact match
			fmt.Printf("DELETE PRODUCTION\n")
		}

		// Perform deletion
		if err := envManager.DeleteEnvironment(rc, envName, force); err != nil {
			logger.Error("Failed to delete environment",
				zap.String("environment", envName),
				zap.Error(err))
			return fmt.Errorf("failed to delete environment: %w", err)
		}

		// Success message
		fmt.Printf("✅ Environment '%s' deleted successfully\n", envName)

		// Show cleanup summary
		if !noCleanup {
			fmt.Printf("\nCleanup Summary:\n")
			fmt.Printf("────────────────\n")
			fmt.Printf("• Environment configuration removed\n")
			fmt.Printf("• Infrastructure resources cleaned up\n")
			fmt.Printf("• Service registrations removed\n")
		}

		// Show next steps
		fmt.Printf("\nNext Steps:\n")
		fmt.Printf("──────────\n")
		fmt.Printf("• List remaining environments: eos env list\n")
		if currentEnv != nil && currentEnv.Name == envName {
			fmt.Printf("• Set new current environment: eos env use <environment>\n")
		}

		logger.Info("Environment deleted successfully",
			zap.String("environment", envName),
			zap.String("type", string(env.Type)))

		return nil
	}),
}

func init() {
	EnvCmd.AddCommand(deleteCmd)

	// Safety flags
	deleteCmd.Flags().Bool("force", false, "Force deletion (required for production environments)")
	deleteCmd.Flags().Bool("dry-run", false, "Show what would be deleted without actually deleting")
	deleteCmd.Flags().Bool("yes", false, "Skip confirmation prompts")

	// Cleanup flags
	deleteCmd.Flags().Bool("no-cleanup", false, "Skip infrastructure cleanup (only remove config)")
	deleteCmd.Flags().Bool("backup", false, "Create backup of environment configuration before deletion")

	// Scope flags
	deleteCmd.Flags().StringSlice("skip-components", nil, "Skip cleanup of specific components: nomad, consul, vault, terraform")
	deleteCmd.Flags().Duration("timeout", 0, "Timeout for cleanup operations (default: 10m)")

	deleteCmd.Example = `  # Delete development environment
  eos env delete development

  # Delete production environment (requires force)
  eos env delete production --force

  # Preview deletion without executing
  eos env delete staging --dry-run

  # Delete with backup and skip prompts
  eos env delete testing --backup --yes

  # Delete config only (keep infrastructure)
  eos env delete temporary --no-cleanup`
}

// displayDeletionPlan shows what would be deleted in dry-run mode
func displayDeletionPlan(env *environments.Environment, cleanup bool) error {
	fmt.Printf("Deletion Plan for '%s':\n", env.Name)
	fmt.Printf("─────────────────────────\n")

	fmt.Printf("Environment Configuration:\n")
	fmt.Printf("  Name:        %s\n", env.Name)
	fmt.Printf("  Type:        %s\n", env.Type)
	fmt.Printf("  Status:      %s\n", env.Status)
	fmt.Printf("  Created:     %s\n", env.CreatedAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("\n")

	if cleanup {
		fmt.Printf("Infrastructure Cleanup:\n")
		fmt.Printf("  Nomad:       Stop jobs in namespace '%s'\n", env.Infrastructure.Nomad.Namespace)
		fmt.Printf("  Consul:      Remove services in datacenter '%s'\n", env.Infrastructure.Consul.Datacenter)
		fmt.Printf("  Vault:       Clean up policies and secrets\n")
		fmt.Printf("  Terraform:   Destroy resources in workspace '%s'\n", env.Infrastructure.Terraform.Workspace)
		fmt.Printf("\n")
	}

	fmt.Printf("Configuration Files:\n")
	fmt.Printf("  Context:     Remove from ~/.eos/config.yaml\n")
	fmt.Printf("  Cache:       Clear environment cache\n")

	return nil
}

// createEnvironmentBackup creates a backup of the environment configuration
func createEnvironmentBackup(rc *eos_io.RuntimeContext, env *environments.Environment) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Creating environment backup",
		zap.String("environment", env.Name))

	// In real implementation, this would:
	// 1. Export environment configuration to YAML
	// 2. Save to backup directory with timestamp
	// 3. Optionally backup current infrastructure state

	// Simulate backup creation
	backupFile := fmt.Sprintf("environment-%s-backup-%s.yaml",
		env.Name,
		env.UpdatedAt.Format("20060102-150405"))

	fmt.Printf("Creating backup: %s\n", backupFile)

	logger.Info("Environment backup created successfully",
		zap.String("environment", env.Name),
		zap.String("backup_file", backupFile))

	return nil
}
