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

var useCmd = &cobra.Command{
	Use:   "use <environment-name>",
	Short: "Switch to a different environment context",
	Long: `Switch the current environment context to the specified environment.
This changes the default environment for all subsequent eos commands until
you switch to a different environment or restart your session.

The environment context affects:
- Default infrastructure endpoints (Nomad, Consul, Vault)
- Deployment configurations and policies
- Security and access control settings
- Monitoring and alerting configurations

Use 'eos env list' to see available environments and their current status.

Examples:
  # Switch to production environment
  eos env use production

  # Switch to development environment
  eos env use development

  # Switch to staging environment
  eos env use staging`,
	Args: cobra.ExactArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		envName := args[0]

		logger.Info("Switching environment context",
			zap.String("command", "env use"),
			zap.String("target_environment", envName),
			zap.String("component", rc.Component))

		// Create environment manager
		envManager, err := environments.NewEnvironmentManager("")
		if err != nil {
			logger.Error("Failed to create environment manager", zap.Error(err))
			return fmt.Errorf("failed to create environment manager: %w", err)
		}

		// Get current environment for logging
		currentEnv, err := envManager.GetCurrentEnvironment(rc)
		var currentEnvName string
		if err == nil {
			currentEnvName = currentEnv.Name
		} else {
			currentEnvName = "none"
		}

		logger.Debug("Current environment context",
			zap.String("current_environment", currentEnvName),
			zap.String("target_environment", envName))

		// Check if target environment exists before switching
		targetEnv, err := envManager.GetEnvironment(rc, envName)
		if err != nil {
			logger.Error("Target environment not found", 
				zap.String("environment", envName),
				zap.Error(err))
			return fmt.Errorf("environment '%s' not found. Use 'eos env list' to see available environments", envName)
		}

		// Check if environment is active
		if targetEnv.Status != environments.EnvironmentStatusActive {
			logger.Warn("Switching to non-active environment",
				zap.String("environment", envName),
				zap.String("status", string(targetEnv.Status)))
			
			fmt.Printf("⚠️  Warning: Environment '%s' is in '%s' status.\n", envName, targetEnv.Status)
			fmt.Printf("   Some operations may not work as expected.\n\n")
		}

		// Perform the environment switch
		if err := envManager.UseEnvironment(rc, envName); err != nil {
			logger.Error("Failed to switch environment", 
				zap.String("environment", envName),
				zap.Error(err))
			return fmt.Errorf("failed to switch to environment '%s': %w", envName, err)
		}

		// Success message
		if currentEnvName == envName {
			fmt.Printf("✅ Already using environment '%s' (%s)\n", targetEnv.DisplayName, envName)
		} else {
			fmt.Printf("✅ Switched from '%s' to '%s' (%s)\n", currentEnvName, targetEnv.DisplayName, envName)
		}

		// Display basic environment info
		fmt.Printf("\nEnvironment Information:\n")
		fmt.Printf("  Type:         %s\n", targetEnv.Type)
		fmt.Printf("  Status:       %s\n", targetEnv.Status)
		fmt.Printf("  Description:  %s\n", targetEnv.Description)
		fmt.Printf("\nInfrastructure Endpoints:\n")
		fmt.Printf("  Nomad:        %s\n", targetEnv.Infrastructure.Nomad.Address)
		fmt.Printf("  Consul:       %s\n", targetEnv.Infrastructure.Consul.Address)
		fmt.Printf("  Vault:        %s\n", targetEnv.Infrastructure.Vault.Address)
		
		if targetEnv.Infrastructure.Provider.Name != "" {
			fmt.Printf("  Provider:     %s (%s)\n", 
				targetEnv.Infrastructure.Provider.Name,
				targetEnv.Infrastructure.Provider.Region)
		}

		// Show deployment strategy
		fmt.Printf("\nDeployment Configuration:\n")
		fmt.Printf("  Strategy:     %s\n", targetEnv.Deployment.Strategy.Type)
		fmt.Printf("  Auto Revert:  %t\n", targetEnv.Deployment.Strategy.AutoRevert)
		fmt.Printf("  Auto Promote: %t\n", targetEnv.Deployment.Strategy.AutoPromote)

		// Security notice for production
		if targetEnv.Type == environments.EnvironmentTypeProduction {
			fmt.Printf("\n🔒 Production Environment Security Notice:\n")
			if targetEnv.Security.AccessControl.MFA.Required {
				fmt.Printf("   • MFA is required for all operations\n")
			}
			if targetEnv.Security.AccessControl.Approval.Required {
				fmt.Printf("   • Deployment approval is required (%d approvers)\n", 
					targetEnv.Security.AccessControl.Approval.MinApprovals)
			}
			if targetEnv.Security.AccessControl.RBAC.Enabled {
				fmt.Printf("   • RBAC is enabled - check your permissions\n")
			}
		}

		logger.Info("Environment context switched successfully",
			zap.String("from", currentEnvName),
			zap.String("to", envName),
			zap.String("type", string(targetEnv.Type)))

		return nil
	}),
}

func init() {
	EnvCmd.AddCommand(useCmd)

	// No additional flags needed for the use command
	useCmd.Example = `  # Switch to production environment
  eos env use production

  # Switch to development environment  
  eos env use development

  # Switch to staging environment
  eos env use staging

  # Use tab completion to see available environments
  eos env use <TAB>`
}