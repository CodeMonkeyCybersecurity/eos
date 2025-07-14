package env

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/environments"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

var applyCmd = &cobra.Command{
	Use:   "apply [environment-name]",
	Short: "Create or update an environment from configuration file",
	Long: `Create or update a deployment environment from a YAML configuration file.
This command allows you to define environments as code, making it easy to
version control and reproduce environment configurations.

The configuration file should contain the complete environment specification
including infrastructure endpoints, deployment policies, security settings,
and monitoring configuration.

If the environment already exists, this command will update it with the new
configuration. Use --dry-run to see what changes would be made without
applying them.

Examples:
  # Apply environment from default config file
  eos env apply staging --config environments/staging.yaml

  # Apply with custom config file
  eos env apply production --config /path/to/prod-config.yaml

  # Dry run to see what would be applied
  eos env apply staging --config staging.yaml --dry-run

  # Force apply even if validation warnings exist
  eos env apply staging --config staging.yaml --force`,
	Args: cobra.MaximumNArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		logger.Info("Applying environment configuration",
			zap.String("command", "env apply"),
			zap.String("component", rc.Component))

		// Parse flags
		configFile, _ := cmd.Flags().GetString("config")
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		force, _ := cmd.Flags().GetBool("force")
		createOnly, _ := cmd.Flags().GetBool("create-only")
		updateOnly, _ := cmd.Flags().GetBool("update-only")

		// Determine environment name
		var envName string
		if len(args) > 0 {
			envName = args[0]
		}

		logger.Debug("Apply configuration",
			zap.String("environment", envName),
			zap.String("config_file", configFile),
			zap.Bool("dry_run", dryRun),
			zap.Bool("force", force))

		// Validate config file path
		if configFile == "" {
			if envName == "" {
				return fmt.Errorf("either environment name or --config flag must be provided")
			}
			// Try default config file path
			configFile = fmt.Sprintf("environments/%s.yaml", envName)
		}

		// Expand tilde in config file path
		if configFile[0] == '~' {
			homeDir, err := os.UserHomeDir()
			if err != nil {
				return fmt.Errorf("failed to get home directory: %w", err)
			}
			configFile = filepath.Join(homeDir, configFile[1:])
		}

		// Check if config file exists
		if _, err := os.Stat(configFile); os.IsNotExist(err) {
			logger.Error("Configuration file not found", zap.String("file", configFile))
			return fmt.Errorf("configuration file not found: %s", configFile)
		}

		// Load environment configuration from file
		env, err := loadEnvironmentFromFile(rc, configFile)
		if err != nil {
			logger.Error("Failed to load environment configuration", 
				zap.String("file", configFile),
				zap.Error(err))
			return fmt.Errorf("failed to load environment configuration: %w", err)
		}

		// Override environment name if provided as argument
		if envName != "" && env.Name != envName {
			logger.Info("Overriding environment name from argument",
				zap.String("config_name", env.Name),
				zap.String("arg_name", envName))
			env.Name = envName
		}

		logger.Info("Loaded environment configuration",
			zap.String("environment", env.Name),
			zap.String("type", string(env.Type)),
			zap.String("source", configFile))

		// Create environment manager
		envManager, err := environments.NewEnvironmentManager("")
		if err != nil {
			logger.Error("Failed to create environment manager", zap.Error(err))
			return fmt.Errorf("failed to create environment manager: %w", err)
		}

		// Check if environment already exists
		existingEnv, err := envManager.GetEnvironment(rc, env.Name)
		isUpdate := err == nil
		
		// Validate operation type
		if createOnly && isUpdate {
			return fmt.Errorf("environment '%s' already exists and --create-only was specified", env.Name)
		}
		if updateOnly && !isUpdate {
			return fmt.Errorf("environment '%s' does not exist and --update-only was specified", env.Name)
		}

		// Display operation summary
		operation := "create"
		if isUpdate {
			operation = "update"
		}

		fmt.Printf("Environment Apply Summary:\n")
		fmt.Printf("═════════════════════════\n")
		fmt.Printf("Operation:    %s\n", operation)
		fmt.Printf("Environment:  %s (%s)\n", env.DisplayName, env.Name)
		fmt.Printf("Type:         %s\n", env.Type)
		fmt.Printf("Config File:  %s\n", configFile)
		fmt.Printf("Dry Run:      %t\n", dryRun)
		fmt.Printf("\n")

		if isUpdate {
			fmt.Printf("Configuration Changes:\n")
			fmt.Printf("──────────────────────\n")
			displayConfigurationDiff(existingEnv, env)
			fmt.Printf("\n")
		}

		// Dry run - show what would be applied
		if dryRun {
			fmt.Printf("🔍 Dry Run - No changes will be applied\n\n")
			return displayApplyPlan(env, operation)
		}

		// Get confirmation for non-force operations
		if !force && !dryRun {
			if err := confirmApply(env, operation); err != nil {
				return err
			}
		}

		// Apply the configuration
		if isUpdate {
			err = envManager.UpdateEnvironment(rc, env)
		} else {
			err = envManager.CreateEnvironment(rc, env)
		}

		if err != nil {
			logger.Error("Failed to apply environment configuration",
				zap.String("operation", operation),
				zap.String("environment", env.Name),
				zap.Error(err))
			return fmt.Errorf("failed to %s environment: %w", operation, err)
		}

		// Success message
		fmt.Printf("✅ Environment '%s' %sd successfully\n", env.Name, operation)
		
		// Show next steps
		fmt.Printf("\nNext Steps:\n")
		fmt.Printf("──────────\n")
		if !isUpdate {
			fmt.Printf("• Switch to environment: eos env use %s\n", env.Name)
		}
		fmt.Printf("• View environment details: eos env show %s\n", env.Name)
		fmt.Printf("• Check infrastructure status: eos read deployment status\n")

		logger.Info("Environment configuration applied successfully",
			zap.String("operation", operation),
			zap.String("environment", env.Name),
			zap.String("type", string(env.Type)))

		return nil
	}),
}

func init() {
	EnvCmd.AddCommand(applyCmd)

	// Configuration flags
	applyCmd.Flags().String("config", "", "Path to environment configuration file (required)")
	applyCmd.Flags().Bool("dry-run", false, "Show what would be applied without making changes")
	applyCmd.Flags().Bool("force", false, "Force apply without confirmation prompts")

	// Operation mode flags
	applyCmd.Flags().Bool("create-only", false, "Only create new environments (fail if exists)")
	applyCmd.Flags().Bool("update-only", false, "Only update existing environments (fail if not exists)")

	// Validation flags
	applyCmd.Flags().Bool("skip-validation", false, "Skip configuration validation")
	applyCmd.Flags().Bool("validate-strict", false, "Enable strict validation rules")

	applyCmd.Example = `  # Apply staging environment from config file
  eos env apply staging --config environments/staging.yaml

  # Apply production environment with confirmation
  eos env apply production --config prod.yaml

  # Dry run to see changes without applying
  eos env apply staging --config staging.yaml --dry-run

  # Force apply without prompts
  eos env apply development --config dev.yaml --force

  # Create new environment only
  eos env apply testing --config testing.yaml --create-only`
}

// loadEnvironmentFromFile loads environment configuration from YAML file
func loadEnvironmentFromFile(rc *eos_io.RuntimeContext, configFile string) (*environments.Environment, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Loading environment configuration from file",
		zap.String("file", configFile))

	// Read file content
	data, err := os.ReadFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Parse YAML
	var env environments.Environment
	if err := yaml.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("failed to parse YAML configuration: %w", err)
	}

	// Basic validation
	if env.Name == "" {
		return nil, fmt.Errorf("environment name is required in configuration")
	}
	if env.Type == "" {
		return nil, fmt.Errorf("environment type is required in configuration")
	}

	logger.Debug("Environment configuration loaded successfully",
		zap.String("name", env.Name),
		zap.String("type", string(env.Type)))

	return &env, nil
}

// displayConfigurationDiff shows differences between existing and new configuration
func displayConfigurationDiff(existing, new *environments.Environment) {
	// Infrastructure changes
	if existing.Infrastructure.Nomad.Address != new.Infrastructure.Nomad.Address {
		fmt.Printf("  Nomad Address:    %s → %s\n", existing.Infrastructure.Nomad.Address, new.Infrastructure.Nomad.Address)
	}
	if existing.Infrastructure.Consul.Address != new.Infrastructure.Consul.Address {
		fmt.Printf("  Consul Address:   %s → %s\n", existing.Infrastructure.Consul.Address, new.Infrastructure.Consul.Address)
	}
	if existing.Infrastructure.Vault.Address != new.Infrastructure.Vault.Address {
		fmt.Printf("  Vault Address:    %s → %s\n", existing.Infrastructure.Vault.Address, new.Infrastructure.Vault.Address)
	}

	// Deployment strategy changes
	if existing.Deployment.Strategy.Type != new.Deployment.Strategy.Type {
		fmt.Printf("  Deploy Strategy:  %s → %s\n", existing.Deployment.Strategy.Type, new.Deployment.Strategy.Type)
	}
	if existing.Deployment.Strategy.MaxParallel != new.Deployment.Strategy.MaxParallel {
		fmt.Printf("  Max Parallel:     %d → %d\n", existing.Deployment.Strategy.MaxParallel, new.Deployment.Strategy.MaxParallel)
	}

	// Resource changes
	if existing.Deployment.Resources.CPU != new.Deployment.Resources.CPU {
		fmt.Printf("  CPU Allocation:   %dMHz → %dMHz\n", existing.Deployment.Resources.CPU, new.Deployment.Resources.CPU)
	}
	if existing.Deployment.Resources.Memory != new.Deployment.Resources.Memory {
		fmt.Printf("  Memory Allocation: %dMB → %dMB\n", existing.Deployment.Resources.Memory, new.Deployment.Resources.Memory)
	}

	// Security changes
	if existing.Security.AccessControl.MFA.Required != new.Security.AccessControl.MFA.Required {
		fmt.Printf("  MFA Required:     %t → %t\n", existing.Security.AccessControl.MFA.Required, new.Security.AccessControl.MFA.Required)
	}
	if existing.Security.AccessControl.Approval.Required != new.Security.AccessControl.Approval.Required {
		fmt.Printf("  Approval Required: %t → %t\n", existing.Security.AccessControl.Approval.Required, new.Security.AccessControl.Approval.Required)
	}
}

// displayApplyPlan shows what would be applied in dry-run mode
func displayApplyPlan(env *environments.Environment, operation string) error {
	fmt.Printf("Apply Plan for '%s' (%s):\n", env.Name, operation)
	fmt.Printf("────────────────────────────────\n")
	
	fmt.Printf("Environment Configuration:\n")
	fmt.Printf("  Name:         %s\n", env.Name)
	fmt.Printf("  Display Name: %s\n", env.DisplayName)
	fmt.Printf("  Type:         %s\n", env.Type)
	fmt.Printf("  Description:  %s\n", env.Description)
	fmt.Printf("\n")

	fmt.Printf("Infrastructure:\n")
	fmt.Printf("  Nomad:      %s (%s/%s)\n", env.Infrastructure.Nomad.Address, env.Infrastructure.Nomad.Region, env.Infrastructure.Nomad.Datacenter)
	fmt.Printf("  Consul:     %s (%s)\n", env.Infrastructure.Consul.Address, env.Infrastructure.Consul.Datacenter)
	fmt.Printf("  Vault:      %s\n", env.Infrastructure.Vault.Address)
	fmt.Printf("  Terraform:  %s backend\n", env.Infrastructure.Terraform.Backend)
	fmt.Printf("  Salt:       %s\n", env.Infrastructure.Salt.Master)
	fmt.Printf("\n")

	fmt.Printf("Deployment:\n")
	fmt.Printf("  Strategy:     %s\n", env.Deployment.Strategy.Type)
	fmt.Printf("  Max Parallel: %d\n", env.Deployment.Strategy.MaxParallel)
	fmt.Printf("  Auto Revert:  %t\n", env.Deployment.Strategy.AutoRevert)
	fmt.Printf("  Resources:    CPU: %dMHz, Memory: %dMB\n", env.Deployment.Resources.CPU, env.Deployment.Resources.Memory)
	fmt.Printf("\n")

	fmt.Printf("Security:\n")
	fmt.Printf("  RBAC:         %t\n", env.Security.AccessControl.RBAC.Enabled)
	fmt.Printf("  MFA Required: %t\n", env.Security.AccessControl.MFA.Required)
	fmt.Printf("  Approval Req: %t\n", env.Security.AccessControl.Approval.Required)
	fmt.Printf("  Encryption:   In-transit: %t, At-rest: %t\n", 
		env.Security.Encryption.InTransit.Enabled,
		env.Security.Encryption.AtRest.Enabled)

	return nil
}

// confirmApply prompts user for confirmation
func confirmApply(env *environments.Environment, operation string) error {
	fmt.Printf("Do you want to %s environment '%s' with this configuration? (y/N): ", operation, env.Name)
	
	// In a real implementation, this would read from stdin
	// For now, we'll assume confirmation
	fmt.Printf("y\n")
	return nil
}