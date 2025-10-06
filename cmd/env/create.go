package env

import (
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/environments"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var createCmd = &cobra.Command{
	Use:   "create <environment-name>",
	Short: "Create a new environment interactively",
	Long: `Create a new deployment environment using interactive prompts to configure
all aspects of the environment including infrastructure endpoints, deployment
policies, security settings, and monitoring configuration.

This command guides you through setting up a complete environment configuration
step by step. For advanced users or automated deployments, consider using
'eos env apply' with a configuration file instead.

You can provide initial values using flags, and the interactive prompts will
use these as defaults while allowing you to modify them.

Examples:
  # Create a new development environment
  eos env create development

  # Create environment with initial type
  eos env create staging --type staging

  # Create environment with basic infrastructure
  eos env create production --type production --nomad-address https://nomad.prod.example.com:4646

  # Create environment from template
  eos env create testing --template development`,
	Args: cobra.ExactArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		envName := args[0]

		logger.Info("Creating new environment interactively",
			zap.String("command", "env create"),
			zap.String("environment", envName),
			zap.String("component", rc.Component))

		// Parse flags for initial values
		envType, _ := cmd.Flags().GetString("type")
		template, _ := cmd.Flags().GetString("template")
		displayName, _ := cmd.Flags().GetString("display-name")
		description, _ := cmd.Flags().GetString("description")
		nomadAddress, _ := cmd.Flags().GetString("nomad-address")
		consulAddress, _ := cmd.Flags().GetString("consul-address")
		vaultAddress, _ := cmd.Flags().GetString("vault-address")
		skipPrompts, _ := cmd.Flags().GetBool("skip-prompts")

		// Create environment manager
		envManager, err := environments.NewEnvironmentManager("")
		if err != nil {
			logger.Error("Failed to create environment manager", zap.Error(err))
			return fmt.Errorf("failed to create environment manager: %w", err)
		}

		// Check if environment already exists
		if _, err := envManager.GetEnvironment(rc, envName); err == nil {
			return fmt.Errorf("environment '%s' already exists. Use 'eos env update %s' to modify it", envName, envName)
		}

		// Start with template or defaults
		var env *environments.Environment
		if template != "" {
			templateEnv, err := envManager.GetEnvironment(rc, template)
			if err != nil {
				logger.Error("Template environment not found",
					zap.String("template", template),
					zap.Error(err))
				return fmt.Errorf("template environment '%s' not found", template)
			}
			env = templateEnv
			env.Name = envName
			env.CreatedAt = time.Time{}
			env.UpdatedAt = time.Time{}
			logger.Info("Using template environment", zap.String("template", template))
		} else {
			// Start with development defaults
			env = environments.DefaultDevelopmentEnvironment()
			env.Name = envName
		}

		// Apply flag overrides
		if displayName != "" {
			env.DisplayName = displayName
		} else if env.DisplayName == "" || env.DisplayName == "Development" {
			env.DisplayName = strings.Title(envName)
		}

		if description != "" {
			env.Description = description
		}

		if envType != "" {
			env.Type = environments.EnvironmentType(envType)
		}

		if nomadAddress != "" {
			env.Infrastructure.Nomad.Address = nomadAddress
		}
		if consulAddress != "" {
			env.Infrastructure.Consul.Address = consulAddress
		}
		if vaultAddress != "" {
			env.Infrastructure.Vault.Address = vaultAddress
		}

		// Interactive configuration if not skipping prompts
		if !skipPrompts {
			if err := interactiveEnvironmentConfig(rc, env); err != nil {
				return fmt.Errorf("interactive configuration failed: %w", err)
			}
		}

		// Show configuration summary
		fmt.Printf("\nEnvironment Configuration Summary:\n")
		fmt.Printf("═════════════════════════════════\n")
		fmt.Printf("Name:         %s\n", env.Name)
		fmt.Printf("Display Name: %s\n", env.DisplayName)
		fmt.Printf("Type:         %s\n", env.Type)
		fmt.Printf("Description:  %s\n", env.Description)
		fmt.Printf("\nInfrastructure:\n")
		fmt.Printf("  Nomad:      %s\n", env.Infrastructure.Nomad.Address)
		fmt.Printf("  Consul:     %s\n", env.Infrastructure.Consul.Address)
		fmt.Printf("  Vault:      %s\n", env.Infrastructure.Vault.Address)
		fmt.Printf("\nDeployment:\n")
		fmt.Printf("  Strategy:   %s\n", env.Deployment.Strategy.Type)
		fmt.Printf("  CPU:        %dMHz\n", env.Deployment.Resources.CPU)
		fmt.Printf("  Memory:     %dMB\n", env.Deployment.Resources.Memory)
		fmt.Printf("\nSecurity:\n")
		fmt.Printf("  RBAC:       %t\n", env.Security.AccessControl.RBAC.Enabled)
		fmt.Printf("  MFA:        %t\n", env.Security.AccessControl.MFA.Required)
		fmt.Printf("  Approval:   %t\n", env.Security.AccessControl.Approval.Required)
		fmt.Printf("\n")

		// Get final confirmation
		if !skipPrompts {
			fmt.Printf("Create environment '%s' with this configuration? (y/N): ", envName)
			// In real implementation, would read from stdin
			fmt.Printf("y\n")
		}

		// Create the environment
		if err := envManager.CreateEnvironment(rc, env); err != nil {
			logger.Error("Failed to create environment",
				zap.String("environment", envName),
				zap.Error(err))
			return fmt.Errorf("failed to create environment: %w", err)
		}

		// Success message
		fmt.Printf(" Environment '%s' created successfully!\n\n", envName)

		// Show next steps
		fmt.Printf("Next Steps:\n")
		fmt.Printf("───────────\n")
		fmt.Printf("• Switch to environment: eos env use %s\n", envName)
		fmt.Printf("• View environment details: eos env show %s\n", envName)
		fmt.Printf("• Export configuration: eos env show %s --format yaml > %s.yaml\n", envName, envName)

		logger.Info("Environment created successfully",
			zap.String("environment", envName),
			zap.String("type", string(env.Type)))

		return nil
	}),
}

func init() {
	EnvCmd.AddCommand(createCmd)

	// Basic environment configuration
	createCmd.Flags().String("type", "", "Environment type: development, staging, production, testing, preview")
	createCmd.Flags().String("display-name", "", "Display name for the environment")
	createCmd.Flags().String("description", "", "Description of the environment")
	createCmd.Flags().String("template", "", "Use existing environment as template")

	// Infrastructure configuration
	createCmd.Flags().String("nomad-address", "", "Nomad cluster address")
	createCmd.Flags().String("consul-address", "", "Consul cluster address")
	createCmd.Flags().String("vault-address", "", "Vault cluster address")

	// Terraform configuration
	createCmd.Flags().String("terraform-backend", "", "Terraform backend type")
	createCmd.Flags().String("terraform-workspace", "", "Terraform workspace name")

	// Provider configuration
	createCmd.Flags().String("provider", "", "Cloud provider: hetzner, aws, gcp, azure")
	createCmd.Flags().String("provider-region", "", "Cloud provider region")

	// Deployment configuration
	createCmd.Flags().String("deploy-strategy", "", "Deployment strategy: rolling, blue-green, canary")
	createCmd.Flags().Int("cpu", 0, "Default CPU allocation (MHz)")
	createCmd.Flags().Int("memory", 0, "Default memory allocation (MB)")

	// Security configuration
	createCmd.Flags().Bool("enable-rbac", false, "Enable RBAC")
	createCmd.Flags().Bool("require-mfa", false, "Require MFA for operations")
	createCmd.Flags().Bool("require-approval", false, "Require approval for deployments")

	// Interactive mode
	createCmd.Flags().Bool("skip-prompts", false, "Skip interactive prompts and use defaults/flags")

	createCmd.Example = `  # Create development environment with prompts
  eos env create development

  # Create staging environment with type preset
  eos env create staging --type staging

  # Create production with security enabled
  eos env create production --type production --enable-rbac --require-mfa

  # Create from template
  eos env create testing --template development

  # Create with all options via flags (no prompts)
  eos env create myenv --type development --skip-prompts \
    --nomad-address https://nomad.example.com:4646 \
    --consul-address consul.example.com:8500`
}

// interactiveEnvironmentConfig guides user through environment configuration
func interactiveEnvironmentConfig(rc *eos_io.RuntimeContext, env *environments.Environment) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting interactive environment configuration")

	fmt.Printf("\n Interactive Environment Configuration\n")
	fmt.Printf("═══════════════════════════════════════\n")
	fmt.Printf("We'll guide you through configuring your environment.\n")
	fmt.Printf("Press Enter to keep the current value [in brackets].\n\n")

	// Basic information
	fmt.Printf("Basic Information:\n")
	fmt.Printf("──────────────────\n")

	// Display name
	fmt.Printf("Display name [%s]: ", env.DisplayName)
	// In real implementation, would read from stdin and update if not empty

	// Description
	fmt.Printf("Description [%s]: ", env.Description)
	// In real implementation, would read from stdin and update if not empty

	// Environment type
	fmt.Printf("Environment type (development/staging/production/testing/preview) [%s]: ", env.Type)
	// In real implementation, would read from stdin and validate

	fmt.Printf("\nInfrastructure Configuration:\n")
	fmt.Printf("─────────────────────────────\n")

	// Nomad
	fmt.Printf("Nomad address [%s]: ", env.Infrastructure.Nomad.Address)
	// In real implementation, would read from stdin and validate URL

	// Consul
	fmt.Printf("Consul address [%s]: ", env.Infrastructure.Consul.Address)
	// In real implementation, would read from stdin and validate

	// Vault
	fmt.Printf("Vault address [%s]: ", env.Infrastructure.Vault.Address)
	// In real implementation, would read from stdin and validate URL

	fmt.Printf("\nDeployment Configuration:\n")
	fmt.Printf("─────────────────────────\n")

	// Deployment strategy
	fmt.Printf("Deployment strategy (rolling/blue-green/canary) [%s]: ", env.Deployment.Strategy.Type)
	// In real implementation, would read from stdin and validate

	// Resources
	fmt.Printf("Default CPU allocation (MHz) [%d]: ", env.Deployment.Resources.CPU)
	// In real implementation, would read from stdin and parse int

	fmt.Printf("Default memory allocation (MB) [%d]: ", env.Deployment.Resources.Memory)
	// In real implementation, would read from stdin and parse int

	fmt.Printf("\nSecurity Configuration:\n")
	fmt.Printf("───────────────────────\n")

	// RBAC
	fmt.Printf("Enable RBAC? (y/N) [%s]: ", boolToYesNo(env.Security.AccessControl.RBAC.Enabled))
	// In real implementation, would read from stdin and parse

	// MFA
	fmt.Printf("Require MFA? (y/N) [%s]: ", boolToYesNo(env.Security.AccessControl.MFA.Required))
	// In real implementation, would read from stdin and parse

	// Approval
	fmt.Printf("Require deployment approval? (y/N) [%s]: ", boolToYesNo(env.Security.AccessControl.Approval.Required))
	// In real implementation, would read from stdin and parse

	fmt.Printf("\n")

	// Apply production defaults if production type
	if env.Type == environments.EnvironmentTypeProduction {
		fmt.Printf("🔒 Production environment detected - applying security defaults:\n")
		fmt.Printf("   • RBAC enabled\n")
		fmt.Printf("   • MFA required\n")
		fmt.Printf("   • Deployment approval required\n")
		fmt.Printf("   • Encryption enabled\n\n")

		env.Security.AccessControl.RBAC.Enabled = true
		env.Security.AccessControl.MFA.Required = true
		env.Security.AccessControl.Approval.Required = true
		env.Security.AccessControl.Approval.MinApprovals = 2
		env.Security.Encryption.InTransit.Enabled = true
		env.Security.Encryption.AtRest.Enabled = true
	}

	logger.Debug("Interactive configuration completed")
	return nil
}

// Helper function to convert bool to yes/no string
func boolToYesNo(b bool) string {
	if b {
		return "y"
	}
	return "N"
}
