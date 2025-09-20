package env

import (
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/environments"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var showCmd = &cobra.Command{
	Use:   "show [environment-name]",
	Short: "Show detailed information about an environment",
	Long: `Show detailed information about a deployment environment including its
infrastructure configuration, deployment settings, security policies, and
current status.

If no environment name is provided, shows information about the current
environment. Use the --detailed flag to show comprehensive configuration
details including infrastructure endpoints, security settings, and monitoring
configuration.

Examples:
  # Show current environment details
  eos env show

  # Show specific environment
  eos env show production

  # Show detailed configuration
  eos env show production --detailed

  # Show in JSON format
  eos env show staging --format json`,
	Args: cobra.MaximumNArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		logger.Info("Showing environment details",
			zap.String("command", "env show"),
			zap.String("component", rc.Component))

		// Parse flags
		detailed, _ := cmd.Flags().GetBool("detailed")
		format, _ := cmd.Flags().GetString("format")

		// Create environment manager
		envManager, err := environments.NewEnvironmentManager("")
		if err != nil {
			logger.Error("Failed to create environment manager", zap.Error(err))
			return fmt.Errorf("failed to create environment manager: %w", err)
		}

		// Determine which environment to show
		var envName string
		if len(args) > 0 {
			envName = args[0]
		} else {
			// Show current environment
			currentEnv, err := envManager.GetCurrentEnvironment(rc)
			if err != nil {
				logger.Error("No current environment set and no environment specified", zap.Error(err))
				return fmt.Errorf("no current environment set and no environment specified. Use 'eos env use <environment>' to set one or specify an environment name")
			}
			envName = currentEnv.Name
		}

		// Get environment details
		env, err := envManager.GetEnvironment(rc, envName)
		if err != nil {
			logger.Error("Failed to get environment", zap.String("environment", envName), zap.Error(err))
			return fmt.Errorf("failed to get environment %s: %w", envName, err)
		}

		logger.Debug("Retrieved environment details",
			zap.String("environment", envName),
			zap.String("type", string(env.Type)),
			zap.String("status", string(env.Status)))

		// Display environment information
		switch format {
		case "json":
			return displayEnvironmentJSON(env)
		case "yaml":
			return displayEnvironmentYAML(env)
		default:
			return displayEnvironmentTable(env, detailed)
		}
	}),
}

func init() {
	EnvCmd.AddCommand(showCmd)

	// Output formatting flags
	showCmd.Flags().String("format", "table", "Output format: table, json, yaml")
	showCmd.Flags().Bool("detailed", false, "Show detailed environment configuration")

	// Section flags for detailed view
	showCmd.Flags().Bool("infrastructure", false, "Show only infrastructure configuration")
	showCmd.Flags().Bool("deployment", false, "Show only deployment configuration")
	showCmd.Flags().Bool("security", false, "Show only security configuration")
	showCmd.Flags().Bool("monitoring", false, "Show only monitoring configuration")

	showCmd.Example = `  # Show current environment
  eos env show

  # Show production environment details
  eos env show production

  # Show detailed infrastructure configuration
  eos env show production --detailed --infrastructure

  # Show environment in JSON format
  eos env show staging --format json`
}

// displayEnvironmentTable displays environment in table format
func displayEnvironmentTable(env *environments.Environment, detailed bool) error {
	// Basic environment information
	fmt.Printf("Environment: %s (%s)\n", env.DisplayName, env.Name)
	fmt.Printf("═══════════════════════════════════\n")
	fmt.Printf("Type:        %s\n", env.Type)
	fmt.Printf("Status:      %s\n", env.Status)
	fmt.Printf("Description: %s\n", env.Description)
	fmt.Printf("Created:     %s\n", env.CreatedAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("Updated:     %s\n", env.UpdatedAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("\n")

	// Infrastructure section
	fmt.Printf("Infrastructure:\n")
	fmt.Printf("───────────────\n")
	fmt.Printf("Nomad:     %s (region: %s, dc: %s)\n",
		env.Infrastructure.Nomad.Address,
		env.Infrastructure.Nomad.Region,
		env.Infrastructure.Nomad.Datacenter)
	fmt.Printf("Consul:    %s (dc: %s)\n",
		env.Infrastructure.Consul.Address,
		env.Infrastructure.Consul.Datacenter)
	fmt.Printf("Vault:     %s\n", env.Infrastructure.Vault.Address)

	fmt.Printf("Terraform: %s backend, workspace: %s\n",
		env.Infrastructure.Terraform.Backend,
		env.Infrastructure.Terraform.Workspace)
	fmt.Printf("Provider:  %s (%s)\n",
		env.Infrastructure.Provider.Name,
		env.Infrastructure.Provider.Region)
	fmt.Printf("\n")

	// Deployment section
	fmt.Printf("Deployment Configuration:\n")
	fmt.Printf("─────────────────────────\n")
	fmt.Printf("Strategy:     %s\n", env.Deployment.Strategy.Type)
	fmt.Printf("Max Parallel: %d\n", env.Deployment.Strategy.MaxParallel)
	fmt.Printf("Auto Revert:  %t\n", env.Deployment.Strategy.AutoRevert)
	fmt.Printf("Auto Promote: %t\n", env.Deployment.Strategy.AutoPromote)
	fmt.Printf("Resources:    CPU: %dMHz, Memory: %dMB (max: %dMB)\n",
		env.Deployment.Resources.CPU,
		env.Deployment.Resources.Memory,
		env.Deployment.Resources.MemoryMax)
	fmt.Printf("\n")

	// Security section
	fmt.Printf("Security Configuration:\n")
	fmt.Printf("───────────────────────\n")
	fmt.Printf("RBAC:         %s\n", enabledStatus(env.Security.AccessControl.RBAC.Enabled))
	fmt.Printf("MFA Required: %s\n", enabledStatus(env.Security.AccessControl.MFA.Required))
	fmt.Printf("Approval Req: %s\n", enabledStatus(env.Security.AccessControl.Approval.Required))
	fmt.Printf("Network Policy: %s\n", enabledStatus(env.Security.NetworkPolicy.Enabled))
	fmt.Printf("Encryption:   In-transit: %s, At-rest: %s\n",
		enabledStatus(env.Security.Encryption.InTransit.Enabled),
		enabledStatus(env.Security.Encryption.AtRest.Enabled))
	fmt.Printf("\n")

	// Monitoring section
	fmt.Printf("Monitoring Configuration:\n")
	fmt.Printf("─────────────────────────\n")
	fmt.Printf("Metrics:   %s (%s, interval: %s)\n",
		enabledStatus(env.Monitoring.Metrics.Enabled),
		env.Monitoring.Metrics.Provider,
		env.Monitoring.Metrics.Interval)
	fmt.Printf("Logging:   %s (level: %s, format: %s)\n",
		enabledStatus(env.Monitoring.Logging.Enabled),
		env.Monitoring.Logging.Level,
		env.Monitoring.Logging.Format)
	fmt.Printf("Tracing:   %s\n", enabledStatus(env.Monitoring.Tracing.Enabled))
	fmt.Printf("Alerting:  %s\n", enabledStatus(env.Monitoring.Alerting.Enabled))
	fmt.Printf("\n")

	// Metadata section
	if env.Metadata.Owner != "" || env.Metadata.Team != "" {
		fmt.Printf("Metadata:\n")
		fmt.Printf("─────────\n")
		if env.Metadata.Owner != "" {
			fmt.Printf("Owner:       %s\n", env.Metadata.Owner)
		}
		if env.Metadata.Team != "" {
			fmt.Printf("Team:        %s\n", env.Metadata.Team)
		}
		if env.Metadata.Project != "" {
			fmt.Printf("Project:     %s\n", env.Metadata.Project)
		}
		if env.Metadata.CostCenter != "" {
			fmt.Printf("Cost Center: %s\n", env.Metadata.CostCenter)
		}
		if env.Metadata.Purpose != "" {
			fmt.Printf("Purpose:     %s\n", env.Metadata.Purpose)
		}
		fmt.Printf("\n")
	}

	if detailed {
		return displayDetailedConfiguration(env)
	}

	return nil
}

// displayDetailedConfiguration shows comprehensive configuration details
func displayDetailedConfiguration(env *environments.Environment) error {
	fmt.Printf("Detailed Configuration:\n")
	fmt.Printf("═══════════════════════\n\n")

	// Infrastructure details
	fmt.Printf("Infrastructure Details:\n")
	fmt.Printf("───────────────────────\n")

	// Nomad details
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "COMPONENT\tENDPOINT\tREGION/DC\tNAMESPACE\tTLS")
	fmt.Fprintf(w, "Nomad\t%s\t%s/%s\t%s\t%s\n",
		env.Infrastructure.Nomad.Address,
		env.Infrastructure.Nomad.Region,
		env.Infrastructure.Nomad.Datacenter,
		env.Infrastructure.Nomad.Namespace,
		enabledStatus(env.Infrastructure.Nomad.TLS.Enabled))
	fmt.Fprintf(w, "Consul\t%s\t%s\t-\t%s\n",
		env.Infrastructure.Consul.Address,
		env.Infrastructure.Consul.Datacenter,
		enabledStatus(env.Infrastructure.Consul.TLS.Enabled))
	fmt.Fprintf(w, "Vault\t%s\t-\t%s\t%s\n",
		env.Infrastructure.Vault.Address,
		env.Infrastructure.Vault.Namespace,
		enabledStatus(env.Infrastructure.Vault.TLS.Enabled))
	w.Flush()
	fmt.Printf("\n")

	// Deployment strategy details
	fmt.Printf("Deployment Strategy Details:\n")
	fmt.Printf("────────────────────────────\n")
	fmt.Printf("Type:              %s\n", env.Deployment.Strategy.Type)
	fmt.Printf("Max Parallel:      %d\n", env.Deployment.Strategy.MaxParallel)
	fmt.Printf("Min Healthy Time:  %s\n", env.Deployment.Strategy.MinHealthyTime)
	fmt.Printf("Healthy Deadline:  %s\n", env.Deployment.Strategy.HealthyDeadline)
	fmt.Printf("Progress Deadline: %s\n", env.Deployment.Strategy.ProgressDeadline)
	fmt.Printf("Auto Revert:       %s\n", enabledStatus(env.Deployment.Strategy.AutoRevert))
	fmt.Printf("Auto Promote:      %s\n", enabledStatus(env.Deployment.Strategy.AutoPromote))
	if env.Deployment.Strategy.Type == "canary" {
		fmt.Printf("Canary Replicas:   %d\n", env.Deployment.Strategy.CanaryReplicas)
		fmt.Printf("Canary Duration:   %s\n", env.Deployment.Strategy.CanaryDuration)
	}
	fmt.Printf("\n")

	// Security details
	fmt.Printf("Security Details:\n")
	fmt.Printf("─────────────────\n")
	if env.Security.AccessControl.Approval.Required {
		fmt.Printf("Approval Required: %s (min: %d, timeout: %s)\n",
			enabledStatus(env.Security.AccessControl.Approval.Required),
			env.Security.AccessControl.Approval.MinApprovals,
			env.Security.AccessControl.Approval.Timeout)
	}
	if env.Security.AccessControl.MFA.Required {
		fmt.Printf("MFA Configuration: Required, Grace Period: %s\n",
			env.Security.AccessControl.MFA.GracePeriod)
	}
	fmt.Printf("Audit Logging:     %s\n", enabledStatus(env.Security.AccessControl.Audit.Enabled))
	fmt.Printf("Secret Scanning:   %s\n", enabledStatus(env.Security.SecretScanning.Enabled))
	fmt.Printf("\n")

	return nil
}

// displayEnvironmentJSON displays environment in JSON format
func displayEnvironmentJSON(env *environments.Environment) error {
	// This would implement proper JSON marshaling
	fmt.Printf("{\n")
	fmt.Printf("  \"name\": \"%s\",\n", env.Name)
	fmt.Printf("  \"display_name\": \"%s\",\n", env.DisplayName)
	fmt.Printf("  \"type\": \"%s\",\n", env.Type)
	fmt.Printf("  \"status\": \"%s\",\n", env.Status)
	fmt.Printf("  \"description\": \"%s\",\n", env.Description)
	fmt.Printf("  \"created_at\": \"%s\",\n", env.CreatedAt.Format(time.RFC3339))
	fmt.Printf("  \"updated_at\": \"%s\",\n", env.UpdatedAt.Format(time.RFC3339))
	fmt.Printf("  \"infrastructure\": {\n")
	fmt.Printf("    \"nomad\": {\n")
	fmt.Printf("      \"address\": \"%s\",\n", env.Infrastructure.Nomad.Address)
	fmt.Printf("      \"region\": \"%s\",\n", env.Infrastructure.Nomad.Region)
	fmt.Printf("      \"datacenter\": \"%s\",\n", env.Infrastructure.Nomad.Datacenter)
	fmt.Printf("      \"namespace\": \"%s\"\n", env.Infrastructure.Nomad.Namespace)
	fmt.Printf("    },\n")
	fmt.Printf("    \"consul\": {\n")
	fmt.Printf("      \"address\": \"%s\",\n", env.Infrastructure.Consul.Address)
	fmt.Printf("      \"datacenter\": \"%s\"\n", env.Infrastructure.Consul.Datacenter)
	fmt.Printf("    },\n")
	fmt.Printf("    \"vault\": {\n")
	fmt.Printf("      \"address\": \"%s\"\n", env.Infrastructure.Vault.Address)
	fmt.Printf("    }\n")
	fmt.Printf("  },\n")
	fmt.Printf("  \"deployment\": {\n")
	fmt.Printf("    \"strategy\": {\n")
	fmt.Printf("      \"type\": \"%s\",\n", env.Deployment.Strategy.Type)
	fmt.Printf("      \"max_parallel\": %d,\n", env.Deployment.Strategy.MaxParallel)
	fmt.Printf("      \"auto_revert\": %t,\n", env.Deployment.Strategy.AutoRevert)
	fmt.Printf("      \"auto_promote\": %t\n", env.Deployment.Strategy.AutoPromote)
	fmt.Printf("    },\n")
	fmt.Printf("    \"resources\": {\n")
	fmt.Printf("      \"cpu\": %d,\n", env.Deployment.Resources.CPU)
	fmt.Printf("      \"memory\": %d,\n", env.Deployment.Resources.Memory)
	fmt.Printf("      \"memory_max\": %d\n", env.Deployment.Resources.MemoryMax)
	fmt.Printf("    }\n")
	fmt.Printf("  }\n")
	fmt.Printf("}\n")
	return nil
}

// displayEnvironmentYAML displays environment in YAML format
func displayEnvironmentYAML(env *environments.Environment) error {
	// This would implement proper YAML marshaling
	fmt.Printf("name: %s\n", env.Name)
	fmt.Printf("display_name: %s\n", env.DisplayName)
	fmt.Printf("type: %s\n", env.Type)
	fmt.Printf("status: %s\n", env.Status)
	fmt.Printf("description: %s\n", env.Description)
	fmt.Printf("created_at: %s\n", env.CreatedAt.Format(time.RFC3339))
	fmt.Printf("updated_at: %s\n", env.UpdatedAt.Format(time.RFC3339))
	fmt.Printf("infrastructure:\n")
	fmt.Printf("  nomad:\n")
	fmt.Printf("    address: %s\n", env.Infrastructure.Nomad.Address)
	fmt.Printf("    region: %s\n", env.Infrastructure.Nomad.Region)
	fmt.Printf("    datacenter: %s\n", env.Infrastructure.Nomad.Datacenter)
	fmt.Printf("    namespace: %s\n", env.Infrastructure.Nomad.Namespace)
	fmt.Printf("  consul:\n")
	fmt.Printf("    address: %s\n", env.Infrastructure.Consul.Address)
	fmt.Printf("    datacenter: %s\n", env.Infrastructure.Consul.Datacenter)
	fmt.Printf("  vault:\n")
	fmt.Printf("    address: %s\n", env.Infrastructure.Vault.Address)
	fmt.Printf("deployment:\n")
	fmt.Printf("  strategy:\n")
	fmt.Printf("    type: %s\n", env.Deployment.Strategy.Type)
	fmt.Printf("    max_parallel: %d\n", env.Deployment.Strategy.MaxParallel)
	fmt.Printf("    auto_revert: %t\n", env.Deployment.Strategy.AutoRevert)
	fmt.Printf("    auto_promote: %t\n", env.Deployment.Strategy.AutoPromote)
	fmt.Printf("  resources:\n")
	fmt.Printf("    cpu: %d\n", env.Deployment.Resources.CPU)
	fmt.Printf("    memory: %d\n", env.Deployment.Resources.Memory)
	fmt.Printf("    memory_max: %d\n", env.Deployment.Resources.MemoryMax)
	return nil
}

// Helper function to display enabled/disabled status
func enabledStatus(enabled bool) string {
	if enabled {
		return "enabled"
	}
	return "disabled"
}
