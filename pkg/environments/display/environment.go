// pkg/environments/display/environment.go
//
// Environment display formatting logic.
// Migrated from cmd/read/env.go to consolidate environment display operations.
//
// Functions migrated:
//   - displayEnvironmentTable() → ShowEnvironmentTable()
//   - displayDetailedConfiguration() → ShowDetailedConfiguration()
//   - displayEnvironmentJSON() → ShowEnvironmentJSON()
//   - displayEnvironmentYAML() → ShowEnvironmentYAML()
//   - enabledStatus() → formatEnabledStatus()

package display

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/environments"
	"gopkg.in/yaml.v3"
)

// ShowEnvironmentTable displays environment in table format.
// Migrated from cmd/read/env.go displayEnvironmentTable().
//
// Parameters:
//   - env: Environment to display
//   - detailed: If true, show detailed configuration sections
func ShowEnvironmentTable(env *environments.Environment, detailed bool) error {
	if env == nil {
		return fmt.Errorf("environment cannot be nil")
	}

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
	fmt.Printf("RBAC:         %s\n", formatEnabledStatus(env.Security.AccessControl.RBAC.Enabled))
	fmt.Printf("MFA Required: %s\n", formatEnabledStatus(env.Security.AccessControl.MFA.Required))
	fmt.Printf("Approval Req: %s\n", formatEnabledStatus(env.Security.AccessControl.Approval.Required))
	fmt.Printf("Network Policy: %s\n", formatEnabledStatus(env.Security.NetworkPolicy.Enabled))
	fmt.Printf("Encryption:   In-transit: %s, At-rest: %s\n",
		formatEnabledStatus(env.Security.Encryption.InTransit.Enabled),
		formatEnabledStatus(env.Security.Encryption.AtRest.Enabled))
	fmt.Printf("\n")

	// Monitoring section
	fmt.Printf("Monitoring Configuration:\n")
	fmt.Printf("─────────────────────────\n")
	fmt.Printf("Metrics:   %s (%s, interval: %s)\n",
		formatEnabledStatus(env.Monitoring.Metrics.Enabled),
		env.Monitoring.Metrics.Provider,
		env.Monitoring.Metrics.Interval)
	fmt.Printf("Logging:   %s (level: %s, format: %s)\n",
		formatEnabledStatus(env.Monitoring.Logging.Enabled),
		env.Monitoring.Logging.Level,
		env.Monitoring.Logging.Format)
	fmt.Printf("Tracing:   %s\n", formatEnabledStatus(env.Monitoring.Tracing.Enabled))
	fmt.Printf("Alerting:  %s\n", formatEnabledStatus(env.Monitoring.Alerting.Enabled))
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
		return ShowDetailedConfiguration(env)
	}

	return nil
}

// ShowDetailedConfiguration displays detailed environment configuration.
// Migrated from cmd/read/env.go displayDetailedConfiguration().
//
// Parameters:
//   - env: Environment to display details for
func ShowDetailedConfiguration(env *environments.Environment) error {
	if env == nil {
		return fmt.Errorf("environment cannot be nil")
	}

	fmt.Printf("Detailed Configuration:\n")
	fmt.Printf("═══════════════════════\n\n")

	// Infrastructure details
	fmt.Printf("Infrastructure Details:\n")
	fmt.Printf("───────────────────────\n")

	// Nomad details
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "COMPONENT\tENDPOINT\tREGION/DC\tNAMESPACE\tTLS")
	_, _ = fmt.Fprintf(w, "Nomad\t%s\t%s/%s\t%s\t%s\n",
		env.Infrastructure.Nomad.Address,
		env.Infrastructure.Nomad.Region,
		env.Infrastructure.Nomad.Datacenter,
		env.Infrastructure.Nomad.Namespace,
		formatEnabledStatus(env.Infrastructure.Nomad.TLS.Enabled))
	_, _ = fmt.Fprintf(w, "Consul\t%s\t%s\t-\t%s\n",
		env.Infrastructure.Consul.Address,
		env.Infrastructure.Consul.Datacenter,
		formatEnabledStatus(env.Infrastructure.Consul.TLS.Enabled))
	_, _ = fmt.Fprintf(w, "Vault\t%s\t-\t%s\t%s\n",
		env.Infrastructure.Vault.Address,
		env.Infrastructure.Vault.Namespace,
		formatEnabledStatus(env.Infrastructure.Vault.TLS.Enabled))
	_ = w.Flush()
	fmt.Printf("\n")

	// Deployment strategy details
	fmt.Printf("Deployment Strategy Details:\n")
	fmt.Printf("────────────────────────────\n")
	fmt.Printf("Type:              %s\n", env.Deployment.Strategy.Type)
	fmt.Printf("Max Parallel:      %d\n", env.Deployment.Strategy.MaxParallel)
	fmt.Printf("Min Healthy Time:  %s\n", env.Deployment.Strategy.MinHealthyTime)
	fmt.Printf("Healthy Deadline:  %s\n", env.Deployment.Strategy.HealthyDeadline)
	fmt.Printf("Progress Deadline: %s\n", env.Deployment.Strategy.ProgressDeadline)
	fmt.Printf("Auto Revert:       %s\n", formatEnabledStatus(env.Deployment.Strategy.AutoRevert))
	fmt.Printf("Auto Promote:      %s\n", formatEnabledStatus(env.Deployment.Strategy.AutoPromote))
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
			formatEnabledStatus(env.Security.AccessControl.Approval.Required),
			env.Security.AccessControl.Approval.MinApprovals,
			env.Security.AccessControl.Approval.Timeout)
	}
	if env.Security.AccessControl.MFA.Required {
		fmt.Printf("MFA Configuration: Required, Grace Period: %s\n",
			env.Security.AccessControl.MFA.GracePeriod)
	}
	fmt.Printf("Audit Logging:     %s\n", formatEnabledStatus(env.Security.AccessControl.Audit.Enabled))
	fmt.Printf("Secret Scanning:   %s\n", formatEnabledStatus(env.Security.SecretScanning.Enabled))
	fmt.Printf("\n")

	return nil
}

// ShowEnvironmentJSON displays environment in JSON format.
// Migrated from cmd/read/env.go displayEnvironmentJSON().
// FIXED: Now uses proper JSON marshaling instead of manual construction.
//
// Parameters:
//   - env: Environment to display as JSON
func ShowEnvironmentJSON(env *environments.Environment) error {
	if env == nil {
		return fmt.Errorf("environment cannot be nil")
	}

	// Use proper JSON marshaling with indentation
	jsonData, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal environment to JSON: %w", err)
	}

	// Print the JSON output
	fmt.Println(string(jsonData))
	return nil
}

// ShowEnvironmentYAML displays environment in YAML format.
// Migrated from cmd/read/env.go displayEnvironmentYAML().
// FIXED: Now uses proper YAML marshaling instead of manual fmt.Printf.
//
// Parameters:
//   - env: Environment to display as YAML
func ShowEnvironmentYAML(env *environments.Environment) error {
	if env == nil {
		return fmt.Errorf("environment cannot be nil")
	}

	// Use proper YAML marshaling (fixed from manual fmt.Printf)
	yamlData, err := yaml.Marshal(env)
	if err != nil {
		return fmt.Errorf("failed to marshal environment to YAML: %w", err)
	}

	// Print the YAML output
	fmt.Print(string(yamlData))
	return nil
}

// formatEnabledStatus returns "enabled" or "disabled" string.
// Migrated from cmd/read/env.go enabledStatus().
func formatEnabledStatus(enabled bool) string {
	if enabled {
		return "enabled"
	}
	return "disabled"
}
