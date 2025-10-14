package list

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/environments"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var envCmd = &cobra.Command{
	Use:   "list",
	Short: "List all deployment environments",
	Long: `List all deployment environments with their status and basic information.

This command displays all configured environments along with their type, status,
and key infrastructure endpoints. Use the --detailed flag to show additional
information about each environment.

Examples:
  # List all environments in table format
  eos list env

  # List environments with detailed information
  eos list env --detailed

  # List environments in JSON format
  eos list env --format json

  # List only active environments
  eos list env --status active

  # List environments of specific type
  eos list env --type production`,
	Aliases: []string{"ls"},
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		logger.Info("Listing environments",
			zap.String("command", "env list"),
			zap.String("component", rc.Component))

		// Parse flags
		detailed, _ := cmd.Flags().GetBool("detailed")
		format, _ := cmd.Flags().GetString("format")
		statusFilter, _ := cmd.Flags().GetString("status")
		typeFilter, _ := cmd.Flags().GetString("type")

		// Create environment manager
		envManager, err := environments.NewEnvironmentManager("")
		if err != nil {
			logger.Error("Failed to create environment manager", zap.Error(err))
			return fmt.Errorf("failed to create environment manager: %w", err)
		}

		// Get all environments
		envs, err := envManager.ListEnvironments(rc)
		if err != nil {
			logger.Error("Failed to list environments", zap.Error(err))
			return fmt.Errorf("failed to list environments: %w", err)
		}

		// Get current environment
		currentEnv, err := envManager.GetCurrentEnvironment(rc)
		if err != nil {
			logger.Warn("No current environment set", zap.Error(err))
		}

		// Apply filters
		filteredEnvs := make(map[string]environments.Environment)
		for name, env := range envs {
			// Status filter
			if statusFilter != "" && string(env.Status) != statusFilter {
				continue
			}

			// Type filter
			if typeFilter != "" && string(env.Type) != typeFilter {
				continue
			}

			filteredEnvs[name] = env
		}

		logger.Debug("Listed environments",
			zap.Int("total", len(envs)),
			zap.Int("filtered", len(filteredEnvs)))

		// Display environments
		switch format {
		case "json":
			return displayEnvironmentsJSON(filteredEnvs, currentEnv)
		case "yaml":
			return displayEnvironmentsYAML(filteredEnvs, currentEnv)
		default:
			return displayEnvironmentsTable(filteredEnvs, currentEnv, detailed)
		}
	}),
}

func init() {
	ListCmd.AddCommand(envCmd)

	// Output formatting flags
	envCmd.Flags().String("format", "table", "Output format: table, json, yaml")
	envCmd.Flags().Bool("detailed", false, "Show detailed environment information")

	// Filtering flags
	envCmd.Flags().String("status", "", "Filter by status: active, inactive, maintenance, destroyed, creating, updating")
	envCmd.Flags().String("type", "", "Filter by type: development, staging, production, testing, preview")

	// Sorting flags
	envCmd.Flags().String("sort", "name", "Sort by: name, type, status, created, updated")
	envCmd.Flags().Bool("reverse", false, "Reverse sort order")

	envCmd.Example = `  # List all environments
  eos list env

  # Show detailed information for all environments
  eos list env --detailed

  # List only production environments
  eos list env --type production

  # List active environments in JSON format
  eos list env --status active --format json

  # List environments sorted by creation date
  eos list env --sort created --reverse`
}

// displayEnvironmentsTable displays environments in table format
func displayEnvironmentsTable(envs map[string]environments.Environment, currentEnv *environments.Environment, detailed bool) error {
	if len(envs) == 0 {
		fmt.Println("No environments found.")
		return nil
	}

	// Create sorted list
	var names []string
	for name := range envs {
		names = append(names, name)
	}
	sort.Strings(names)

	// Create table writer
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	// Print header
	if detailed {
		_, _ = fmt.Fprintln(w, "CURRENT\tNAME\tTYPE\tSTATUS\tNOMAD\tCONSUL\tVAULT\tCREATED\tUPDATED")
	} else {
		_, _ = fmt.Fprintln(w, "CURRENT\tNAME\tTYPE\tSTATUS\tINFRASTRUCTURE")
	}

	// Print environments
	for _, name := range names {
		env := envs[name]
		
		// Check if this is the current environment
		current := ""
		if currentEnv != nil && currentEnv.Name == name {
			current = "*"
		}

		if detailed {
			_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				current,
				env.Name,
				env.Type,
				env.Status,
				env.Infrastructure.Nomad.Address,
				env.Infrastructure.Consul.Address,
				env.Infrastructure.Vault.Address,
				env.CreatedAt.Format("2006-01-02"),
				env.UpdatedAt.Format("2006-01-02"))
		} else {
			// Compact infrastructure info
			infra := fmt.Sprintf("nomad:%s consul:%s vault:%s",
				getShortAddress(env.Infrastructure.Nomad.Address),
				getShortAddress(env.Infrastructure.Consul.Address),
				getShortAddress(env.Infrastructure.Vault.Address))

			_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
				current,
				env.Name,
				env.Type,
				env.Status,
				infra)
		}
	}

	w.Flush()

	// Show current environment info
	if currentEnv != nil {
		fmt.Printf("\nCurrent environment: %s (%s)\n", currentEnv.Name, currentEnv.Type)
	} else {
		fmt.Printf("\nNo current environment set. Use 'eos env use <environment>' to set one.\n")
	}

	return nil
}

// displayEnvironmentsJSON displays environments in JSON format
func displayEnvironmentsJSON(envs map[string]environments.Environment, currentEnv *environments.Environment) error {
	// This would implement JSON output
	fmt.Printf("{\n")
	fmt.Printf("  \"current_environment\": \"%s\",\n", getCurrentEnvName(currentEnv))
	fmt.Printf("  \"environments\": {\n")

	names := make([]string, 0, len(envs))
	for name := range envs {
		names = append(names, name)
	}
	sort.Strings(names)

	for i, name := range names {
		env := envs[name]
		fmt.Printf("    \"%s\": {\n", name)
		fmt.Printf("      \"type\": \"%s\",\n", env.Type)
		fmt.Printf("      \"status\": \"%s\",\n", env.Status)
		fmt.Printf("      \"created_at\": \"%s\",\n", env.CreatedAt.Format("2006-01-02T15:04:05Z"))
		fmt.Printf("      \"updated_at\": \"%s\"\n", env.UpdatedAt.Format("2006-01-02T15:04:05Z"))
		if i < len(names)-1 {
			fmt.Printf("    },\n")
		} else {
			fmt.Printf("    }\n")
		}
	}

	fmt.Printf("  }\n")
	fmt.Printf("}\n")
	return nil
}

// displayEnvironmentsYAML displays environments in YAML format
func displayEnvironmentsYAML(envs map[string]environments.Environment, currentEnv *environments.Environment) error {
	// This would implement YAML output
	fmt.Printf("current_environment: %s\n", getCurrentEnvName(currentEnv))
	fmt.Printf("environments:\n")

	names := make([]string, 0, len(envs))
	for name := range envs {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		env := envs[name]
		fmt.Printf("  %s:\n", name)
		fmt.Printf("    type: %s\n", env.Type)
		fmt.Printf("    status: %s\n", env.Status)
		fmt.Printf("    created_at: %s\n", env.CreatedAt.Format("2006-01-02T15:04:05Z"))
		fmt.Printf("    updated_at: %s\n", env.UpdatedAt.Format("2006-01-02T15:04:05Z"))
	}

	return nil
}

// Helper functions

func getShortAddress(address string) string {
	// Remove protocol and port for compact display
	addr := strings.TrimPrefix(address, "http://")
	addr = strings.TrimPrefix(addr, "https://")
	if idx := strings.Index(addr, ":"); idx > 0 {
		addr = addr[:idx]
	}
	return addr
}

func getCurrentEnvName(env *environments.Environment) string {
	if env == nil {
		return ""
	}
	return env.Name
}