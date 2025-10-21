// cmd/read/env.go
//
// REFACTORED: This file now follows Clean Architecture principles.
// All display logic has been moved to pkg/environments/display/.
//
// Before: 366 lines with display formatting and business logic
// After: ~100 lines of pure orchestration
//
// Migrated functions:
//   - displayEnvironmentTable() → pkg/environments/display.ShowEnvironmentTable()
//   - displayDetailedConfiguration() → pkg/environments/display.ShowDetailedConfiguration()
//   - displayEnvironmentJSON() → pkg/environments/display.ShowEnvironmentJSON()
//   - displayEnvironmentYAML() → pkg/environments/display.ShowEnvironmentYAML()
//   - enabledStatus() → pkg/environments/display.formatEnabledStatus() (private)
//
// IMPROVEMENTS:
//   - Fixed YAML marshaling (now uses yaml.Marshal instead of manual fmt.Printf)
//   - Maintained JSON marshaling fix (uses json.MarshalIndent for security)
//   - All display logic now testable and reusable

package read

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/environments"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/environments/display"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var envCmd = &cobra.Command{
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
  eos read env

  # Show specific environment
  eos read env production

  # Show detailed configuration
  eos read env production --detailed

  # Show in JSON format
  eos read env staging --format json`,
	Args: cobra.MaximumNArgs(1),
	RunE: eos.Wrap(showEnvironment),
}

func init() {
	ReadCmd.AddCommand(envCmd)

	// Output formatting flags
	envCmd.Flags().String("format", "table", "Output format: table, json, yaml")
	envCmd.Flags().Bool("detailed", false, "Show detailed environment configuration")

	// Section flags for detailed view
	envCmd.Flags().Bool("infrastructure", false, "Show only infrastructure configuration")
	envCmd.Flags().Bool("deployment", false, "Show only deployment configuration")
	envCmd.Flags().Bool("security", false, "Show only security configuration")
	envCmd.Flags().Bool("monitoring", false, "Show only monitoring configuration")

	envCmd.Example = `  # Show current environment
  eos read env

  # Show production environment details
  eos read env production

  # Show detailed infrastructure configuration
  eos read env production --detailed --infrastructure

  # Show environment in JSON format
  eos read env staging --format json`
}

// showEnvironment orchestrates the environment display operation.
// All display logic is delegated to pkg/environments/display.
func showEnvironment(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
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

	// Display environment information (delegated to pkg/environments/display)
	switch format {
	case "json":
		return display.ShowEnvironmentJSON(env)
	case "yaml":
		return display.ShowEnvironmentYAML(env)
	default:
		return display.ShowEnvironmentTable(env, detailed)
	}
}
