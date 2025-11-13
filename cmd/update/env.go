// cmd/update/env.go

package update

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/environments"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/verify"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var envCmd = &cobra.Command{
	Use:   "env <environment-name>",
	Short: "Update an existing environment or switch context",
	Long: `Update an existing deployment environment's configuration or switch the active environment context.

This command can:
- Update environment configuration (default)
- Apply environment from YAML/JSON file (--apply flag)
- Switch to a different environment (--use flag)

Examples:
  # Update environment configuration
  eos update env production --nomad-address https://nomad.prod.example.com:4646

  # Apply environment from file
  eos update env staging --apply --config staging.yaml

  # Switch to a different environment
  eos update env production --use`,
	Args: cobra.ExactArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		// CRITICAL: Detect flag-like args (P0-1 fix)
		if err := verify.ValidateNoFlagLikeArgs(args); err != nil {
			return err
		}

		envName := args[0]

		// Check which operation to perform
		apply, _ := cmd.Flags().GetBool("apply")
		use, _ := cmd.Flags().GetBool("use")

		if apply {
			return applyEnvironment(rc, cmd, envName)
		} else if use {
			return useEnvironment(rc, envName)
		} else {
			return updateEnvironment(rc, cmd, envName)
		}
	}),
}

func init() {
	UpdateCmd.AddCommand(envCmd)

	// Operation mode flags
	envCmd.Flags().Bool("apply", false, "Apply environment from configuration file")
	envCmd.Flags().Bool("use", false, "Switch to this environment")

	// Configuration file (for --apply)
	envCmd.Flags().String("config", "", "Configuration file path (for --apply)")

	// Update flags
	envCmd.Flags().String("type", "", "Environment type")
	envCmd.Flags().String("display-name", "", "Display name")
	envCmd.Flags().String("description", "", "Description")
	envCmd.Flags().String("nomad-address", "", "Nomad address")
	envCmd.Flags().String("consul-address", "", "Consul address")
	envCmd.Flags().String("vault-address", "", "Vault address")
}

// useEnvironment switches the current environment context
func useEnvironment(rc *eos_io.RuntimeContext, envName string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Switching environment context",
		zap.String("command", "update env --use"),
		zap.String("target_environment", envName))

	// Create environment manager
	envManager, err := environments.NewEnvironmentManager("")
	if err != nil {
		logger.Error("Failed to create environment manager", zap.Error(err))
		return fmt.Errorf("failed to create environment manager: %w", err)
	}

	// Verify environment exists
	env, err := envManager.GetEnvironment(rc, envName)
	if err != nil {
		logger.Error("Environment not found", zap.String("environment", envName), zap.Error(err))
		return fmt.Errorf("environment '%s' not found: %w", envName, err)
	}

	// Switch to the environment
	if err := envManager.UseEnvironment(rc, envName); err != nil {
		logger.Error("Failed to switch environment",
			zap.String("environment", envName),
			zap.Error(err))
		return fmt.Errorf("failed to switch to environment '%s': %w", envName, err)
	}

	fmt.Printf(" Switched to environment: %s (%s)\n", env.DisplayName, env.Name)
	fmt.Printf("\nActive Environment Configuration:\n")
	fmt.Printf("───────────────────────────────────\n")
	fmt.Printf("Type:        %s\n", env.Type)
	fmt.Printf("Nomad:       %s\n", env.Infrastructure.Nomad.Address)
	fmt.Printf("Consul:      %s\n", env.Infrastructure.Consul.Address)
	fmt.Printf("Vault:       %s\n", env.Infrastructure.Vault.Address)

	logger.Info("Environment context switched successfully",
		zap.String("environment", envName),
		zap.String("type", string(env.Type)))

	return nil
}

// updateEnvironment updates an existing environment
func updateEnvironment(rc *eos_io.RuntimeContext, cmd *cobra.Command, envName string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Updating environment",
		zap.String("command", "update env"),
		zap.String("environment", envName))

	// Create environment manager
	envManager, err := environments.NewEnvironmentManager("")
	if err != nil {
		logger.Error("Failed to create environment manager", zap.Error(err))
		return fmt.Errorf("failed to create environment manager: %w", err)
	}

	// Get existing environment
	env, err := envManager.GetEnvironment(rc, envName)
	if err != nil {
		logger.Error("Environment not found", zap.String("environment", envName), zap.Error(err))
		return fmt.Errorf("environment '%s' not found: %w", envName, err)
	}

	// Apply flag updates
	updated := false

	if cmd.Flags().Changed("type") {
		envType, _ := cmd.Flags().GetString("type")
		env.Type = environments.EnvironmentType(envType)
		updated = true
	}

	if cmd.Flags().Changed("display-name") {
		displayName, _ := cmd.Flags().GetString("display-name")
		env.DisplayName = displayName
		updated = true
	}

	if cmd.Flags().Changed("description") {
		description, _ := cmd.Flags().GetString("description")
		env.Description = description
		updated = true
	}

	if cmd.Flags().Changed("nomad-address") {
		nomadAddress, _ := cmd.Flags().GetString("nomad-address")
		env.Infrastructure.Nomad.Address = nomadAddress
		updated = true
	}

	if cmd.Flags().Changed("consul-address") {
		consulAddress, _ := cmd.Flags().GetString("consul-address")
		env.Infrastructure.Consul.Address = consulAddress
		updated = true
	}

	if cmd.Flags().Changed("vault-address") {
		vaultAddress, _ := cmd.Flags().GetString("vault-address")
		env.Infrastructure.Vault.Address = vaultAddress
		updated = true
	}

	if !updated {
		return fmt.Errorf("no updates specified. Use flags to update environment configuration")
	}

	// Update the environment
	if err := envManager.UpdateEnvironment(rc, env); err != nil {
		logger.Error("Failed to update environment",
			zap.String("environment", envName),
			zap.Error(err))
		return fmt.Errorf("failed to update environment: %w", err)
	}

	fmt.Printf(" Environment '%s' updated successfully\n", envName)

	logger.Info("Environment updated successfully",
		zap.String("environment", envName))

	return nil
}

// applyEnvironment creates or updates environment from config file
func applyEnvironment(rc *eos_io.RuntimeContext, cmd *cobra.Command, envName string) error {
	logger := otelzap.Ctx(rc.Ctx)

	configFile, _ := cmd.Flags().GetString("config")
	if configFile == "" {
		return fmt.Errorf("--config flag is required when using --apply")
	}

	logger.Info("Applying environment from configuration file",
		zap.String("command", "update env --apply"),
		zap.String("environment", envName),
		zap.String("config_file", configFile))

	// For now, return an error indicating this feature needs implementation
	// TODO: Implement file loading with proper YAML/JSON parsing
	logger.Warn("Apply from file not yet implemented")
	return fmt.Errorf("--apply flag not yet fully implemented. Use direct update flags or create environment manually")
}
