// cmd/list/vault.go
//
// REFACTORED: This file now follows Clean Architecture principles.
// All display logic has been moved to pkg/vault/display/.
//
// Before: 280 lines with mixed validation and display logic
// After: ~140 lines of pure orchestration
//
// Migrated functions:
//   - validateConfiguration() display logic → pkg/vault/display.ShowConfigurationValidation()
//   - validateSecurityPosture() display logic → pkg/vault/display.ShowSecurityPosture()
//
// IMPROVEMENTS:
//   - Separated display logic from validation logic
//   - Display functions now reusable and testable
//   - Validation logic remains in pkg/vault (already well-structured)

package list

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/servicestatus"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	vaultdisplay "github.com/CodeMonkeyCybersecurity/eos/pkg/vault/display"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var vaultCheckCmd = &cobra.Command{
	Use:   "vault",
	Short: "Check Vault installation, configuration, and operational status",
	Long: `Comprehensive status check for Vault secrets management service.

This command validates:
- Configuration file syntax and semantics
- TLS certificate and key configuration
- File permissions and ownership
- Security posture and compliance
- Common misconfigurations
- Runtime status (service, health, integrations)

EXAMPLES:
  # Full status with runtime information (default)
  sudo eos list vault

  # Configuration validation only
  sudo eos list vault --config

  # Security posture only
  sudo eos list vault --security

  # Runtime status only
  sudo eos list vault --runtime

  # Comprehensive validation (all checks)
  sudo eos list vault --all

  # JSON output for automation
  sudo eos list vault --format json`,

	RunE: eos_cli.Wrap(runVaultCheck),
}

func init() {
	vaultCheckCmd.Flags().Bool("config", false, "Check configuration only")
	vaultCheckCmd.Flags().Bool("security", false, "Check security posture only")
	vaultCheckCmd.Flags().Bool("runtime", false, "Check runtime status only")
	vaultCheckCmd.Flags().Bool("all", false, "Perform all validation checks")
	vaultCheckCmd.Flags().StringP("format", "f", "text",
		"Output format for runtime status: text, json, yaml, short")

	ListCmd.AddCommand(vaultCheckCmd)
}

// runVaultCheck orchestrates Vault validation checks.
// All display logic is delegated to pkg/vault/display.
func runVaultCheck(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting Vault validation checks")

	// Get flags
	checkConfig, _ := cmd.Flags().GetBool("config")
	checkSecurity, _ := cmd.Flags().GetBool("security")
	checkRuntime, _ := cmd.Flags().GetBool("runtime")
	checkAll, _ := cmd.Flags().GetBool("all")

	// Default: run runtime status if no specific flag is set
	runConfig := checkConfig || checkAll
	runSecurity := checkSecurity || checkAll
	runRuntime := checkRuntime || checkAll || (!checkConfig && !checkSecurity && !checkRuntime)

	hasErrors := false

	// Runtime status (new default behavior)
	if runRuntime {
		logger.Info("Gathering runtime status")
		if err := showRuntimeStatus(rc, cmd); err != nil {
			logger.Error("Runtime status check failed", zap.Error(err))
			hasErrors = true
		}
	}

	// Configuration validation
	if runConfig {
		logger.Info("Running configuration validation")
		if err := validateConfiguration(rc); err != nil {
			logger.Error("Configuration validation failed", zap.Error(err))
			hasErrors = true
		} else {
			logger.Info("Configuration validation passed")
		}
	}

	// Security posture validation
	if runSecurity {
		logger.Info("Running security posture validation")
		if err := validateSecurityPosture(rc); err != nil {
			logger.Error("Security posture validation failed", zap.Error(err))
			hasErrors = true
		} else {
			logger.Info("Security posture validation passed")
		}
	}

	if hasErrors {
		return fmt.Errorf("validation failed - see errors above")
	}

	logger.Info("All validation checks passed")
	return nil
}

// validateConfiguration validates Vault configuration and displays results.
// Validation logic in pkg/vault, display logic delegated to pkg/vault/display.
func validateConfiguration(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Validating Vault configuration", zap.String("config", shared.VaultConfigPath))

	// Use the validation logic from pkg/vault
	result, err := vault.ValidateConfigWithFallback(rc, shared.VaultConfigPath)
	if err != nil {
		return fmt.Errorf("validation error: %w", err)
	}

	// Display results (delegated to pkg/vault/display)
	vaultdisplay.ShowConfigurationValidation(result)

	if !result.Valid {
		return fmt.Errorf("configuration is invalid")
	}

	return nil
}

// validateSecurityPosture validates Vault security posture and displays results.
// Validation logic in pkg/vault, display logic delegated to pkg/vault/display.
func validateSecurityPosture(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Validating Vault security posture")

	// Use the validation logic from pkg/vault
	passed, failed := vault.ValidateSecurityPosture(rc)

	// Display results (delegated to pkg/vault/display)
	vaultdisplay.ShowSecurityPosture(passed, failed)

	if len(failed) > 0 {
		return fmt.Errorf("security posture validation failed (%d issues)", len(failed))
	}

	return nil
}

// showRuntimeStatus displays Vault runtime status.
// Status retrieval from pkg/servicestatus, format parsing here (minimal logic).
func showRuntimeStatus(rc *eos_io.RuntimeContext, cmd *cobra.Command) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Creating Vault status provider")

	// Get format flag
	outputFormat, _ := cmd.Flags().GetString("format")

	// Create status provider
	provider := servicestatus.NewVaultStatusProvider()

	// Get comprehensive status
	status, err := provider.GetStatus(rc)
	if err != nil {
		logger.Error("Failed to get Vault status", zap.Error(err))
		return err
	}

	// Determine output format
	format := servicestatus.FormatText
	switch outputFormat {
	case "json":
		format = servicestatus.FormatJSON
	case "yaml":
		format = servicestatus.FormatYAML
	case "short":
		format = servicestatus.FormatShort
	}

	// Display status
	logger.Info(status.Display(format))

	return nil
}
