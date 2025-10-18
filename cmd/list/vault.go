// cmd/list/vault.go

package list

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/servicestatus"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)
// TODO: refactor - ANTI-PATTERN: Package-level mutable state for flags
// ISSUE: These package-level vars make the command non-reentrant and harder to test
// FIX: Pass these as parameters or use a config struct
// IMPACT: Testing difficulty, potential race conditions in concurrent usage
// MOVE TO: Consider using cobra's PersistentFlags or cmd.Flags().Get*() in RunE
var (
	vaultCheckConfig   bool
	vaultCheckSecurity bool
	vaultCheckAll      bool
	vaultCheckRuntime  bool
	vaultOutputFormat  string
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
	vaultCheckCmd.Flags().BoolVar(&vaultCheckConfig, "config", false, "Check configuration only")
	vaultCheckCmd.Flags().BoolVar(&vaultCheckSecurity, "security", false, "Check security posture only")
	vaultCheckCmd.Flags().BoolVar(&vaultCheckRuntime, "runtime", false, "Check runtime status only")
	vaultCheckCmd.Flags().BoolVar(&vaultCheckAll, "all", false, "Perform all validation checks")
	vaultCheckCmd.Flags().StringVarP(&vaultOutputFormat, "format", "f", "text",
		"Output format for runtime status: text, json, yaml, short")

	ListCmd.AddCommand(vaultCheckCmd)
}
// TODO: refactor - Move to pkg/vault/check.go
// BUSINESS LOGIC: Orchestration of multiple validation checks
// ANTI-PATTERN: Complex flag logic in cmd/ instead of pkg/
// FIX: Create VaultCheckConfig struct in pkg/vault/types.go with ParseFlags() method
// DEPENDENCIES: validateConfiguration, validateSecurityPosture, showRuntimeStatus (all need moving)
// MOVE TO: pkg/vault/check.go as RunVaultValidation(rc, config)
func runVaultCheck(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting Vault validation checks")

	// Default: run runtime status if no specific flag is set
	runConfig := vaultCheckConfig || vaultCheckAll
	runSecurity := vaultCheckSecurity || vaultCheckAll
	runRuntime := vaultCheckRuntime || vaultCheckAll || (!vaultCheckConfig && !vaultCheckSecurity && !vaultCheckRuntime)

	hasErrors := false

	// Runtime status (new default behavior)
	if runRuntime {
		logger.Info("Gathering runtime status")
		if err := showRuntimeStatus(rc); err != nil {
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
// TODO: refactor - Move to pkg/vault/validation.go
// BUSINESS LOGIC: Configuration validation and result display
// ANTI-PATTERN: Display logic mixed with validation logic
// FIX: Split into validation (pkg/vault/validation.go) and display (pkg/output/vault.go)
// ISSUES: Direct fmt.Println instead of logger, hardcoded formatting
// MOVE TO: pkg/vault/validation.go as ValidateConfiguration(rc, configPath) (*ValidationResult, error)
// THEN: Create displayValidationResult(result) in pkg/output/ or pkg/vault/display.go
func validateConfiguration(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Validating Vault configuration", zap.String("config", shared.VaultConfigPath))

	// Use the new config validator with fallback
	result, err := vault.ValidateConfigWithFallback(rc, shared.VaultConfigPath)
	if err != nil {
		return fmt.Errorf("validation error: %w", err)
	}

	// Display results
	fmt.Println("\n Configuration Validation Results")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	if result.Valid {
		fmt.Println(" Status: VALID")
	} else {
		fmt.Println(" Status: INVALID")
	}

	fmt.Printf(" Method: %s\n", result.Method)
	fmt.Println()

	// Errors
	if len(result.Errors) > 0 {
		fmt.Printf(" Errors (%d):\n", len(result.Errors))
		for i, err := range result.Errors {
			fmt.Printf("  %d. %s\n", i+1, err)
		}
		fmt.Println()
	}

	// Warnings
	if len(result.Warnings) > 0 {
		fmt.Printf("Warnings (%d):\n", len(result.Warnings))
		for i, warn := range result.Warnings {
			fmt.Printf("  %d. %s\n", i+1, warn)
		}
		fmt.Println()
	}

	// Suggestions
	if len(result.Suggestions) > 0 {
		fmt.Printf(" Suggestions (%d):\n", len(result.Suggestions))
		for i, sugg := range result.Suggestions {
			fmt.Printf("  %d. %s\n", i+1, sugg)
		}
		fmt.Println()
	}

	if !result.Valid {
		return fmt.Errorf("configuration is invalid")
	}

	return nil
}
// TODO: refactor - Move to pkg/vault/security.go
// BUSINESS LOGIC: Security validation and result display
// ANTI-PATTERN: Display logic mixed with validation logic, direct fmt.Println usage
// FIX: Split into security checks (pkg/vault/security.go) and display (pkg/output/)
// ISSUES: Hardcoded URLs, direct console output instead of structured logging
// MOVE TO: pkg/vault/security.go as ValidateSecurityPosture(rc) (*SecurityResult, error)
// THEN: Create displaySecurityResult(result) in pkg/output/ or pkg/vault/display.go
func validateSecurityPosture(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Validating Vault security posture")

	passed, failed := vault.ValidateSecurityPosture(rc)

	// Display results
	fmt.Println("Security Posture Validation Results")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	if len(passed) > 0 {
		fmt.Printf("\n Passed Checks (%d):\n", len(passed))
		for i, check := range passed {
			fmt.Printf("  %d. %s\n", i+1, check)
		}
	}

	if len(failed) > 0 {
		fmt.Printf("\n Failed Checks (%d):\n", len(failed))
		for i, check := range failed {
			fmt.Printf("  %d. %s\n", i+1, check)
		}
	}

	fmt.Println()

	// Recommendations
	if len(failed) > 0 {
		fmt.Println(" Recommendations:")
		fmt.Println("  • Review failed security checks above")
		fmt.Println("  • Run 'sudo eos debug vault' for detailed diagnostics")
		fmt.Println("  • Consult security documentation: https://wiki.cybermonkey.net.au")
		fmt.Println()

		return fmt.Errorf("security posture validation failed (%d issues)", len(failed))
	}

	return nil
}
// TODO: refactor - Move to pkg/vault/status.go
// BUSINESS LOGIC: Status retrieval and format conversion
// ANTI-PATTERN: Format string parsing in cmd/, direct logger.Info for display
// FIX: Move format parsing to pkg/servicestatus/formats.go
// ISSUES: Switch statement for format parsing should be in pkg/
// MOVE TO: pkg/vault/status.go as ShowVaultStatus(rc, format) error
// OR: Use existing pkg/servicestatus pattern and just call from cmd/
func showRuntimeStatus(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Creating Vault status provider")

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
	switch vaultOutputFormat {
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
