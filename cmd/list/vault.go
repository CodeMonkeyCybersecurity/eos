// cmd/list/vault.go

package list

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var (
	vaultCheckConfig   bool
	vaultCheckSecurity bool
	vaultCheckAll      bool
)

var vaultCheckCmd = &cobra.Command{
	Use:   "vault",
	Short: "Validate Vault configuration and security posture",
	Long: `Perform pre-flight validation of Vault configuration and security.

This command validates:
- Configuration file syntax and semantics
- TLS certificate and key configuration
- File permissions and ownership
- Security posture and compliance
- Common misconfigurations

EXAMPLES:
  # Quick config validation
  sudo eos check vault

  # Configuration only
  sudo eos check vault --config

  # Security posture only
  sudo eos check vault --security

  # Comprehensive validation
  sudo eos check vault --all`,

	RunE: eos_cli.Wrap(runVaultCheck),
}

func init() {
	vaultCheckCmd.Flags().BoolVar(&vaultCheckConfig, "config", false, "Check configuration only")
	vaultCheckCmd.Flags().BoolVar(&vaultCheckSecurity, "security", false, "Check security posture only")
	vaultCheckCmd.Flags().BoolVar(&vaultCheckAll, "all", false, "Perform all validation checks")

	ListCmd.AddCommand(vaultCheckCmd)
}

func runVaultCheck(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info(" Starting Vault validation checks")

	// Default: run all checks if no specific flag is set
	runConfig := vaultCheckConfig || vaultCheckAll || (!vaultCheckConfig && !vaultCheckSecurity)
	runSecurity := vaultCheckSecurity || vaultCheckAll

	hasErrors := false

	// Configuration validation
	if runConfig {
		logger.Info("📋 Running configuration validation")
		if err := validateConfiguration(rc); err != nil {
			logger.Error(" Configuration validation failed", zap.Error(err))
			hasErrors = true
		} else {
			logger.Info(" Configuration validation passed")
		}
	}

	// Security posture validation
	if runSecurity {
		logger.Info("🔒 Running security posture validation")
		if err := validateSecurityPosture(rc); err != nil {
			logger.Error(" Security posture validation failed", zap.Error(err))
			hasErrors = true
		} else {
			logger.Info(" Security posture validation passed")
		}
	}

	if hasErrors {
		return fmt.Errorf("validation failed - see errors above")
	}

	logger.Info(" All validation checks passed")
	fmt.Println("\n Vault validation successful")
	return nil
}

// validateConfiguration performs comprehensive configuration validation
func validateConfiguration(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Validating Vault configuration", zap.String("config", shared.VaultConfigPath))

	// Use the new config validator with fallback
	result, err := vault.ValidateConfigWithFallback(rc, shared.VaultConfigPath)
	if err != nil {
		return fmt.Errorf("validation error: %w", err)
	}

	// Display results
	fmt.Println("\n📋 Configuration Validation Results")
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

// validateSecurityPosture performs security posture checks
func validateSecurityPosture(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Validating Vault security posture")

	passed, failed := vault.ValidateSecurityPosture(rc)

	// Display results
	fmt.Println("\n🔒 Security Posture Validation Results")
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
		fmt.Println("📋 Recommendations:")
		fmt.Println("  • Review failed security checks above")
		fmt.Println("  • Run 'sudo eos debug vault' for detailed diagnostics")
		fmt.Println("  • Consult security documentation: https://wiki.cybermonkey.net.au")
		fmt.Println()

		return fmt.Errorf("security posture validation failed (%d issues)", len(failed))
	}

	return nil
}
