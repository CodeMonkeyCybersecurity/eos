// pkg/vault/display/validation.go
//
// Vault validation result display formatting.
// Migrated from cmd/list/vault.go to consolidate vault display operations.

package display

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
)

// ShowConfigurationValidation displays configuration validation results.
// Migrated from cmd/list/vault.go validateConfiguration() display logic.
//
// Parameters:
//   - result: Configuration validation result to display
func ShowConfigurationValidation(result *vault.ConfigValidationResult) {
	if result == nil {
		return
	}

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
}

// ShowSecurityPosture displays security posture validation results.
// Migrated from cmd/list/vault.go validateSecurityPosture() display logic.
//
// Parameters:
//   - passed: List of passed security checks
//   - failed: List of failed security checks
func ShowSecurityPosture(passed, failed []string) {
	// No nil check needed for slices - they handle nil naturally
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
	}
}
