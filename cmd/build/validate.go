package build

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/build"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var validateCmd = &cobra.Command{
	Use:   "validate [component]",
	Short: "Validate build configuration and dependencies",
	Long: `Validate build configuration, dependencies, and build environment for components.

This command performs comprehensive validation of build configurations following the
assessment→intervention→evaluation pattern. It checks for configuration correctness,
dependency availability, build tool versions, and environment readiness.

Validation includes:
- Build configuration syntax and semantics
- Dependency resolution and availability
- Docker configuration and base images
- Build tool versions and compatibility
- Resource requirements and constraints
- Security and compliance checks

Examples:
  # Validate specific component
  eos build validate helen

  # Validate all components
  eos build validate --all

  # Strict validation with enhanced checks
  eos build validate helen --strict

  # Validate dependencies only
  eos build validate helen --dependencies-only

  # Validate with specific environment
  eos build validate --environment production`,
	Args: cobra.MaximumNArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		var componentName string
		if len(args) > 0 {
			componentName = args[0]
		}

		logger.Info("Validating build configuration",
			zap.String("command", "build validate"),
			zap.String("component", componentName),
			zap.String("context", rc.Component))

		// Parse flags
		strict, _ := cmd.Flags().GetBool("strict")
		all, _ := cmd.Flags().GetBool("all")
		depsOnly, _ := cmd.Flags().GetBool("dependencies-only")
		environment, _ := cmd.Flags().GetString("environment")
		format, _ := cmd.Flags().GetString("format")
		fix, _ := cmd.Flags().GetBool("fix")

		logger.Debug("Validation configuration",
			zap.String("component", componentName),
			zap.Bool("strict", strict),
			zap.Bool("all", all),
			zap.Bool("dependencies_only", depsOnly),
			zap.String("environment", environment))

		// Create validator
		validator, err := build.NewBuildValidator(rc, &build.ValidatorConfig{
			Strict:           strict,
			Environment:      environment,
			DependenciesOnly: depsOnly,
			AutoFix:          fix,
		})
		if err != nil {
			logger.Error("Failed to create build validator", zap.Error(err))
			return fmt.Errorf("failed to create build validator: %w", err)
		}

		var results []*build.ValidationResult

		if all {
			// Validate all components
			components, err := validator.DiscoverComponents(rc)
			if err != nil {
				logger.Error("Failed to discover components for validation", zap.Error(err))
				return fmt.Errorf("failed to discover components: %w", err)
			}

			for _, component := range components {
				result, err := validator.ValidateComponent(rc, component.Name)
				if err != nil {
					logger.Warn("Component validation failed",
						zap.String("component", component.Name),
						zap.Error(err))
					// Create failed result
					result = &build.ValidationResult{
						Component: component.Name,
						Valid:     false,
						Errors:    []string{err.Error()},
					}
				}
				results = append(results, result)
			}
		} else if componentName != "" {
			// Validate specific component
			result, err := validator.ValidateComponent(rc, componentName)
			if err != nil {
				logger.Error("Component validation failed",
					zap.String("component", componentName),
					zap.Error(err))
				return fmt.Errorf("validation failed for component %s: %w", componentName, err)
			}
			results = append(results, result)
		} else {
			// Validate workspace
			result, err := validator.ValidateWorkspace(rc)
			if err != nil {
				logger.Error("Workspace validation failed", zap.Error(err))
				return fmt.Errorf("workspace validation failed: %w", err)
			}
			results = append(results, result)
		}

		// Display results
		switch format {
		case "json":
			return displayValidationResultsJSON(results)
		case "yaml":
			return displayValidationResultsYAML(results)
		default:
			return displayValidationResultsTable(results, strict)
		}
	}),
}

func init() {
	BuildCmd.AddCommand(validateCmd)

	// Validation scope flags
	validateCmd.Flags().Bool("all", false, "Validate all components")
	validateCmd.Flags().Bool("strict", false, "Enable strict validation with enhanced checks")
	validateCmd.Flags().Bool("dependencies-only", false, "Validate dependencies only")

	// Environment and context flags
	validateCmd.Flags().String("environment", "", "Validate for specific environment")
	validateCmd.Flags().String("format", "table", "Output format: table, json, yaml")

	// Validation behavior flags
	validateCmd.Flags().Bool("fix", false, "Attempt to fix validation issues automatically")
	validateCmd.Flags().Bool("fail-fast", false, "Stop on first validation error")
	validateCmd.Flags().StringSlice("skip-checks", nil, "Skip specific validation checks")

	// Reporting flags
	validateCmd.Flags().Bool("show-warnings", true, "Show validation warnings")
	validateCmd.Flags().Bool("show-suggestions", true, "Show improvement suggestions")

	validateCmd.Example = `  # Validate specific component
  eos build validate helen

  # Validate all components with strict checks
  eos build validate --all --strict

  # Validate dependencies only
  eos build validate helen --dependencies-only

  # Validate for production environment
  eos build validate --environment production

  # Validate and auto-fix issues
  eos build validate helen --fix`
}

// displayValidationResultsTable displays validation results in table format
func displayValidationResultsTable(results []*build.ValidationResult, strict bool) error {
	if len(results) == 0 {
		fmt.Println("No validation results to display.")
		return nil
	}

	fmt.Printf("Build Validation Results:\n")
	fmt.Printf("═════════════════════════\n\n")

	for _, result := range results {
		status := " VALID"
		if !result.Valid {
			status = " INVALID"
		} else if len(result.Warnings) > 0 {
			status = "VALID (with warnings)"
		}

		fmt.Printf("Component: %s\n", result.Component)
		fmt.Printf("Status:    %s\n", status)
		fmt.Printf("Checks:    %d passed, %d failed, %d warnings\n",
			result.ChecksPassed, len(result.Errors), len(result.Warnings))
		fmt.Printf("\n")

		// Show errors
		if len(result.Errors) > 0 {
			fmt.Printf("Errors:\n")
			for _, err := range result.Errors {
				fmt.Printf("   %s\n", err)
			}
			fmt.Printf("\n")
		}

		// Show warnings
		if len(result.Warnings) > 0 {
			fmt.Printf("Warnings:\n")
			for _, warning := range result.Warnings {
				fmt.Printf("  %s\n", warning)
			}
			fmt.Printf("\n")
		}

		// Show suggestions
		if len(result.Suggestions) > 0 {
			fmt.Printf("Suggestions:\n")
			for _, suggestion := range result.Suggestions {
				fmt.Printf("  💡 %s\n", suggestion)
			}
			fmt.Printf("\n")
		}

		// Show detailed check results if strict mode
		if strict && len(result.Checks) > 0 {
			fmt.Printf("Detailed Checks:\n")
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			_, _ = fmt.Fprintln(w, "CHECK\tSTATUS\tDESCRIPTION")
			for _, check := range result.Checks {
				status := "PASS"
				if !check.Passed {
					status = "FAIL"
				}
				_, _ = fmt.Fprintf(w, "%s\t%s\t%s\n", check.Name, status, check.Description)
			}
			w.Flush()
			fmt.Printf("\n")
		}

		fmt.Printf("────────────────────────────────────────\n\n")
	}

	// Summary
	valid := 0
	invalid := 0
	for _, result := range results {
		if result.Valid {
			valid++
		} else {
			invalid++
		}
	}

	fmt.Printf("Validation Summary:\n")
	fmt.Printf("───────────────────\n")
	fmt.Printf("Total:    %d components\n", len(results))
	fmt.Printf("Valid:    %d\n", valid)
	fmt.Printf("Invalid:  %d\n", invalid)

	if invalid > 0 {
		fmt.Printf("\n %d component(s) failed validation\n", invalid)
	} else {
		fmt.Printf("\n All components passed validation\n")
	}

	return nil
}

// displayValidationResultsJSON displays validation results in JSON format
func displayValidationResultsJSON(results []*build.ValidationResult) error {
	fmt.Printf("{\n")
	fmt.Printf("  \"validation_results\": [\n")

	for i, result := range results {
		fmt.Printf("    {\n")
		fmt.Printf("      \"component\": \"%s\",\n", result.Component)
		fmt.Printf("      \"valid\": %t,\n", result.Valid)
		fmt.Printf("      \"checks_passed\": %d,\n", result.ChecksPassed)
		fmt.Printf("      \"errors\": %d,\n", len(result.Errors))
		fmt.Printf("      \"warnings\": %d,\n", len(result.Warnings))
		fmt.Printf("      \"suggestions\": %d\n", len(result.Suggestions))

		if i < len(results)-1 {
			fmt.Printf("    },\n")
		} else {
			fmt.Printf("    }\n")
		}
	}

	fmt.Printf("  ]\n")
	fmt.Printf("}\n")
	return nil
}

// displayValidationResultsYAML displays validation results in YAML format
func displayValidationResultsYAML(results []*build.ValidationResult) error {
	fmt.Printf("validation_results:\n")

	for _, result := range results {
		fmt.Printf("- component: %s\n", result.Component)
		fmt.Printf("  valid: %t\n", result.Valid)
		fmt.Printf("  checks_passed: %d\n", result.ChecksPassed)
		fmt.Printf("  errors: %d\n", len(result.Errors))
		fmt.Printf("  warnings: %d\n", len(result.Warnings))
		fmt.Printf("  suggestions: %d\n", len(result.Suggestions))
	}

	return nil
}
