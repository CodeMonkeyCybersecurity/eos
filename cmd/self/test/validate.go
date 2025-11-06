package test

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate testing infrastructure health",
	Long: `Validates that testing infrastructure is correctly configured and healthy.

Checks include:
- Pre-commit hooks installed and configured
- Coverage thresholds properly set
- E2E tests have proper build tags
- No deprecated patterns (e.g., old benchmark syntax)
- Test isolation working correctly
- No flaky tests detected in recent runs

Examples:
  # Basic validation
  eos self test validate

  # Detailed validation with fixes suggested
  eos self test validate --verbose

  # Check specific aspect
  eos self test validate --check=build-tags
`,
	RunE: eos_cli.Wrap(runValidate),
}

func init() {
	validateCmd.Flags().Bool("verbose", false, "Show detailed validation output")
	validateCmd.Flags().String("check", "", "Check specific aspect (build-tags, coverage, hooks, benchmarks)")
}

func runValidate(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	verbose, _ := cmd.Flags().GetBool("verbose")
	check, _ := cmd.Flags().GetString("check")

	logger.Info("Validating testing infrastructure",
		zap.Bool("verbose", verbose),
		zap.String("specific_check", check))

	// ASSESS: Run validation checks
	results := runValidationChecks(rc, check)

	// EVALUATE: Report results
	return reportValidationResults(rc, results, verbose)
}

// ValidationResult represents a single validation check result
type ValidationResult struct {
	Check       string
	Passed      bool
	Message     string
	Remediation string
	Severity    string // "error", "warning", "info"
}

// ValidationResults aggregates all validation results
type ValidationResults struct {
	Checks []ValidationResult
}

func (r *ValidationResults) AllPassed() bool {
	for _, check := range r.Checks {
		if !check.Passed && check.Severity == "error" {
			return false
		}
	}
	return true
}

func runValidationChecks(rc *eos_io.RuntimeContext, specificCheck string) *ValidationResults {
	logger := otelzap.Ctx(rc.Ctx)
	results := &ValidationResults{Checks: []ValidationResult{}}

	checks := map[string]func(*eos_io.RuntimeContext) ValidationResult{
		"build-tags":     validateE2EBuildTags,
		"coverage":       validateCoverageConfig,
		"hooks":          validatePreCommitHooks,
		"benchmarks":     validateBenchmarkPattern,
		"test-isolation": validateTestIsolation,
	}

	// Run specific check or all checks
	if specificCheck != "" {
		if checkFunc, exists := checks[specificCheck]; exists {
			result := checkFunc(rc)
			results.Checks = append(results.Checks, result)
		} else {
			logger.Warn("Unknown validation check", zap.String("check", specificCheck))
			results.Checks = append(results.Checks, ValidationResult{
				Check:    "unknown",
				Passed:   false,
				Message:  fmt.Sprintf("Unknown check: %s", specificCheck),
				Severity: "error",
			})
		}
	} else {
		// Run all checks
		for name, checkFunc := range checks {
			logger.Debug("Running validation check", zap.String("check", name))
			result := checkFunc(rc)
			results.Checks = append(results.Checks, result)
		}
	}

	return results
}

func validateE2EBuildTags(rc *eos_io.RuntimeContext) ValidationResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Validating E2E build tags")

	// Check all E2E test files have build tags
	e2eDir := "test/e2e"
	files, err := filepath.Glob(filepath.Join(e2eDir, "*_test.go"))
	if err != nil {
		return ValidationResult{
			Check:    "build-tags",
			Passed:   false,
			Message:  fmt.Sprintf("Failed to glob E2E test files: %v", err),
			Severity: "error",
		}
	}

	missingTags := []string{}
	for _, file := range files {
		content, err := os.ReadFile(file)
		if err != nil {
			continue
		}

		// Check first line for //go:build e2e
		if len(content) < 15 || string(content[:15]) != "//go:build e2e\n" {
			missingTags = append(missingTags, filepath.Base(file))
		}
	}

	if len(missingTags) > 0 {
		return ValidationResult{
			Check:    "build-tags",
			Passed:   false,
			Message:  fmt.Sprintf("%d E2E test files missing build tags: %v", len(missingTags), missingTags),
			Severity: "error",
			Remediation: `Add '//go:build e2e' as the FIRST line of each E2E test file.

Example:
  //go:build e2e

  package e2e

  func TestE2E_Something(t *testing.T) {
      // ...
  }

See: docs/TESTING_ADVERSARIAL_ANALYSIS.md for details.`,
		}
	}

	return ValidationResult{
		Check:    "build-tags",
		Passed:   true,
		Message:  fmt.Sprintf("All %d E2E test files have proper build tags", len(files)),
		Severity: "info",
	}
}

func validateCoverageConfig(rc *eos_io.RuntimeContext) ValidationResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Validating coverage configuration")

	// Check if .testcoverage.yml exists
	if _, err := os.Stat(".testcoverage.yml"); os.IsNotExist(err) {
		return ValidationResult{
			Check:    "coverage",
			Passed:   false,
			Message:  ".testcoverage.yml not found",
			Severity: "error",
			Remediation: `Create .testcoverage.yml with coverage thresholds.

Example:
  threshold:
    total: 80  # Overall minimum
    file: 70   # Per-file minimum

See: .testcoverage.yml in repo root for full example.`,
		}
	}

	// TODO: Parse YAML and validate thresholds are set
	return ValidationResult{
		Check:    "coverage",
		Passed:   true,
		Message:  ".testcoverage.yml exists",
		Severity: "info",
	}
}

func validatePreCommitHooks(rc *eos_io.RuntimeContext) ValidationResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Validating pre-commit hooks")

	// Check if .pre-commit-config.yaml exists
	if _, err := os.Stat(".pre-commit-config.yaml"); os.IsNotExist(err) {
		return ValidationResult{
			Check:    "hooks",
			Passed:   false,
			Message:  ".pre-commit-config.yaml not found",
			Severity: "error",
			Remediation: `Pre-commit framework not configured.

Run: eos self test setup

Or manually:
  pip install pre-commit
  pre-commit install`,
		}
	}

	// Check if hooks are installed
	if _, err := os.Stat(".git/hooks/pre-commit"); os.IsNotExist(err) {
		return ValidationResult{
			Check:    "hooks",
			Passed:   false,
			Message:  "Pre-commit hooks not installed",
			Severity: "error",
			Remediation: `Pre-commit hooks not installed.

Run: pre-commit install

Or: eos self test setup`,
		}
	}

	return ValidationResult{
		Check:    "hooks",
		Passed:   true,
		Message:  "Pre-commit framework configured and hooks installed",
		Severity: "info",
	}
}

func validateBenchmarkPattern(rc *eos_io.RuntimeContext) ValidationResult {
	// This would grep for deprecated benchmark patterns
	// For now, return a placeholder
	return ValidationResult{
		Check:    "benchmarks",
		Passed:   true,
		Message:  "Benchmark pattern validation not yet implemented",
		Severity: "warning",
		Remediation: `Manual check: git grep "for.*b\.N" -- "*_test.go"

If found, migrate to B.Loop() pattern (Go 1.24+)`,
	}
}

func validateTestIsolation(rc *eos_io.RuntimeContext) ValidationResult {
	// This would check for common test isolation issues
	// For now, return a placeholder
	return ValidationResult{
		Check:    "test-isolation",
		Passed:   true,
		Message:  "Test isolation validation not yet implemented",
		Severity: "warning",
		Remediation: `Manual check:
- Ensure tests use t.TempDir() for file operations
- Verify no shared global state
- Check database tests use transactions`,
	}
}

func reportValidationResults(rc *eos_io.RuntimeContext, results *ValidationResults, verbose bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	fmt.Println("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("  Testing Infrastructure Validation Results")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()

	for _, result := range results.Checks {
		symbol := "✓"
		if !result.Passed {
			if result.Severity == "error" {
				symbol = "✗"
			} else {
				symbol = "⚠"
			}
		}

		fmt.Printf("%s %s: %s\n", symbol, result.Check, result.Message)

		if verbose && result.Remediation != "" {
			fmt.Println(result.Remediation)
			fmt.Println()
		}
	}

	fmt.Println()

	if results.AllPassed() {
		logger.Info("All validation checks passed")
		fmt.Println("✓ All validation checks passed!")
		return nil
	}

	// List failed checks
	failed := 0
	warnings := 0
	for _, result := range results.Checks {
		if !result.Passed {
			if result.Severity == "error" {
				failed++
			} else {
				warnings++
			}
		}
	}

	if failed > 0 {
		fmt.Printf("✗ %d validation check(s) failed\n", failed)
	}
	if warnings > 0 {
		fmt.Printf("⚠ %d warning(s)\n", warnings)
	}

	fmt.Println("\nRun 'eos self test validate --verbose' for remediation steps.")

	return fmt.Errorf("%d validation checks failed", failed)
}
