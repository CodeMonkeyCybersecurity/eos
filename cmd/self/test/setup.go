package test

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Set up testing infrastructure for developers",
	Long: `Installs and configures testing infrastructure including:
- Pre-commit hooks (via pre-commit framework)
- Coverage enforcement tools
- Test utilities and dependencies
- IDE/editor test integration

This command should be run by new developers when first setting up their environment.

Prerequisites:
- Python 3 (for pre-commit framework)
- Go 1.24+ (for testing tools)

Examples:
  # Full setup (recommended for new developers)
  eos self test setup

  # Verify setup completed correctly
  eos self test setup --verify

  # Force reinstall (if hooks are misconfigured)
  eos self test setup --force
`,
	RunE: eos_cli.Wrap(runSetup),
}

func init() {
	setupCmd.Flags().Bool("verify", false, "Verify setup without making changes")
	setupCmd.Flags().Bool("force", false, "Force reinstall even if already set up")
}

func runSetup(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	verify, _ := cmd.Flags().GetBool("verify")
	force, _ := cmd.Flags().GetBool("force")

	logger.Info("Setting up testing infrastructure",
		zap.Bool("verify_only", verify),
		zap.Bool("force", force))

	// ASSESS: Check current state
	state := assessTestingInfrastructure(rc)

	if verify {
		return reportSetupState(rc, state)
	}

	// INTERVENE: Install missing components
	if err := installTestingInfrastructure(rc, state, force); err != nil {
		return fmt.Errorf("failed to install testing infrastructure: %w", err)
	}

	// EVALUATE: Verify installation
	newState := assessTestingInfrastructure(rc)
	return reportSetupState(rc, newState)
}

// TestingInfrastructureState tracks what's installed
type TestingInfrastructureState struct {
	PreCommitInstalled       bool
	PreCommitHooksInstalled  bool
	CoverageToolInstalled    bool
	TestCoverageConfigExists bool
	FuzzCorpusExists         bool
	TestDataDirExists        bool
}

func assessTestingInfrastructure(rc *eos_io.RuntimeContext) *TestingInfrastructureState {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Assessing current testing infrastructure state")

	state := &TestingInfrastructureState{}

	// Check if pre-commit framework is installed
	if _, err := exec.LookPath("pre-commit"); err == nil {
		state.PreCommitInstalled = true
	}

	// Check if pre-commit hooks are installed
	if _, err := os.Stat(".git/hooks/pre-commit"); err == nil {
		// Check if it's managed by pre-commit framework
		content, _ := os.ReadFile(".git/hooks/pre-commit")
		if len(content) > 0 && string(content[:20]) != "#!/bin/bash" {
			state.PreCommitHooksInstalled = true
		}
	}

	// Check if coverage tool is available
	if _, err := exec.LookPath("go-test-coverage"); err == nil {
		state.CoverageToolInstalled = true
	}

	// Check if .testcoverage.yml exists
	if _, err := os.Stat(".testcoverage.yml"); err == nil {
		state.TestCoverageConfigExists = true
	}

	// Check if testdata directories exist
	if _, err := os.Stat("testdata"); err == nil {
		state.TestDataDirExists = true
	}

	return state
}

func installTestingInfrastructure(rc *eos_io.RuntimeContext, state *TestingInfrastructureState, force bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Install pre-commit framework if missing
	if !state.PreCommitInstalled || force {
		logger.Info("Installing pre-commit framework")
		// Try pip install
		cmd := exec.Command("pip", "install", "pre-commit")
		if output, err := cmd.CombinedOutput(); err != nil {
			logger.Warn("Failed to install pre-commit via pip, trying pip3",
				zap.Error(err),
				zap.String("output", string(output)))

			// Try pip3
			cmd = exec.Command("pip3", "install", "pre-commit")
			if output, err := cmd.CombinedOutput(); err != nil {
				return fmt.Errorf("failed to install pre-commit: %w\nOutput: %s", err, output)
			}
		}
		logger.Info("Pre-commit framework installed successfully")
	}

	// Install pre-commit hooks
	if !state.PreCommitHooksInstalled || force {
		logger.Info("Installing pre-commit hooks")
		cmd := exec.Command("pre-commit", "install")
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to install pre-commit hooks: %w\nOutput: %s", err, output)
		}
		logger.Info("Pre-commit hooks installed successfully")
	}

	// Install coverage tool
	if !state.CoverageToolInstalled || force {
		logger.Info("Installing go-test-coverage tool")
		cmd := exec.Command("go", "install", "github.com/vladopajic/go-test-coverage/v2@latest")
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to install go-test-coverage: %w\nOutput: %s", err, output)
		}
		logger.Info("Coverage tool installed successfully")
	}

	// Create .testcoverage.yml if missing
	if !state.TestCoverageConfigExists {
		logger.Info(".testcoverage.yml already exists or will be created by pre-commit config")
	}

	// Create testdata directory if missing
	if !state.TestDataDirExists {
		logger.Info("Creating testdata directory")
		if err := os.MkdirAll("testdata", 0755); err != nil {
			logger.Warn("Failed to create testdata directory",
				zap.Error(err))
		}
	}

	return nil
}

func reportSetupState(rc *eos_io.RuntimeContext, state *TestingInfrastructureState) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Testing Infrastructure Status Report",
		zap.Bool("pre_commit_framework", state.PreCommitInstalled),
		zap.Bool("pre_commit_hooks", state.PreCommitHooksInstalled),
		zap.Bool("coverage_tool", state.CoverageToolInstalled),
		zap.Bool("coverage_config", state.TestCoverageConfigExists),
		zap.Bool("test_data_dir", state.TestDataDirExists))

	// Determine overall status
	allGood := state.PreCommitInstalled &&
		state.PreCommitHooksInstalled &&
		state.CoverageToolInstalled &&
		state.TestCoverageConfigExists

	if allGood {
		logger.Info("✓ Testing infrastructure is fully set up and ready")
		fmt.Println("\n✓ Testing infrastructure is fully configured!")
		fmt.Println("\nNext steps:")
		fmt.Println("  1. Run tests: go test ./...")
		fmt.Println("  2. Check coverage: eos self test coverage")
		fmt.Println("  3. Pre-commit hooks will run automatically on git commit")
		return nil
	}

	// Report what's missing
	fmt.Println("\n⚠ Some testing infrastructure components are missing:")

	if !state.PreCommitInstalled {
		fmt.Println("  ✗ Pre-commit framework - run: eos self test setup")
	}
	if !state.PreCommitHooksInstalled {
		fmt.Println("  ✗ Pre-commit hooks - run: pre-commit install")
	}
	if !state.CoverageToolInstalled {
		fmt.Println("  ✗ Coverage tool - run: go install github.com/vladopajic/go-test-coverage/v2@latest")
	}
	if !state.TestCoverageConfigExists {
		fmt.Println("  ✗ Coverage config (.testcoverage.yml) - should exist in repo")
	}

	fmt.Println("\nRun 'eos self test setup' to install missing components.")

	return fmt.Errorf("testing infrastructure incomplete")
}
