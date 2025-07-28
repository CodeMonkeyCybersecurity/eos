package nuke

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ExecuteNuke performs the complete infrastructure nuke operation following AIE pattern
func ExecuteNuke(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS - Evaluate what needs to be removed
	logger.Info("Starting infrastructure nuke operation",
		zap.Bool("remove_all", config.RemoveAll),
		zap.Bool("force", config.Force),
		zap.Bool("keep_data", config.KeepData),
		zap.Bool("dev_mode", config.DevMode),
		zap.Strings("exclude", config.ExcludeList))

	// Phase 1: Assessment
	plan, err := AssessInfrastructure(rc, config)
	if err != nil {
		return fmt.Errorf("assessment failed: %w", err)
	}

	// Show removal plan to user
	ShowRemovalPlan(rc, plan)

	// Confirm with user unless --force
	if !config.Force {
		if !interaction.PromptYesNo(rc.Ctx, "Are you sure you want to destroy all infrastructure?", false) {
			logger.Info("Nuke operation cancelled by user")
			return nil
		}
	}

	// INTERVENE - Execute the removal
	logger.Info("Beginning infrastructure destruction sequence")
	
	phaseResults, err := ExecuteRemoval(rc, config, plan)
	if err != nil {
		return fmt.Errorf("removal execution failed: %w", err)
	}

	// EVALUATE - Verify removal was successful
	result, err := EvaluateRemoval(rc, config, plan, phaseResults)
	if err != nil {
		return fmt.Errorf("evaluation failed: %w", err)
	}

	// Generate final report
	GenerateRemovalReport(rc, result, phaseResults)

	// Handle removal of eos itself if requested
	if config.RemoveAll && !isExcluded("eos", config.ExcludeList) {
		if err := removeEosItself(rc); err != nil {
			logger.Warn("Failed to remove eos itself", zap.Error(err))
		}
	}

	logger.Info("Infrastructure nuke operation completed",
		zap.Float64("success_rate", result.SuccessRate),
		zap.Int("remaining_components", result.RemainingComponents))

	return nil
}

// removeEosItself removes the eos binary and related files
func removeEosItself(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Removing eos itself")

	// Remove eos binary
	eosBinary := "/usr/local/bin/eos"
	if fileExists(eosBinary) {
		logger.Info("Removing eos binary", zap.String("path", eosBinary))
		if err := removeFile(eosBinary); err != nil {
			return fmt.Errorf("failed to remove eos binary: %w", err)
		}
	}

	// Note: Cannot remove source directory while running from it
	logger.Warn("Cannot remove eos source directory while running from it")

	return nil
}

// Helper functions

func isExcluded(item string, excludeList []string) bool {
	for _, excluded := range excludeList {
		if excluded == item {
			return true
		}
	}
	return false
}

func removeFile(path string) error {
	return os.Remove(path)
}