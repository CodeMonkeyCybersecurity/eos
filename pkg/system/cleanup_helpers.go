// Package system provides system-level operations and utilities
package system

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// RunOrphansOnlyCleanup handles orphaned packages only following the Assess → Intervene → Evaluate pattern
func RunOrphansOnlyCleanup(rc *eos_io.RuntimeContext, cleanup *PackageCleanup, interactive bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Ensure deborphan is available
	logger.Info("Assessing orphaned packages cleanup prerequisites")
	if err := cleanup.EnsureDeborphan(); err != nil {
		return err
	}

	// Find orphaned packages
	orphans, err := cleanup.FindOrphanedPackages()
	if err != nil {
		return err
	}

	if len(orphans) == 0 {
		logger.Info("No orphaned packages found")
		return nil
	}

	// INTERVENE - Remove orphaned packages
	logger.Info("Found orphaned packages", zap.Int("count", len(orphans)))
	if interactive {
		// In interactive mode, the RemoveOrphanedPackages method will prompt
		return cleanup.RemoveOrphanedPackages(orphans)
	}

	// In non-interactive mode, proceed directly
	return cleanup.RemoveOrphanedPackages(orphans)
}

// RunKernelsOnlyCleanup handles unused kernels only following the Assess → Intervene → Evaluate pattern
func RunKernelsOnlyCleanup(rc *eos_io.RuntimeContext, cleanup *PackageCleanup, interactive bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Find unused kernels
	logger.Info("Assessing unused kernel cleanup")
	kernels, err := cleanup.FindUnusedKernels()
	if err != nil {
		return err
	}

	if len(kernels) == 0 {
		logger.Info("No unused kernels found")
		return nil
	}

	// INTERVENE - Remove unused kernels
	logger.Info("Found unused kernels", zap.Int("count", len(kernels)))

	// For safety, skip kernel removal in non-interactive mode
	if !interactive {
		logger.Info("Skipping kernel removal in non-interactive mode for safety")
		return nil
	}

	// In interactive mode, proceed with removal
	return cleanup.RemoveUnusedKernels(kernels)
}
