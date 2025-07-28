package nuke

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ShowPhaseProgress displays progress for each phase using structured logging
func ShowPhaseProgress(rc *eos_io.RuntimeContext, phase int, description string) {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Phase progress",
		zap.Int("phase", phase),
		zap.Int("total_phases", 6),
		zap.String("description", description),
		zap.String("progress", fmt.Sprintf("Phase %d/6: %s", phase, description)))
}

// LogPhaseCompletion logs when a phase is completed
func LogPhaseCompletion(rc *eos_io.RuntimeContext, result PhaseResult) {
	logger := otelzap.Ctx(rc.Ctx)
	
	if result.Success {
		logger.Info("Phase completed successfully",
			zap.Int("phase", result.Phase),
			zap.String("description", result.Description),
			zap.Any("details", result.Details))
	} else {
		logger.Error("Phase completed with errors", 
			zap.Int("phase", result.Phase),
			zap.String("description", result.Description),
			zap.Error(result.Error),
			zap.Any("details", result.Details))
	}
}