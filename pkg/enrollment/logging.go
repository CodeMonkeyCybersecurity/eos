package enrollment

import (
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// LogEnrollmentResults logs the final enrollment results
// Migrated from cmd/self/enroll.go logEnrollmentResults
func LogEnrollmentResults(logger otelzap.LoggerWithCtx, result *EnrollmentResult) {
	// ASSESS - Check result status
	if result.Success {
		// INTERVENE - Log successful enrollment
		logger.Info(" Enrollment verification report",
			zap.String("role", result.Role),
			zap.String("master", result.MasterAddress),
			zap.Strings("services_setup", result.ServicesSetup),
			zap.Strings("configs_updated", result.ConfigsUpdated),
			zap.Strings("backups_created", result.BackupsCreated),
			zap.Duration("duration", result.Duration))

		// Log additional success details
		if len(result.ServicesSetup) > 0 {
			logger.Info(" Services successfully configured",
				zap.Int("count", len(result.ServicesSetup)),
				zap.Strings("services", result.ServicesSetup))
		}

		if len(result.ConfigsUpdated) > 0 {
			logger.Info(" Configuration files updated",
				zap.Int("count", len(result.ConfigsUpdated)),
				zap.Strings("configs", result.ConfigsUpdated))
		}

		if len(result.BackupsCreated) > 0 {
			logger.Info("💾 Backups created successfully",
				zap.Int("count", len(result.BackupsCreated)),
				zap.Strings("backups", result.BackupsCreated))
		}
	} else {
		// EVALUATE - Log enrollment errors
		logger.Error(" Enrollment completed with errors",
			zap.String("role", result.Role),
			zap.String("master", result.MasterAddress),
			zap.Strings("errors", result.Errors),
			zap.Duration("duration", result.Duration))

		// Log detailed error information
		for i, err := range result.Errors {
			logger.Error("Error details",
				zap.Int("error_number", i+1),
				zap.String("error", err))
		}
	}
}
