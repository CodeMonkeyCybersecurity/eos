package schedule

import (
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CronToOnCalendar converts a cron expression to systemd OnCalendar format
// Migrated from cmd/backup/schedule.go cronToOnCalendar
func CronToOnCalendar(rc *eos_io.RuntimeContext, cron string) string {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Analyze the cron expression
	logger.Debug("Assessing cron expression for conversion",
		zap.String("cron", cron))

	// INTERVENE - Convert to OnCalendar format
	logger.Debug("Converting cron to OnCalendar format")

	// Simple conversion for common patterns
	switch cron {
	case "0 0 * * *":
		logger.Debug("Recognized daily cron pattern")
		return "daily"
	case "0 0 * * 0":
		logger.Debug("Recognized weekly cron pattern")
		return "weekly"
	case "0 0 1 * *":
		logger.Debug("Recognized monthly cron pattern")
		return "monthly"
	case "0 * * * *":
		logger.Debug("Recognized hourly cron pattern")
		return "hourly"
	default:
		// Try to parse and convert
		parts := strings.Split(cron, " ")
		if len(parts) == 5 {
			// Convert "0 2 * * *" to "*-*-* 02:00:00"
			if parts[2] == "*" && parts[3] == "*" && parts[4] == "*" {
				onCalendar := fmt.Sprintf("*-*-* %02s:%02s:00", parts[1], parts[0])
				logger.Debug("Converted custom cron pattern",
					zap.String("on_calendar", onCalendar))
				return onCalendar
			}
		}

		// EVALUATE - Fallback to daily
		logger.Warn("Could not convert cron expression, falling back to daily",
			zap.String("cron", cron))
		return "daily"
	}
}
