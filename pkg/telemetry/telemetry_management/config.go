package telemetry_management

import (
	"os"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// GetTelemetryFilePath returns the path to the telemetry file, following the same logic as the telemetry package
// Migrated from cmd/self/telemetry.go getTelemetryFilePath
func GetTelemetryFilePath() string {
	// ASSESS - Determine telemetry file location preference
	// Try system directory first (Ubuntu/production)
	systemPath := "/var/log/eos/telemetry.jsonl"
	if _, err := os.Stat(filepath.Dir(systemPath)); err == nil {
		return systemPath
	}

	// INTERVENE - Fallback to user directory (development/macOS)
	// EVALUATE - Return appropriate path based on system capabilities
	return filepath.Join(os.Getenv("HOME"), ".eos", "telemetry", "telemetry.jsonl")
}

// ShowTelemetryInfo displays telemetry configuration details
// Migrated from cmd/self/telemetry.go showTelemetryInfo
func ShowTelemetryInfo(rc *eos_io.RuntimeContext) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Prepare telemetry configuration display
	logger.Info("Assessing telemetry configuration display")

	telemetryPath := GetTelemetryFilePath()

	// INTERVENE - Display telemetry configuration information
	logger.Info(" Telemetry configuration",
		zap.String("file_path", telemetryPath),
		zap.String("format", "JSONL (JSON Lines)"),
		zap.String("privacy", "Local storage only - no external transmission"))

	logger.Info(" Analysis commands",
		zap.String("command_frequency", "jq -r '.name' "+telemetryPath+" | sort | uniq -c | sort -nr"),
		zap.String("success_rate", "jq -r 'select(.attributes.success == true) | .name' "+telemetryPath+" | wc -l"),
		zap.String("avg_duration", "jq -r 'select(.attributes.duration_ms) | \"\\(.name) \\(.attributes.duration_ms)\"' "+telemetryPath))

	// EVALUATE - Log successful configuration display
	logger.Info("Telemetry configuration displayed successfully")
}
