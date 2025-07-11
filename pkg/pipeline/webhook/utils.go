package webhook

import (
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// AllFilesPresent checks if all files in the map are present
// Migrated from cmd/read/pipeline_webhook_status.go allFilesPresent
func AllFilesPresent(files map[string]bool) bool {
	// ASSESS - Check file presence status
	for _, present := range files {
		if !present {
			// EVALUATE - Return false if any file is missing
			return false
		}
	}
	// EVALUATE - All files are present
	return true
}

// CheckEnvVar checks if an environment variable is configured in a file
// Migrated from cmd/read/pipeline_webhook_status.go checkEnvVar
func CheckEnvVar(rc *eos_io.RuntimeContext, envFile, varName string) bool {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS - Prepare environment variable check
	logger.Debug("Assessing environment variable configuration",
		zap.String("file", envFile),
		zap.String("variable", varName))
	
	// INTERVENE - Read and check environment file
	// Simple check - in production you'd want proper env file parsing
	data, err := os.ReadFile(envFile)
	if err != nil {
		logger.Debug("Failed to read environment file",
			zap.String("file", envFile),
			zap.String("variable", varName),
			zap.Error(err))
		return false
	}

	present := strings.Contains(string(data), varName+"=")
	
	// EVALUATE - Log result and return
	logger.Debug("Environment variable check completed",
		zap.String("file", envFile),
		zap.String("variable", varName),
		zap.Bool("present", present))
	
	return present
}