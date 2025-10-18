package services

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/pipeline"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ShowServiceConfiguration displays service configuration file content
// Migrated from cmd/read/pipeline_services.go showServiceConfiguration
func ShowServiceConfiguration(rc *eos_io.RuntimeContext, config pipeline.ServiceConfiguration) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Prepare service configuration display
	logger.Info("Assessing service configuration display",
		zap.String("service", config.Name),
		zap.String("service_file", config.ServiceFile))

	logger.Info(" Service Configuration Content")

	// INTERVENE - Display configuration content
	if shared.FileExists(config.ServiceFile) {
		logger.Debug("Reading service configuration file")

		content, err := os.ReadFile(config.ServiceFile)
		if err != nil {
			logger.Error("Failed to read service configuration file",
				zap.String("file", config.ServiceFile),
				zap.Error(err))
			return fmt.Errorf("failed to read service file %s: %w", config.ServiceFile, err)
		}

		logger.Info(" " + filepath.Base(config.ServiceFile) + " content:")
		lines := strings.Split(string(content), "\n")
		for _, line := range lines {
			logger.Info("  " + line)
		}

		// EVALUATE - Log successful configuration display
		logger.Info("Service configuration displayed successfully",
			zap.String("service", config.Name),
			zap.String("file", config.ServiceFile),
			zap.Int("lines_displayed", len(lines)))
	} else {
		logger.Warn("Service configuration file does not exist",
			zap.String("file", config.ServiceFile))
	}

	return nil
}
