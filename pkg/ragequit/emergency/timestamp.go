package emergency

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/ragequit/system"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CreateTimestampFile creates a timestamp file for ragequit execution
// Migrated from cmd/ragequit/ragequit.go createTimestampFile
func CreateTimestampFile(rc *eos_io.RuntimeContext, reason string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Determine file location
	logger.Info("Assessing timestamp file creation",
		zap.String("reason", reason))

	homeDir := system.GetHomeDir()
	timestampFile := filepath.Join(homeDir, "ragequit-timestamp.txt")

	// INTERVENE - Create timestamp file
	logger.Debug("Creating ragequit timestamp file",
		zap.String("path", timestampFile))

	content := fmt.Sprintf("Ragequit executed at: %s\nTriggered by: %s\nReason: %s\nHostname: %s\n",
		time.Now().Format(time.RFC3339),
		os.Getenv("USER"),
		reason,
		system.GetHostname())

	if err := os.WriteFile(timestampFile, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to create timestamp file: %w", err)
	}

	// EVALUATE - Verify file creation
	if _, err := os.Stat(timestampFile); err != nil {
		return fmt.Errorf("timestamp file not created: %w", err)
	}

	logger.Info("Created ragequit timestamp file successfully",
		zap.String("file", timestampFile))

	return nil
}
