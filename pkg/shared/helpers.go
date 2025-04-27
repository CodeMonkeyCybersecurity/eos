// pkg/shared/vars.go

package shared

import (
	"bufio"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

func CombineMarkers(additional ...string) []string {
	return append(DefaultMarkers, additional...)
}

// SafeClose closes an io.Closer and logs a warning if it fails.
func SafeClose(c io.Closer, log *zap.Logger) {
	if err := c.Close(); err != nil {
		log.Warn("Error closing resource", zap.Error(err))
	}
}

// SafeSync syncs a zap logger and logs a warning if it fails.
func SafeSync(log *zap.Logger) {
	if err := log.Sync(); err != nil {
		log.Warn("Error syncing logger", zap.Error(err))
	}
}

// safeFlush flushes a buffered writer and logs a warning if it fails.
func SafeFlush(w *bufio.Writer, log *zap.Logger) {
	if err := w.Flush(); err != nil {
		log.Warn("Error flushing writer", zap.Error(err))
	}
}

// SafeScanln reads a line from standard input and logs a warning if it fails.
func SafeScanln(dest any, log *zap.Logger) {
	if _, err := fmt.Scanln(dest); err != nil {
		log.Warn("Error scanning input", zap.Error(err))
	}
}

// SafeSscanf parses a string and logs a warning if it fails.
func SafeSscanf(str, format string, dest any, log *zap.Logger) {
	if _, err := fmt.Sscanf(str, format, dest); err != nil {
		log.Warn("Error parsing input", zap.String("input", str), zap.Error(err))
	}
}

// SafeHelp prints CLI help and logs a warning if it fails.
func SafeHelp(cmd *cobra.Command, log *zap.Logger) {
	if err := cmd.Help(); err != nil {
		log.Warn("Failed to print help", zap.Error(err))
	}
}

// SafeRemove removes a file and logs a warning if it fails.
func SafeRemove(name string, log *zap.Logger) {
	if err := os.Remove(name); err != nil {
		log.Warn("Error removing file", zap.String("path", name), zap.Error(err))
	}
}
