// pkg/shared/vars.go

package shared

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

func CombineMarkers(additional ...string) []string {
	return append(DefaultMarkers, additional...)
}

// SafeClose closes an io.Closer and logs a warning if it fails.
func SafeClose(c io.Closer, log *zap.Logger) {
	if err := c.Close(); err != nil {
		log.Warn("Closing resource failed", zap.String("resource", fmt.Sprintf("%T", c)), zap.Error(err))
	}
}

// safeFlush flushes a buffered writer and logs a warning if it fails.
func SafeFlush(w *bufio.Writer, log *zap.Logger) {
	if err := w.Flush(); err != nil {
		log.Warn("Flushing writer failed", zap.String("writer", fmt.Sprintf("%T", w)), zap.Error(err))
	}
}

// SafeScanln reads a line from standard input and logs a warning if it fails.
func SafeScanln(dest any, log *zap.Logger) {
	if _, err := fmt.Scanln(dest); err != nil {
		log.Warn("Reading input failed", zap.String("destination", fmt.Sprintf("%T", dest)), zap.Error(err))
	}
}

// SafeSscanf parses a string and logs a warning if it fails.
func SafeSscanf(str, format string, dest any, log *zap.Logger) {
	if _, err := fmt.Sscanf(str, format, dest); err != nil {
		log.Warn("Parsing string input failed", zap.String("input", str), zap.String("format", format), zap.Error(err))
	}
}

// SafeHelp prints CLI help and logs a warning if it fails.
func SafeHelp(cmd *cobra.Command, log *zap.Logger) {
	if err := cmd.Help(); err != nil {
		log.Warn("Displaying CLI help failed", zap.String("command", cmd.Name()), zap.Error(err))
	}
}

// SafeRemove removes a file and logs a warning if it fails.
func SafeRemove(name string, log *zap.Logger) {
	if err := os.Remove(name); err != nil {
		log.Warn("Removing file failed", zap.String("path", name), zap.Error(err))
	}
}

// SafeSync attempts to flush logs safely, suppressing known ignorable errors.
// Unexpected errors are logged as warnings, but do not interrupt CLI flow.
func SafeSync(log *zap.Logger) {
	if log == nil {
		return
	}
	if err := log.Sync(); err != nil {
		if IsIgnorableSyncError(err) {
			log.Debug("Logger sync skipped (harmless)", zap.String("reason", err.Error()))
		} else {
			log.Warn("Logger sync failed", zap.Error(err))
		}
	}
}

// IsIgnorableSyncError returns true if the sync error is known to be harmless.
func IsIgnorableSyncError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "invalid argument") ||
		strings.Contains(errStr, "bad file descriptor")
}
