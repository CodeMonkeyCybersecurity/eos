// pkg/shared/vars.go

package shared

import (
	"bufio"
	"context"
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
func SafeClose(ctx context.Context, c io.Closer) {
	if err := c.Close(); err != nil {
		zap.L().Warn("Closing resource failed", zap.String("resource", fmt.Sprintf("%T", c)), zap.Error(err))
	}
}

// safeFlush flushes a buffered writer and logs a warning if it fails.
func SafeFlush(w *bufio.Writer) {
	if err := w.Flush(); err != nil {
		zap.L().Warn("Flushing writer failed", zap.String("writer", fmt.Sprintf("%T", w)), zap.Error(err))
	}
}

// SafeScanln reads a line from standard input and logs a warning if it fails.
func SafeScanln(dest any) {
	if _, err := fmt.Scanln(dest); err != nil {
		zap.L().Warn("Reading input failed", zap.String("destination", fmt.Sprintf("%T", dest)), zap.Error(err))
	}
}

// SafeSscanf parses a string and logs a warning if it fails.
func SafeSscanf(str, format string, dest any) {
	if _, err := fmt.Sscanf(str, format, dest); err != nil {
		zap.L().Warn("Parsing string input failed", zap.String("input", str), zap.String("format", format), zap.Error(err))
	}
}

// SafeHelp prints CLI help and logs a warning if it fails.
func SafeHelp(cmd *cobra.Command) {
	if err := cmd.Help(); err != nil {
		zap.L().Warn("Displaying CLI help failed", zap.String("command", cmd.Name()), zap.Error(err))
	}
}

// SafeRemove removes a file and logs a warning if it fails.
func SafeRemove(name string) {
	if err := os.Remove(name); err != nil {
		zap.L().Warn("Removing file failed", zap.String("path", name), zap.Error(err))
	}
}

// SafeSync attempts to sync the zap logger, gracefully handling harmless errors.
// Known harmless errors (e.g., "sync /dev/stdout: invalid argument") are suppressed with a soft warning.
// Unexpected errors are logged as warnings without crashing the CLI.
func SafeSync() {
	if err := zap.L().Sync(); err != nil {
		errStr := err.Error()

		switch {
		case strings.Contains(errStr, "invalid argument"), strings.Contains(errStr, "bad file descriptor"):
			zap.L().Debug("Logger sync harmlessly skipped", zap.String("reason", errStr))
		default:
			zap.L().Warn("Nonstandard logger sync issue", zap.Error(err))
		}
	}
}
