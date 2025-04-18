// pkg/logger/writer.go

package logger

import (
	"fmt"
	"os"

	"go.uber.org/zap/zapcore"
)

// GetLogFileWriter tries to create a file writer at the specified path.
func GetLogFileWriter(path string) (zapcore.WriteSyncer, error) {
	// 💡 Ensure secure directory + file exists with correct perms
	if err := EnsureLogPermissions(path); err != nil {
		return zapcore.AddSync(os.Stdout), fmt.Errorf("log permission error: %w", err)
	}

	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return zapcore.AddSync(os.Stdout), fmt.Errorf("failed to open log file: %w", err)
	}

	return zapcore.AddSync(file), nil
}

// FindWritableLogPath returns the first usable log path using XDG state locations.
func FindWritableLogPath() (string, error) {
	for _, path := range DefaultLogPaths {
		if _, err := GetLogFileWriter(path); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("no writable log path found")
}

// GetFallbackLogWriter returns the best available log writer using default paths or stdout.
func GetFallbackLogWriter() zapcore.WriteSyncer {
	path, err := FindWritableLogPath()
	if err == nil {
		writer, err := GetLogFileWriter(path)
		if err == nil {
			fmt.Fprintf(os.Stderr, "\n📝 Logging to file: %s\n", path)
			return writer
		}
		fmt.Fprintf(os.Stderr, "⚠️ Logging fallback: could not open log file %s: %v\n", path, err)
	} else {
		fmt.Fprintf(os.Stderr, "⚠️ Logging fallback: no valid log paths found\n")
	}

	fmt.Fprintln(os.Stderr, "📤 Logging to stdout")
	return zapcore.AddSync(os.Stdout)
}
