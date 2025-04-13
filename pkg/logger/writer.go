/* pkg/logger/writer.go */

package logger

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/xdg"
	"go.uber.org/zap/zapcore"
)

// GetLogFileWriter tries to create a file writer at the specified path.
func GetLogFileWriter(path string) (zapcore.WriteSyncer, error) {
	_ = os.MkdirAll(filepath.Dir(path), 0755)
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return zapcore.AddSync(os.Stdout), err
	}
	return zapcore.AddSync(file), nil
}

// FindWritableLogPath returns the first usable log path using XDG state locations.
func FindWritableLogPath() (string, error) {
	candidates := []string{
		xdg.XDGStatePath("eos", "eos.log"),
		xdg.XDGDataPath("eos", "eos.log"),
		"/var/log/eos.log", // system-wide fallback
	}

	for _, path := range candidates {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err == nil {
			f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
			if err == nil {
				f.Close()
				return path, nil
			}
		}
	}
	return "", fmt.Errorf("no writable log path found")
}

// GetFallbackLogWriter returns the best available log writer using XDG or stdout fallback.
func GetFallbackLogWriter() zapcore.WriteSyncer {
	if path, err := FindWritableLogPath(); err == nil {
		writer, err := GetLogFileWriter(path)
		if err == nil {
			return writer
		}
	}
	return zapcore.AddSync(os.Stdout)
}
