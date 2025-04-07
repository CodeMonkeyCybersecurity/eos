// pkg/logger/inspect.go

package logger

import (
	"os"
	"strings"
)

// ReadLogFile returns the contents of a given log file.
func ReadLogFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func ColorizeLogLine(line string) string {
	switch {
	case strings.Contains(line, "ERROR"), strings.Contains(line, "FATAL"):
		return "\033[31m" + line + "\033[0m" // Red
	case strings.Contains(line, "WARN"):
		return "\033[33m" + line + "\033[0m" // Yellow
	case strings.Contains(line, "DEBUG"), strings.Contains(line, "TRACE"):
		return "\033[34m" + line + "\033[0m" // Blue
	case strings.Contains(line, "INFO"):
		return "\033[32m" + line + "\033[0m" // Green
	default:
		return line
	}
}
