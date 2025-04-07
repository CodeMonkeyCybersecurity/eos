// pkg/logger/inspect.go

package logger

import (
	"encoding/json"
	"os"
)

// ReadLogFile returns the contents of a given log file.
func ReadLogFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// ColorizeLogLine takes a raw JSON log line and applies ANSI color to the level field.
func ColorizeLogLine(jsonLine string) string {
	var entry map[string]interface{}
	if err := json.Unmarshal([]byte(jsonLine), &entry); err != nil {
		return jsonLine // skip if it's not valid JSON
	}

	rawLevel, ok := entry["L"].(string)
	if !ok {
		return jsonLine
	}

	var colored string
	switch rawLevel {
	case "DEBUG":
		colored = "\033[90m" + jsonLine + "\033[0m"
	case "INFO":
		colored = "\033[32m" + jsonLine + "\033[0m"
	case "WARN", "WARNING":
		colored = "\033[33m" + jsonLine + "\033[0m"
	case "ERROR":
		colored = "\033[31m" + jsonLine + "\033[0m"
	case "FATAL", "PANIC", "DPANIC":
		colored = "\033[1;31m" + jsonLine + "\033[0m"
	default:
		colored = jsonLine
	}

	return colored
}
