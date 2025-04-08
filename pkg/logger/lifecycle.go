/* pkg/logger/lifecycle.go */
package logger

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// generateTraceID returns a short 8-char trace ID.
func generateTraceID() string {
	return uuid.New().String()[:8]
}

func withCommandLogging(name string, fn func() error) error {
	log := L()
	traceID := generateTraceID()
	start := time.Now()

	log.Info("Command started", zap.String("command", name), zap.Time("start_time", start), zap.String("trace_id", traceID))

	err := fn()

	end := time.Now()
	duration := end.Sub(start)

	if err != nil {
		log.Error("Command failed", zap.String("command", name), zap.Duration("duration", duration), zap.Error(err), zap.String("trace_id", traceID))
	} else {
		log.Info("Command completed", zap.String("command", name), zap.Duration("duration", duration), zap.String("trace_id", traceID))
	}

	return err
}

// For pkg/* use when zap is unavailable
func logCommandStart(cmd string) (string, time.Time) {
	traceID := generateTraceID()
	start := time.Now()
	fmt.Printf("[INFO] Command starting: %s | trace_id=%s\n", cmd, traceID)
	return traceID, start
}

func logCommandEnd(cmd string, traceID string, start time.Time) {
	duration := time.Since(start)
	fmt.Printf("[INFO] Command completed: %s | duration=%s | trace_id=%s\n", cmd, duration, traceID)
}

// ResolveLogPath attempts to find the best writable log file path.
func resolveLogPath() string {
	for _, path := range PlatformLogPaths() {
		dir := filepath.Dir(path)
		if err := os.MkdirAll(dir, 0700); err != nil {
			continue
		}
		file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err == nil {
			file.Close()
			return path
		}
	}
	return ""
}
