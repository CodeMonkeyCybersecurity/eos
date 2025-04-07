// pkg/logger/lifecycle.go

package logger

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// generateTraceID returns a short 8-char trace ID.
func generateTraceID() string {
	return uuid.New().String()[:8]
}

func WithCommandLogging(name string, fn func() error) error {
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

// For use in pkg/ without zap
func LogCommandStart(cmd string) (string, time.Time) {
	traceID := generateTraceID()
	start := time.Now()
	fmt.Printf("[INFO] Command starting: %s | trace_id=%s\n", cmd, traceID)
	return traceID, start
}

func LogCommandEnd(cmd string, traceID string, start time.Time) {
	duration := time.Since(start)
	fmt.Printf("[INFO] Command completed: %s | duration=%s | trace_id=%s\n", cmd, duration, traceID)
}
