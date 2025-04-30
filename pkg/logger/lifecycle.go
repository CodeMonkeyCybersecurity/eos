// pkg/logger/lifecycle.go

package logger

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eoserr"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// generateTraceID returns a short 8-char trace ID.
func GenerateTraceID() string {
	return uuid.New().String()[:8]
}

func TraceIDFromContext(ctx context.Context) string {
	val := ctx.Value(traceIDKey)
	if str, ok := val.(string); ok {
		return str
	}
	return "unknown"
}

func WithCommandLogging(ctx context.Context, name string, fn func(context.Context) error) (string, error) {
	traceID := GenerateTraceID()
	ctx = WithTraceID(ctx, traceID)

	log := L().With(zap.String("trace_id", traceID))
	start := time.Now()

	log.Info("Command started", zap.String("command", name), zap.Time("start_time", start))

	err := fn(ctx)

	duration := time.Since(start)
	if err != nil {
		if eoserr.IsExpectedUserError(err) {
			log.Warn("Command completed with user error", zap.String("command", name), zap.Duration("duration", duration), zap.Error(err))
		} else {
			if eoserr.IsExpectedUserError(err) {
				log.Warn("Command completed with user error", zap.Error(err))
			} else {
				log.Error("Command failed", zap.Error(err))
			}
		}
	} else {
		log.Info("Command completed", zap.String("command", name), zap.Duration("duration", duration))
	}
	return traceID, err
}
func WithTraceID(ctx context.Context, traceID string) context.Context {
	return context.WithValue(ctx, traceIDKey, traceID)
}

// LogCommandStart is a CLI fallback for packages without zap/logger context.
// This traceID is not propagated into structured logs.
func LogCommandStart(cmd string) (string, time.Time) {
	traceID := GenerateTraceID()
	start := time.Now()
	fmt.Printf("[INFO] Command starting: %s | trace_id=%s\n", cmd, traceID)
	return traceID, start
}

func LogCommandEnd(cmd string, traceID string, start time.Time) {
	duration := time.Since(start)
	fmt.Printf("[INFO] Command completed: %s | duration=%s | trace_id=%s\n", cmd, duration, traceID)
}

// ResolveLogPath attempts to find the best writable log file path.
func ResolveLogPath() string {
	for _, path := range PlatformLogPaths() {
		dir := filepath.Dir(path)
		if err := os.MkdirAll(dir, 0700); err != nil {
			continue
		}
		file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err == nil {
			if cerr := file.Close(); cerr != nil {
				L().Warn("Failed to close test log file", zap.String("path", path), zap.Error(cerr))
			}
			L().Info("📝 Using resolved log path", zap.String("log_path", path))
			return path
		} else {
			L().Debug("Skipped unwritable log path", zap.String("path", path), zap.Error(err))
		}
	}

	L().Warn("⚠️ No writable log path could be resolved")
	return ""
}

// LogCommandLifecycle returns a deferred function for consistent start/stop logging.
func LogCommandLifecycle(cmdName string) func(err *error) {
	start := time.Now()
	L().Info("Command started", zap.String("command", cmdName), zap.Time("start_time", start))

	return func(err *error) {
		duration := time.Since(start)
		if *err != nil {
			L().Error("Command failed", zap.String("command", cmdName), zap.Duration("duration", duration), zap.Error(*err))
		} else {
			L().Info("Command completed", zap.String("command", cmdName), zap.Duration("duration", duration))
		}
	}
}
