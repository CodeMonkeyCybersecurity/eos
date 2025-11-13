// pkg/logger/lifecycle.go

package logger

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	cerr "github.com/cockroachdb/errors"
	"github.com/google/uuid"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// generateTraceID returns a short 8-char trace ID.
func GenerateTraceID() string {
	return uuid.New().String()[:8]
}

func WithCommandLogging(rc *eos_io.RuntimeContext, name string, fn func(context.Context) error) (string, error) {
	traceID := GenerateTraceID()

	log := otelzap.Ctx(rc.Ctx)
	start := time.Now()

	log.Info("Command started", zap.String("command", name), zap.Time("start_time", start))

	err := fn(rc.Ctx)

	duration := time.Since(start)
	if err != nil {
		if eos_err.IsExpectedUserError(err) {
			log.Warn("Command completed with user error", zap.String("command", name), zap.Duration("duration", duration), zap.Error(err))
		} else {
			log.Error("Command failed", zap.String("command", name), zap.Duration("duration", duration), zap.Error(err))
		}
	} else {
		log.Info("Command completed", zap.String("command", name), zap.Duration("duration", duration))
	}
	return traceID, err
}

func WithTraceID(rc *eos_io.RuntimeContext, traceID string) context.Context {
	return context.WithValue(rc.Ctx, traceIDKey, traceID)
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
func ResolveLogPath(rc *eos_io.RuntimeContext) string {
	for _, path := range PlatformLogPaths() {
		dir := filepath.Dir(path)
		if err := os.MkdirAll(dir, shared.SecretDirPerm); err != nil {
			continue
		}
		file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err == nil {
			if cerr := file.Close(); cerr != nil {
				otelzap.Ctx(rc.Ctx).Warn("Failed to close test log file", zap.String("path", path), zap.Error(cerr))
			}
			otelzap.Ctx(rc.Ctx).Info(" Using resolved log path", zap.String("log_path", path))
			return path
		} else {
			otelzap.Ctx(rc.Ctx).Debug("Skipped unwritable log path", zap.String("path", path), zap.Error(err))
		}
	}

	otelzap.Ctx(rc.Ctx).Warn("No writable log path could be resolved")
	return ""
}

func TryWritablePath(paths []string) (string, error) {
	for _, path := range paths {
		dir := filepath.Dir(path)
		if err := os.MkdirAll(dir, shared.SecretDirPerm); err != nil {
			continue
		}
		if file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600); err == nil {
			if err := file.Close(); err != nil {
				// Continue to next path if we can't close the file
				continue
			}
			return path, nil
		}
	}
	return "", cerr.New("no writable log path found")
}
