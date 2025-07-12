// pkg/execute/retry.go

package execute

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Package execute provides retry functionality with structured logging
// This implementation follows Eos standards:
// - All fmt.Printf/Println replaced with structured logging
// - User-facing output uses stderr to preserve stdout
// - Enhanced error handling and context

// RetryCommand retries execution with structured logging and proper error handling
func RetryCommand(rc *eos_io.RuntimeContext, maxAttempts int, delay time.Duration, name string, args ...string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting command retry execution",
		zap.String("command", name),
		zap.Strings("args", args),
		zap.Int("max_attempts", maxAttempts),
		zap.Duration("delay", delay))

	var lastErr error
	for i := 1; i <= maxAttempts; i++ {
		logger.Info("Executing command attempt",
			zap.Int("attempt", i),
			zap.String("command", name),
			zap.Strings("args", args))

		// Display attempt info to user via stderr
		if _, err := fmt.Fprintf(os.Stderr, "[Attempt %d] %s %s\n", i, name, joinArgs(args)); err != nil {
			logger.Warn("Failed to write attempt info to stderr", zap.Error(err))
		}

		cmd := exec.CommandContext(rc.Ctx, name, args...)

		var buf bytes.Buffer
		cmd.Stdout = io.MultiWriter(os.Stdout, &buf)
		cmd.Stderr = io.MultiWriter(os.Stderr, &buf)

		err := cmd.Run()
		if err == nil {
			logger.Info("Command attempt succeeded",
				zap.Int("attempt", i),
				zap.String("command", name))

			// Display success info to user via stderr
			if _, writeErr := fmt.Fprintf(os.Stderr, "[Attempt %d] Command succeeded\n", i); writeErr != nil {
				logger.Warn("Failed to write success info to stderr", zap.Error(writeErr))
			}
			return nil
		}

		lastErr = err
		logger.Warn("Command attempt failed",
			zap.Int("attempt", i),
			zap.String("command", name),
			zap.Error(err))

		// Display failure info to user via stderr
		if _, writeErr := fmt.Fprintf(os.Stderr, "[Attempt %d] Command failed: %v\n", i, err); writeErr != nil {
			logger.Warn("Failed to write failure info to stderr", zap.Error(writeErr))
		}

		// Wait before retry (except on last attempt)
		if i < maxAttempts {
			logger.Info("Waiting before retry",
				zap.Duration("delay", delay),
				zap.Int("next_attempt", i+1))
			time.Sleep(delay)
		}
	}

	logger.Error("All command attempts failed",
		zap.String("command", name),
		zap.Int("total_attempts", maxAttempts),
		zap.Error(lastErr))

	return fmt.Errorf("command failed after %d attempts: %v", maxAttempts, lastErr)
}

// RetryCommandCaptureRefactored retries execution with output capture and structured logging
func RetryCommandCaptureRefactored(rc *eos_io.RuntimeContext, maxAttempts int, delay time.Duration, name string, args ...string) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting command retry execution with capture",
		zap.String("command", name),
		zap.Strings("args", args),
		zap.Int("max_attempts", maxAttempts),
		zap.Duration("delay", delay))

	var lastErr error
	var output string

	for i := 1; i <= maxAttempts; i++ {
		logger.Info("Executing command attempt with capture",
			zap.Int("attempt", i),
			zap.String("command", name),
			zap.Strings("args", args))

		// Display attempt info to user via stderr
		if _, err := fmt.Fprintf(os.Stderr, "[Capturing Attempt %d] %s %s\n", i, name, joinArgs(args)); err != nil {
			logger.Warn("Failed to write attempt info to stderr", zap.Error(err))
		}

		cmd := exec.CommandContext(rc.Ctx, name, args...)
		var buf bytes.Buffer
		cmd.Stdout = &buf
		cmd.Stderr = &buf

		err := cmd.Run()
		output = buf.String()

		if err == nil {
			logger.Info("Command attempt with capture succeeded",
				zap.Int("attempt", i),
				zap.String("command", name),
				zap.Int("output_length", len(output)))
			return output, nil
		}

		lastErr = err
		logger.Warn("Command attempt with capture failed",
			zap.Int("attempt", i),
			zap.String("command", name),
			zap.Error(err),
			zap.String("output", output))

		// Display failure info to user via stderr
		if _, writeErr := fmt.Fprintf(os.Stderr, "[Attempt %d] Command failed: %v\n", i, err); writeErr != nil {
			logger.Warn("Failed to write failure info to stderr", zap.Error(writeErr))
		}

		// Wait before retry (except on last attempt)
		if i < maxAttempts {
			logger.Info("Waiting before retry",
				zap.Duration("delay", delay),
				zap.Int("next_attempt", i+1))
			time.Sleep(delay)
		}
	}

	logger.Error("All command attempts with capture failed",
		zap.String("command", name),
		zap.Int("total_attempts", maxAttempts),
		zap.Error(lastErr))

	return output, fmt.Errorf("command failed after %d attempts: %v", maxAttempts, lastErr)
}
