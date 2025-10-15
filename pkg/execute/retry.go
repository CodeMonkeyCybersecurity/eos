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
// - Error type detection to fail fast on deterministic errors

// ErrorType classifies errors for retry decision making
type ErrorType int

const (
	// ErrorTypeTransient indicates a temporary failure that may succeed on retry
	// Examples: network timeouts, temporary locks, service starting up
	ErrorTypeTransient ErrorType = iota

	// ErrorTypeDeterministic indicates a permanent failure that won't be fixed by retrying
	// Examples: config validation, missing files, invalid credentials, permission denied
	ErrorTypeDeterministic

	// ErrorTypeUnknown indicates we can't classify the error
	ErrorTypeUnknown
)

// ClassifyError determines if an error is transient (retry) or deterministic (fail fast)
// Returns ErrorTypeDeterministic for: config errors, validation failures, missing files, permission denied
// Returns ErrorTypeTransient for: network timeouts, locks, service not ready
// Returns ErrorTypeUnknown when classification is uncertain (defaults to retrying)
func ClassifyError(err error, output string) ErrorType {
	if err == nil {
		return ErrorTypeTransient
	}

	errStr := err.Error()
	outStr := output

	// Deterministic failures - DO NOT RETRY
	deterministicPatterns := []string{
		"no such file or directory",
		"permission denied",
		"command not found",
		"invalid configuration",
		"validation failed",
		"invalid credentials",
		"config error",
		"syntax error",
		"parse error",
		"already exists",
		"already in use",
		"bind: address already in use",
		"multiple network interfaces", // Requires user decision
		"missing required",
		"forbidden",
		"unauthorized",
		"bad request",
		"invalid argument",
	}

	for _, pattern := range deterministicPatterns {
		if bytes.Contains([]byte(errStr), []byte(pattern)) ||
			bytes.Contains([]byte(outStr), []byte(pattern)) {
			return ErrorTypeDeterministic
		}
	}

	// Transient failures - RETRY
	transientPatterns := []string{
		"timeout",
		"connection refused",
		"connection reset",
		"temporary failure",
		"resource temporarily unavailable",
		"try again",
		"locked",
		"not ready",
		"starting up",
		"dial tcp",
		"network unreachable",
		"i/o timeout",
		"context deadline exceeded",
	}

	for _, pattern := range transientPatterns {
		if bytes.Contains([]byte(errStr), []byte(pattern)) ||
			bytes.Contains([]byte(outStr), []byte(pattern)) {
			return ErrorTypeTransient
		}
	}

	// Default to unknown (will retry conservatively)
	return ErrorTypeUnknown
}

// errorTypeString converts ErrorType to string for logging
func errorTypeString(et ErrorType) string {
	switch et {
	case ErrorTypeTransient:
		return "transient"
	case ErrorTypeDeterministic:
		return "deterministic"
	case ErrorTypeUnknown:
		return "unknown"
	default:
		return "unknown"
	}
}

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
		output := buf.String()

		// Classify error type to decide if we should retry
		errorType := ClassifyError(err, output)

		logger.Warn("Command attempt failed",
			zap.Int("attempt", i),
			zap.String("command", name),
			zap.Error(err),
			zap.String("error_type", errorTypeString(errorType)))

		// Display failure info to user via stderr
		if _, writeErr := fmt.Fprintf(os.Stderr, "[Attempt %d] Command failed: %v\n", i, err); writeErr != nil {
			logger.Warn("Failed to write failure info to stderr", zap.Error(writeErr))
		}

		// FAIL FAST on deterministic errors
		if errorType == ErrorTypeDeterministic {
			logger.Error("Deterministic error detected - not retrying",
				zap.String("command", name),
				zap.Error(err),
				zap.String("output", output),
				zap.String("remediation", "Fix the configuration or input and try again"))
			return fmt.Errorf("deterministic error (will not retry): %w\nOutput: %s\nRemediation: Check configuration and inputs", err, output)
		}

		// Wait before retry (except on last attempt)
		if i < maxAttempts {
			logger.Info("Waiting before retry",
				zap.Duration("delay", delay),
				zap.Int("next_attempt", i+1))
			// SECURITY P2 #7: Use context-aware sleep to respect cancellation
			select {
			case <-time.After(delay):
				// Continue to next retry
			case <-rc.Ctx.Done():
				return fmt.Errorf("retry cancelled: %w", rc.Ctx.Err())
			}
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

		// Classify error type to decide if we should retry
		errorType := ClassifyError(err, output)

		logger.Warn("Command attempt with capture failed",
			zap.Int("attempt", i),
			zap.String("command", name),
			zap.Error(err),
			zap.String("output", output),
			zap.String("error_type", errorTypeString(errorType)))

		// Display failure info to user via stderr
		if _, writeErr := fmt.Fprintf(os.Stderr, "[Attempt %d] Command failed: %v\n", i, err); writeErr != nil {
			logger.Warn("Failed to write failure info to stderr", zap.Error(writeErr))
		}

		// FAIL FAST on deterministic errors
		if errorType == ErrorTypeDeterministic {
			logger.Error("Deterministic error detected - not retrying",
				zap.String("command", name),
				zap.Error(err),
				zap.String("output", output),
				zap.String("remediation", "Fix the configuration or input and try again"))
			return output, fmt.Errorf("deterministic error (will not retry): %w\nOutput: %s\nRemediation: Check configuration and inputs", err, output)
		}

		// Wait before retry (except on last attempt)
		if i < maxAttempts {
			logger.Info("Waiting before retry",
				zap.Duration("delay", delay),
				zap.Int("next_attempt", i+1))
			// SECURITY P2 #7: Use context-aware sleep to respect cancellation
			select {
			case <-time.After(delay):
				// Continue to next retry
			case <-rc.Ctx.Done():
				return output, fmt.Errorf("retry cancelled: %w", rc.Ctx.Err())
			}
		}
	}

	logger.Error("All command attempts with capture failed",
		zap.String("command", name),
		zap.Int("total_attempts", maxAttempts),
		zap.Error(lastErr))

	return output, fmt.Errorf("command failed after %d attempts: %v", maxAttempts, lastErr)
}
