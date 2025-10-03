// pkg/execute/execute.go

package execute

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/telemetry"
	cerr "github.com/cockroachdb/errors"
	"go.opentelemetry.io/otel/attribute"
	"go.uber.org/zap"
)

// Package execute provides secure command execution with structured logging
// This implementation follows Eos standards:
// - All fmt.Printf/Println replaced with structured logging
// - Fallback logging uses stderr instead of stdout
// - Enhanced error handling and context
// - Shell execution disabled for security

// Run executes a command with structured logging and proper error handling
func Run(ctx context.Context, opts Options) (string, error) {
	cmdStr := buildCommandString(opts.Command, opts.Args...)

	// Setup logger and context
	logger := opts.Logger
	if logger == nil {
		logger = DefaultLogger
	}
	if logger == nil {
		// Create a no-op logger if both opts.Logger and DefaultLogger are nil
		logger = zap.NewNop()
	}
	if ctx == nil {
		ctx = context.Background()
	}
	rc, cancel := context.WithTimeout(ctx, defaultTimeout(opts.Timeout))
	defer cancel()

	// Start telemetry span
	rc, span := telemetry.Start(rc, "execute.Run")
	defer span.End()
	span.SetAttributes(
		attribute.String("command", opts.Command),
		attribute.Bool("shell", opts.Shell),
		attribute.String("args", strings.Join(opts.Args, " ")),
	)

	// TODO: Command validation would go here if needed
	// Validation logic can be added based on specific requirements

	// Dry run mode
	if opts.DryRun || DefaultDryRun {
		logInfo(logger, "Dry run mode - command not executed", zap.String("command", cmdStr))
		return "", nil
	}

	// Add detailed debug logging for systemctl commands to track down -m flag issue
	if opts.Command == "systemctl" {
		logger.Debug("SYSTEMCTL COMMAND TRACE",
			zap.String("command", opts.Command),
			zap.Strings("args", opts.Args),
			zap.String("full_command", cmdStr))
	}

	logInfo(logger, "Starting execution", zap.String("command", cmdStr))

	var output string
	var err error

	// Setup retry configuration with defaults
	maxRetries := max(1, opts.Retries)
	useBackoff := opts.ExponentialBackoff || (opts.Retries > 1 && !opts.ExponentialBackoff) // default true if retries > 1
	initialDelay := opts.Delay
	if initialDelay == 0 {
		initialDelay = 100 * time.Millisecond // sensible default
	}

	// Setup retry timeout context if specified
	retryCtx := rc
	var retryCancel context.CancelFunc
	if opts.MaxRetryTimeout > 0 {
		retryCtx, retryCancel = context.WithTimeout(rc, opts.MaxRetryTimeout)
		defer retryCancel()
	}

	retryStartTime := time.Now()

	for i := 1; i <= maxRetries; i++ {
		// Check if retry timeout exceeded
		if opts.MaxRetryTimeout > 0 && time.Since(retryStartTime) >= opts.MaxRetryTimeout {
			return output, cerr.Wrapf(err, "retry timeout exceeded after %v", opts.MaxRetryTimeout)
		}

		var cmd *exec.Cmd
		if opts.Shell {
			// SECURITY: Shell mode is dangerous and should be avoided
			logger.Warn("Shell execution mode is deprecated due to security risks",
				zap.String("command", opts.Command))
			return "", fmt.Errorf("shell execution mode disabled for security - use Args instead")
		} else {
			cmd = exec.CommandContext(retryCtx, opts.Command, opts.Args...)
		}
		if opts.Dir != "" {
			cmd.Dir = opts.Dir
		}

		var buf bytes.Buffer
		// FIXED: Only capture to buffer, use structured logging for output
		// Removed os.Stdout to prevent raw command output mixing with structured logs
		cmd.Stdout = &buf
		cmd.Stderr = &buf

		err = cmd.Run()
		output = buf.String()

		if err == nil {
			logInfo(logger, "Execution succeeded", zap.String("command", cmdStr))
			break
		}

		summary := eos_err.ExtractSummary(ctx, output, 2)
		span.RecordError(err)
		logError(logger, "Execution failed", err,
			zap.Int("attempt", i),
			zap.Int("max_attempts", maxRetries),
			zap.String("command", cmdStr),
			zap.String("summary", summary),
		)

		if i < maxRetries {
			// Calculate delay with exponential backoff and jitter
			delay := initialDelay
			if useBackoff {
				// Exponential backoff: delay * 2^(attempt-1)
				// e.g., 100ms, 200ms, 400ms, 800ms, 1600ms...
				delay = initialDelay * time.Duration(1<<uint(i-1))
			}

			// Add jitter (±25%) to prevent thundering herd
			jitterFactor := (2*float64(time.Now().UnixNano()%1000)/1000.0 - 1) * 0.25
			jitter := time.Duration(float64(delay) * jitterFactor)
			delay = delay + jitter

			// Cap maximum delay at 30 seconds
			if delay > 30*time.Second {
				delay = 30 * time.Second
			}

			logger.Debug("Retrying after delay",
				zap.Duration("delay", delay),
				zap.Bool("exponential_backoff", useBackoff),
				zap.Int("attempt", i))

			select {
			case <-time.After(delay):
				// Continue to next retry
			case <-retryCtx.Done():
				return output, cerr.Wrapf(retryCtx.Err(), "retry cancelled: %w", err)
			}
		}
	}

	if err != nil {
		return output, cerr.Wrapf(err, "command failed after %d attempts", maxRetries)
	}

	if opts.Capture {
		return output, nil
	}
	return "", nil
}

// logInfo logs info messages with fallback to stderr (not stdout)
func logInfo(logger *zap.Logger, msg string, fields ...zap.Field) {
	if logger != nil {
		logger.Info(msg, fields...)
	} else if DefaultLogger != nil {
		DefaultLogger.Info(msg, fields...)
	} else {
		// Use stderr for fallback logging to preserve stdout
		if _, err := fmt.Fprintf(os.Stderr, "[INFO] %s\n", msg); err != nil {
			// If stderr write fails, there's nothing more we can do
		}
	}
}

// logError logs error messages with fallback to stderr (not stdout)
func logError(logger *zap.Logger, msg string, err error, fields ...zap.Field) {
	if logger != nil {
		logger.Error(msg, append(fields, zap.Error(err))...)
	} else if DefaultLogger != nil {
		DefaultLogger.Error(msg, append(fields, zap.Error(err))...)
	} else {
		// Use stderr for fallback logging to preserve stdout
		if _, writeErr := fmt.Fprintf(os.Stderr, "[ERROR] %s: %v\n", msg, err); writeErr != nil {
			// If stderr write fails, there's nothing more we can do
		}
	}
}

// Cmd returns a function that executes the given command and args with default options
func Cmd(ctx context.Context, cmd string, args ...string) func() error {
	return func() error {
		_, err := Run(ctx, Options{
			Command: cmd,
			Args:    args,
		})
		return err
	}
}

// RunSimple executes a command with minimal options and structured logging
func RunSimple(ctx context.Context, cmd string, args ...string) error {
	_, err := Run(ctx, Options{
		Command: cmd,
		Args:    args,
		Capture: false,
	})
	return err
}

// joinArgs joins command arguments with proper quoting for logging
func joinArgs(args []string) string {
	return shellQuote(args)
}

// shellQuote ensures args are properly quoted for visibility in logs
func shellQuote(args []string) string {
	var quoted []string
	for _, arg := range args {
		quoted = append(quoted, fmt.Sprintf("'%s'", arg))
	}
	return strings.Join(quoted, " ")
}

// RunShell executes a shell command (deprecated for security reasons)
func RunShell(ctx context.Context, cmdStr string) (string, error) {
	// Shell execution is disabled for security
	return "", fmt.Errorf("shell execution disabled for security - use Run with Args instead")
}
