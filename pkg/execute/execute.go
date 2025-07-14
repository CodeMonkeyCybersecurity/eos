// pkg/execute/execute.go

package execute

import (
	"bytes"
	"context"
	"fmt"
	"io"
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

	logInfo(logger, "Starting execution", zap.String("command", cmdStr))

	var output string
	var err error

	for i := 1; i <= max(1, opts.Retries); i++ {
		var cmd *exec.Cmd
		if opts.Shell {
			// SECURITY: Shell mode is dangerous and should be avoided
			logger.Warn("Shell execution mode is deprecated due to security risks",
				zap.String("command", opts.Command))
			return "", fmt.Errorf("shell execution mode disabled for security - use Args instead")
		} else {
			cmd = exec.CommandContext(rc, opts.Command, opts.Args...)
		}
		if opts.Dir != "" {
			cmd.Dir = opts.Dir
		}

		var buf bytes.Buffer
		// TODO: Remove os.Stdout from MultiWriter to prevent raw command output in logs
		// This causes unstructured output mixed with structured logs (issue flagged 2025-07-14)
		// Should only capture to buffer and use structured logging for command output
		writer := io.MultiWriter(os.Stdout, &buf)
		cmd.Stdout = writer
		cmd.Stderr = writer

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
			zap.String("command", cmdStr),
			zap.String("summary", summary),
		)

		if i < opts.Retries {
			time.Sleep(opts.Delay)
		}
	}

	if err != nil {
		return output, cerr.Wrapf(err, "command failed after %d attempts", opts.Retries)
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
