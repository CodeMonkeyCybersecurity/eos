// pkg/execute/execute_refactored.go

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

// TODO: This is a refactored version of execute.go following Eos standards:
// - All fmt.Printf/Println replaced with structured logging
// - Fallback logging uses stderr instead of stdout
// - Enhanced error handling and context

// RunRefactored executes a command with structured logging and proper error handling
func RunRefactored(ctx context.Context, opts Options) (string, error) {
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
	rc, span := telemetry.Start(rc, "execute.RunRefactored")
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
		logInfoRefactored(logger, "Dry run mode - command not executed", zap.String("command", cmdStr))
		return "", nil
	}

	logInfoRefactored(logger, "Starting execution", zap.String("command", cmdStr))

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
		writer := io.MultiWriter(os.Stdout, &buf)
		cmd.Stdout = writer
		cmd.Stderr = writer

		err = cmd.Run()
		output = buf.String()

		if err == nil {
			logInfoRefactored(logger, "Execution succeeded", zap.String("command", cmdStr))
			break
		}

		summary := eos_err.ExtractSummary(ctx, output, 2)
		span.RecordError(err)
		logErrorRefactored(logger, "Execution failed", err,
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

// logInfoRefactored logs info messages with fallback to stderr (not stdout)
func logInfoRefactored(logger *zap.Logger, msg string, fields ...zap.Field) {
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

// logErrorRefactored logs error messages with fallback to stderr (not stdout)
func logErrorRefactored(logger *zap.Logger, msg string, err error, fields ...zap.Field) {
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

// CmdRefactored returns a function that executes the given command and args with default options
func CmdRefactored(ctx context.Context, cmd string, args ...string) func() error {
	return func() error {
		_, err := RunRefactored(ctx, Options{
			Command: cmd,
			Args:    args,
		})
		return err
	}
}

// RunSimpleRefactored executes a command with minimal options and structured logging
func RunSimpleRefactored(ctx context.Context, cmd string, args ...string) error {
	_, err := RunRefactored(ctx, Options{
		Command: cmd,
		Args:    args,
		Capture: false,
	})
	return err
}