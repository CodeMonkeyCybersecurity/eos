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

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cue"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/telemetry"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/verify"
	cerr "github.com/cockroachdb/errors"
	"go.opentelemetry.io/otel/attribute"
	"go.uber.org/zap"
)

func Run(ctx context.Context, opts Options) (string, error) {
	cmdStr := buildCommandString(opts.Command, opts.Args...)

	// Setup logger and context
	logger := opts.Logger
	if logger == nil {
		logger = DefaultLogger
	}
	if ctx == nil {
		ctx = context.Background()
	}
	rc, cancel := context.WithTimeout(ctx, defaultTimeout(opts.Timeout))
	defer cancel()

	// 📈 Start telemetry span
	rc, span := telemetry.Start(rc, "execute.Run")
	defer span.End()
	span.SetAttributes(
		attribute.String("command", opts.Command),
		attribute.Bool("shell", opts.Shell),
		attribute.String("args", strings.Join(opts.Args, " ")),
	)

	// ✅ Validation
	if opts.Struct != nil {
		if err := verify.Struct(opts.Struct); err != nil {
			span.RecordError(err)
			logError(logger, "🚫 Struct validation failed", err)
			return "", cerr.WithHint(err, "Struct-level validation failed")
		}
	}
	if opts.SchemaPath != "" && opts.YAMLPath != "" {
		if err := eos_cue.ValidateYAMLWithCUE(opts.SchemaPath, opts.YAMLPath); err != nil {
			span.RecordError(err)
			logError(logger, "📄 CUE validation failed", err)
			return "", cerr.WithHint(err, "Schema/YAML mismatch")
		}
	}

	// 🧪 Dry-run
	if opts.DryRun || DefaultDryRun {
		logInfo(logger, "Dry-run: skipping execution", zap.String("command", cmdStr))
		return "", nil
	}

	logInfo(logger, "Starting execution", zap.String("command", cmdStr))

	var output string
	var err error

	for i := 1; i <= max(1, opts.Retries); i++ {
		var cmd *exec.Cmd
		if opts.Shell {
			// SECURITY: Shell mode is dangerous and should be avoided
			// If absolutely necessary, validate and sanitize the command string
			logger.Warn("⚠️ Shell execution mode is deprecated due to security risks",
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

// joinArgs formats arguments for display.
func joinArgs(args []string) string {
	return shellQuote(args)
}

// shellQuote ensures args are properly quoted for visibility.
func shellQuote(args []string) string {
	var quoted []string
	for _, arg := range args {
		quoted = append(quoted, fmt.Sprintf("'%s'", arg))
	}
	return strings.Join(quoted, " ")
}

func logInfo(logger *zap.Logger, msg string, fields ...zap.Field) {
	if logger != nil {
		logger.Info(msg, fields...)
	} else if DefaultLogger != nil {
		DefaultLogger.Info(msg, fields...)
	} else {
		fmt.Println("ℹ️", msg)
	}
}

func logError(logger *zap.Logger, msg string, err error, fields ...zap.Field) {
	if logger != nil {
		logger.Error(msg, append(fields, zap.Error(err))...)
	} else if DefaultLogger != nil {
		DefaultLogger.Error(msg, append(fields, zap.Error(err))...)
	} else {
		fmt.Printf("❌ %s: %v\n", msg, err)
	}
}

// Cmd returns a function that executes the given command and args with default options.
func Cmd(ctx context.Context, cmd string, args ...string) func() error {
	return func() error {
		_, err := Run(ctx, Options{
			Command: cmd,
			Args:    args,
		})
		return err
	}
}

func RunShell(ctx context.Context, cmdStr string) (string, error) {
	// SECURITY: RunShell is deprecated due to command injection risks
	return "", fmt.Errorf("RunShell is disabled for security - use RunSimple with explicit args instead")
}

// RunSimple is a legacy-safe wrapper that drops output.
func RunSimple(ctx context.Context, cmd string, args ...string) error {
	_, err := Run(ctx, Options{Command: cmd, Args: args})
	return err
}
