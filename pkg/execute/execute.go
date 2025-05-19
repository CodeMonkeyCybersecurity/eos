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

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eoserr"
	"go.uber.org/zap"
)

func Run(opts Options) (string, error) {
	cmdStr := buildCommandString(opts.Command, opts.Args...)

	// Use per-call logger if set, otherwise fallback
	logger := opts.Logger
	if logger == nil {
		logger = DefaultLogger
	}
	dry := opts.DryRun || DefaultDryRun

	if dry {
		logInfo(logger, "Dry-run: skipping execution", zap.String("command", cmdStr))
		return "", nil
	}

	logInfo(logger, "Starting execution", zap.String("command", cmdStr))

	var output string
	var err error

	for i := 1; i <= max(1, opts.Retries); i++ {
		ctx := opts.Ctx
		if ctx == nil {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(context.Background(), defaultTimeout(opts.Timeout))
			defer cancel()
		}

		var cmd *exec.Cmd
		if opts.Shell {
			cmd = exec.CommandContext(ctx, "bash", "-c", opts.Command)
		} else {
			cmd = exec.CommandContext(ctx, opts.Command, opts.Args...)
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

		summary := eoserr.ExtractSummary(output, 2)
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
		return output, fmt.Errorf("command failed after %d attempts: %w", opts.Retries, err)
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

// Settable globals (optional, but encouraged to override per-call)
var (
	DefaultLogger *zap.Logger
	DefaultDryRun bool
)

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
func Cmd(cmd string, args ...string) func() error {
	return func() error {
		_, err := Run(Options{
			Command: cmd,
			Args:    args,
		})
		return err
	}
}

func RunShell(cmdStr string) (string, error) {
	return Run(Options{
		Command: cmdStr,
		Shell:   true,
	})
}

// RunSimple is a legacy-safe wrapper that drops output.
func RunSimple(cmd string, args ...string) error {
	_, err := Run(Options{Command: cmd, Args: args})
	return err
}
