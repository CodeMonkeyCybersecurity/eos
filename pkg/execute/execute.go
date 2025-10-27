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

	// SECURITY: Command validation
	// Commands are executed via exec.CommandContext which doesn't use shell
	// Arguments are passed as separate parameters (not concatenated strings)
	// This prevents shell injection attacks
	// Additional validation can be added here if specific command restrictions are needed

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

		// Set environment variables if provided
		// If Env is nil, command inherits parent process environment (default behavior)
		// If Env is non-nil (even empty slice), command gets only those variables
		if opts.Env != nil {
			cmd.Env = opts.Env
		}

		var buf bytes.Buffer
		// StreamOutput: Show output directly to user in real-time (for long-running installs)
		// Otherwise: Capture to buffer for structured logging
		if opts.StreamOutput {
			// Stream mode: Show output to user, also capture for error reporting
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
		} else {
			// Buffer mode: Capture for structured logging
			cmd.Stdout = &buf
			cmd.Stderr = &buf
		}

		err = cmd.Run()
		output = buf.String()

		if err == nil {
			logInfo(logger, "Execution succeeded", zap.String("command", cmdStr))
			break
		}

		summary := eos_err.ExtractSummary(ctx, output, 2)
		span.RecordError(err)

		// Context-aware error logging
		exitCode := getExitCode(err)
		logLevel := determineLogLevel(opts.Context, cmdStr, exitCode, summary)
		contextMsg := getContextMessage(opts.Context, cmdStr, exitCode, summary)

		// Log at appropriate level based on context
		switch logLevel {
		case LogLevelDebug:
			logger.Debug(contextMsg,
				zap.Int("attempt", i),
				zap.String("command", cmdStr),
				zap.Int("exit_code", exitCode),
				zap.String("output", summary))
		case LogLevelInfo:
			logger.Info(contextMsg,
				zap.Int("attempt", i),
				zap.String("command", cmdStr),
				zap.Int("exit_code", exitCode))
		case LogLevelWarn:
			logger.Warn(contextMsg,
				zap.Int("attempt", i),
				zap.String("command", cmdStr),
				zap.Int("exit_code", exitCode),
				zap.String("output", summary))
		case LogLevelError:
			logError(logger, "Execution failed", err,
				zap.Int("attempt", i),
				zap.Int("max_attempts", maxRetries),
				zap.String("command", cmdStr),
				zap.Int("exit_code", exitCode),
				zap.String("summary", summary),
			)
		}

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

// getExitCode extracts numeric exit code from error
func getExitCode(err error) int {
	if err == nil {
		return 0
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode()
	}
	return -1 // Unknown error type
}

// LogLevel represents logging severity
type LogLevel int

const (
	LogLevelDebug LogLevel = iota
	LogLevelInfo
	LogLevelWarn
	LogLevelError
)

// determineLogLevel decides what log level to use based on execution context
func determineLogLevel(ctx ExecutionContext, command string, exitCode int, output string) LogLevel {
	// Success - always INFO
	if exitCode == 0 {
		return LogLevelInfo
	}

	// Context-specific interpretation
	switch ctx {
	case ContextRemoval:
		return interpretRemovalExitCode(command, exitCode, output)
	case ContextVerify:
		return interpretVerifyExitCode(command, exitCode, output)
	default:
		// ContextNormal: any error is ERROR
		return LogLevelError
	}
}

// interpretRemovalExitCode interprets exit codes during removal operations
func interpretRemovalExitCode(command string, exitCode int, output string) LogLevel {
	// Systemd commands during removal
	if strings.Contains(command, "systemctl") {
		switch exitCode {
		case 5:
			// Unit not loaded → EXPECTED during removal
			return LogLevelDebug
		case 6:
			// Unit not active → EXPECTED during removal
			return LogLevelDebug
		case 1:
			// Generic failure → Check output for specifics
			if strings.Contains(output, "does not exist") || strings.Contains(output, "not loaded") {
				return LogLevelDebug // Not found is good during removal
			}
			return LogLevelError
		default:
			return LogLevelError
		}
	}

	// User/group management during removal
	if strings.Contains(command, "userdel") || strings.Contains(command, "groupdel") {
		if exitCode == 6 {
			// User/group doesn't exist → EXPECTED during removal
			return LogLevelDebug
		}
		return LogLevelError
	}

	// Process management during removal
	if strings.Contains(command, "pkill") || strings.Contains(command, "pgrep") {
		if exitCode == 1 {
			// No processes found → EXPECTED during removal
			return LogLevelDebug
		}
		if exitCode == 2 {
			// Check for "invalid user" (user already removed)
			if strings.Contains(output, "invalid user") {
				return LogLevelDebug
			}
			return LogLevelError
		}
		return LogLevelError
	}

	// Default: treat as error
	return LogLevelError
}

// interpretVerifyExitCode interprets exit codes during verification
func interpretVerifyExitCode(command string, exitCode int, output string) LogLevel {
	// Systemctl list-unit-files: exit 1 with header-only output = not found (SUCCESS)
	if strings.Contains(command, "systemctl") && strings.Contains(command, "list-unit-files") {
		if exitCode == 1 {
			// Exit 1 means no units matched the pattern
			// Output will be "UNIT FILE STATE PRESET" (header only) if nothing found
			return LogLevelDebug // Successfully verified removal - unit doesn't exist
		}
		if exitCode == 0 {
			// Exit 0 means unit file was found - might be a problem during removal verification
			return LogLevelWarn
		}
	}

	// pgrep: exit 1 = no processes found (SUCCESS during removal verification)
	if strings.Contains(command, "pgrep") && exitCode == 1 {
		return LogLevelDebug // Successfully verified - no processes running
	}

	// id command: exit 1 = user doesn't exist (SUCCESS)
	// PRIMARY signal: exit code 1 (locale-independent)
	// Note: Error message is locale-dependent ("no such user" in English, "Benutzer existiert nicht" in German)
	// We trust the exit code alone
	if strings.Contains(command, "id") && exitCode == 1 {
		return LogLevelDebug // Successfully verified - user removed
	}

	// Generic "not found" patterns (fallback for other commands)
	// PRIMARY signal: exit code 1
	// SECONDARY signal: output strings (locale-dependent, use as hint only)
	if exitCode == 1 {
		// Many commands use exit 1 for "not found"
		// Check output for confirmation, but accept exit code alone
		if strings.Contains(output, "does not exist") ||
			strings.Contains(output, "not found") ||
			strings.Contains(output, "not loaded") ||
			len(strings.TrimSpace(output)) == 0 { // Empty output often means "not found"
			return LogLevelDebug // Successfully verified removal
		}
		// Exit 1 but with unexpected output - might be an error
		// Log at INFO level instead of ERROR (not critical during verification)
		return LogLevelInfo
	}

	if exitCode == 0 {
		// Found something that should be removed - might be a problem
		return LogLevelWarn
	}

	return LogLevelError
}

// getContextMessage returns human-readable context for log message
func getContextMessage(ctx ExecutionContext, command string, exitCode int, output string) string {
	if ctx == ContextRemoval {
		if strings.Contains(command, "systemctl") && exitCode == 5 {
			return "Service already stopped or never installed (expected during removal)"
		}
		if strings.Contains(command, "systemctl") && exitCode == 6 {
			return "Service not active (expected during removal)"
		}
		if strings.Contains(command, "userdel") && exitCode == 6 {
			return "User already removed (expected during removal)"
		}
		if strings.Contains(command, "groupdel") && exitCode == 6 {
			return "Group already removed (expected during removal)"
		}
		if (strings.Contains(command, "pkill") || strings.Contains(command, "pgrep")) && exitCode == 1 {
			return "No processes found (expected during removal)"
		}
		if strings.Contains(command, "pkill") && exitCode == 2 && strings.Contains(output, "invalid user") {
			return "User already removed (expected during removal)"
		}
	}
	return "Command completed with non-zero exit code"
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
