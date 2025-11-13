// pkg/watchdog/timer_watchdog.go

package watchdog

import (
	"context"
	"os"
	"runtime/debug"
	"time"

	"go.uber.org/zap"
)

// TimerWatchdog implements a timeout mechanism for command execution
type TimerWatchdog struct {
	timeout   time.Duration
	logger    *zap.Logger
	timer     *time.Timer
	done      chan bool
	onTimeout func()
}

// TimerConfig configures the timer watchdog
type TimerConfig struct {
	Timeout   time.Duration
	OnTimeout func() // Optional custom timeout handler
}

// DefaultTimerConfig returns the default timer configuration
func DefaultTimerConfig() TimerConfig {
	return TimerConfig{
		Timeout: 3 * time.Minute,
		OnTimeout: func() {
			// Default behavior: exit with error
			os.Exit(124) // Standard timeout exit code
		},
	}
}

// NewTimerWatchdog creates a new timer watchdog
func NewTimerWatchdog(logger *zap.Logger, config TimerConfig) *TimerWatchdog {
	if config.OnTimeout == nil {
		config.OnTimeout = DefaultTimerConfig().OnTimeout
	}

	return &TimerWatchdog{
		timeout:   config.Timeout,
		logger:    logger,
		done:      make(chan bool, 1),
		onTimeout: config.OnTimeout,
	}
}

// Start begins the timer watchdog
func (tw *TimerWatchdog) Start() {
	tw.timer = time.NewTimer(tw.timeout)

	go func() {
		// SECURITY: Panic recovery for timer goroutine
		defer func() {
			if r := recover(); r != nil {
				tw.logger.Error("Timer watchdog panic recovered",
					zap.Any("panic", r),
					zap.String("stack", string(debug.Stack())))
			}
		}()

		select {
		case <-tw.done:
			// Command completed, stop timer
			if !tw.timer.Stop() {
				// Drain the channel if timer already fired
				select {
				case <-tw.timer.C:
				default:
				}
			}
			tw.logger.Debug("Timer watchdog stopped normally",
				zap.Duration("elapsed", tw.timeout))

		case <-tw.timer.C:
			// Timeout occurred
			tw.logger.Error("Command execution timeout exceeded",
				zap.Duration("timeout", tw.timeout),
				zap.Int("pid", os.Getpid()))

			// Call the timeout handler
			tw.onTimeout()
		}
	}()
}

// Stop signals that the command completed successfully
func (tw *TimerWatchdog) Stop() {
	select {
	case tw.done <- true:
	default:
		// Channel already has a value, ignore
	}
}

// ExecuteWithTimeout runs a function with timeout protection
func ExecuteWithTimeout(ctx context.Context, logger *zap.Logger, timeout time.Duration, fn func() error) error {
	// Create timer watchdog
	config := TimerConfig{
		Timeout: timeout,
		OnTimeout: func() {
			logger.Fatal("Execution timeout exceeded",
				zap.Duration("timeout", timeout))
		},
	}

	watchdog := NewTimerWatchdog(logger, config)
	watchdog.Start()
	defer watchdog.Stop()

	// Execute the function
	return fn()
}

// CommandWatchdog provides a higher-level interface for command execution with timeout
type CommandWatchdog struct {
	logger  *zap.Logger
	timeout time.Duration
}

// NewCommandWatchdog creates a watchdog for command execution
func NewCommandWatchdog(logger *zap.Logger, timeout time.Duration) *CommandWatchdog {
	return &CommandWatchdog{
		logger:  logger,
		timeout: timeout,
	}
}

// Execute runs a command with timeout protection
func (cw *CommandWatchdog) Execute(commandName string, args []string, fn func() error) error {
	cw.logger.Info("Command execution started with watchdog",
		zap.String("command", commandName),
		zap.Strings("args", args),
		zap.Duration("timeout", cw.timeout),
		zap.String("working_dir", func() string {
			if wd, err := os.Getwd(); err == nil {
				return wd
			}
			return "unknown"
		}()),
		zap.Int("uid", os.Getuid()),
		zap.Int("gid", os.Getgid()))

	// Use a timer with done channel for clean shutdown
	timer := time.NewTimer(cw.timeout)
	defer timer.Stop()

	done := make(chan error, 1)

	// Execute function in goroutine with panic recovery
	go func() {
		defer func() {
			if r := recover(); r != nil {
				cw.logger.Error("Command goroutine panic recovered",
					zap.String("command", commandName),
					zap.Any("panic", r),
					zap.String("stack", string(debug.Stack())))
				// Send error through channel instead of crashing
				select {
				case done <- nil:
				default:
				}
			}
		}()
		done <- fn()
	}()

	// Wait for completion or timeout
	select {
	case err := <-done:
		// Command completed
		if err != nil {
			cw.logger.Error("Command completed with error",
				zap.Error(err),
				zap.String("command", commandName))
		} else {
			cw.logger.Info("Command completed successfully",
				zap.String("command", commandName))
		}
		return err

	case <-timer.C:
		// Timeout occurred
		cw.logger.Fatal("Command execution timeout exceeded",
			zap.Duration("timeout", cw.timeout),
			zap.String("command", commandName))
		return nil // Never reached due to Fatal
	}
}
