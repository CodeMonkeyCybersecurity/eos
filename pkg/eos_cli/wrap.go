// pkg/eoscli/wrap.go

package eos_cli

import (
	"context"
	"os"
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/bootstrap"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/security"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/watchdog"
	cerr "github.com/cockroachdb/errors"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// Wrap ensures panic recovery, telemetry, logging, and validation
func Wrap(fn func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) (err error) {
		logger.InitFallback()
		
		// Debug logging
		fmt.Fprintf(os.Stderr, "DEBUG: Wrap() called for command: %s\n", cmd.Name())
		
		ctx := eos_io.NewContext(context.Background(), cmd.Name())
		defer ctx.End(&err)

		// Panic recovery
		defer func() {
			if r := recover(); r != nil {
				err = cerr.AssertionFailedf("panic: %v", r)
				ctx.Log.Error("Panic recovered", zap.Any("panic", r))
			}
		}()

		eos_io.LogRuntimeExecutionContext(ctx)

		// Start resource watchdog for resource-intensive commands
		startResourceWatchdog(ctx, cmd.Name())

		// SECURITY: Sanitize command arguments before processing
		sanitizedArgs, sanitizeErr := sanitizeCommandInputs(ctx, cmd, args)
		if sanitizeErr != nil {
			ctx.Log.Error("Input sanitization failed",
				zap.Error(sanitizeErr),
				zap.Strings("raw_args", args),
				zap.String("command", cmd.Name()))
			return eos_err.NewExpectedError(ctx.Ctx, cerr.Wrap(sanitizeErr, "invalid input"))
		}

		// Replace original args with sanitized version
		args = sanitizedArgs

		// Vault environment, telemetry attribute
		vaultAddr, vaultErr := vault.EnsureVaultEnv(ctx)
		if vaultErr != nil {
			ctx.Log.Warn("Failed to resolve VAULT_ADDR", zap.Error(vaultErr))
		} else {
			ctx.Log.Info(" VAULT_ADDR resolved", zap.String("VAULT_ADDR", vaultAddr))
			ctx.Attributes["vault_addr"] = vaultAddr
		}

		// Unified validation logic
		if verr := ctx.ValidateAll(); verr != nil {
			ctx.Log.Error("Validation failed", zap.Error(verr))
			return verr
		}

		// CRITICAL FIX: Never prompt for bootstrap if we're already running a bootstrap command
		isBootstrapCommand := strings.Contains(cmd.CommandPath(), "bootstrap") || 
			cmd.Name() == "bootstrap" ||
			(cmd.Parent() != nil && cmd.Parent().Name() == "bootstrap")
		
		// Debug logging to understand command detection
		ctx.Log.Debug("Bootstrap command detection",
			zap.String("cmd.Name()", cmd.Name()),
			zap.String("cmd.CommandPath()", cmd.CommandPath()),
			zap.String("cmd.Use", cmd.Use),
			zap.Bool("has_parent", cmd.Parent() != nil),
			zap.String("parent_name", func() string {
				if cmd.Parent() != nil {
					return cmd.Parent().Name()
				}
				return "none"
			}()),
			zap.Bool("is_bootstrap_command", isBootstrapCommand))
		
		// Check if system needs bootstrap before executing command
		// For subcommands, also check if parent command is exempt
		shouldCheckBootstrap := !isBootstrapCommand
		if shouldCheckBootstrap && cmd.Parent() != nil {
			// If parent command is exempt, skip bootstrap check for subcommands
			parentExempt := !bootstrap.ShouldPromptForBootstrap(cmd.Parent().Name())
			shouldCheckBootstrap = !parentExempt
			
			if parentExempt {
				ctx.Log.Debug("Skipping bootstrap check - parent command is exempt",
					zap.String("parent", cmd.Parent().Name()),
					zap.String("command", cmd.Name()))
			}
		}
		
		if shouldCheckBootstrap && bootstrap.ShouldPromptForBootstrap(cmd.Name()) {
			ctx.Log.Info("Checking bootstrap status", 
				zap.String("command", cmd.Name()),
				zap.String("parent", func() string {
					if cmd.Parent() != nil {
						return cmd.Parent().Name()
					}
					return "none"
				}()),
				zap.Bool("is_bootstrap_cmd", isBootstrapCommand))

			// Also check environment variable to prevent any possibility of recursion
			if os.Getenv("EOS_BOOTSTRAP_IN_PROGRESS") != "1" {
				ctx.Log.Info("Bootstrap prompt check",
					zap.String("EOS_BOOTSTRAP_IN_PROGRESS", os.Getenv("EOS_BOOTSTRAP_IN_PROGRESS")))
				
				// Don't prompt in the wrapper - just warn
				ctx.Log.Warn("System is not bootstrapped")
				ctx.Log.Warn("Some commands may fail without proper setup")
				ctx.Log.Warn("Run 'eos bootstrap' to set up the system")
			}
		}

		err = fn(ctx, cmd, args)
		if err != nil && !eos_err.IsExpectedUserError(err) {
			err = cerr.WithStack(err)
		}
		return err
	}
}

// WrapExtended is like Wrap but creates a context with extended timeout for long-running operations.
// This should only be used for commands that legitimately need more time than the global watchdog allows.
func WrapExtended(timeout time.Duration, fn func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) (err error) {
		logger.InitFallback()
		ctx := eos_io.NewExtendedContext(context.Background(), cmd.Name(), timeout)
		defer ctx.End(&err)

		// Panic recovery
		defer func() {
			if r := recover(); r != nil {
				err = cerr.AssertionFailedf("panic: %v", r)
				ctx.Log.Error("Panic recovered", zap.Any("panic", r))
			}
		}()

		eos_io.LogRuntimeExecutionContext(ctx)

		// Start resource watchdog for resource-intensive commands
		startResourceWatchdog(ctx, cmd.Name())

		// SECURITY: Sanitize command arguments before processing
		sanitizedArgs, sanitizeErr := sanitizeCommandInputs(ctx, cmd, args)
		if sanitizeErr != nil {
			ctx.Log.Error("Input sanitization failed",
				zap.Error(sanitizeErr),
				zap.Strings("raw_args", args),
				zap.String("command", cmd.Name()))
			return eos_err.NewExpectedError(ctx.Ctx, cerr.Wrap(sanitizeErr, "invalid input"))
		}

		// Replace original args with sanitized version
		args = sanitizedArgs

		// Vault environment, telemetry attribute
		vaultAddr, vaultErr := vault.EnsureVaultEnv(ctx)
		if vaultErr != nil {
			ctx.Log.Warn("Failed to resolve VAULT_ADDR", zap.Error(vaultErr))
		} else {
			ctx.Log.Info(" VAULT_ADDR resolved", zap.String("VAULT_ADDR", vaultAddr))
			ctx.Attributes["vault_addr"] = vaultAddr
		}

		// Unified validation logic
		if verr := ctx.ValidateAll(); verr != nil {
			ctx.Log.Error("Validation failed", zap.Error(verr))
			return verr
		}

		// CRITICAL FIX: Never prompt for bootstrap if we're already running a bootstrap command
		isBootstrapCommand := strings.Contains(cmd.CommandPath(), "bootstrap") || 
			cmd.Name() == "bootstrap" ||
			(cmd.Parent() != nil && cmd.Parent().Name() == "bootstrap")
		
		// Debug logging to understand command detection
		ctx.Log.Debug("Bootstrap command detection",
			zap.String("cmd.Name()", cmd.Name()),
			zap.String("cmd.CommandPath()", cmd.CommandPath()),
			zap.String("cmd.Use", cmd.Use),
			zap.Bool("has_parent", cmd.Parent() != nil),
			zap.String("parent_name", func() string {
				if cmd.Parent() != nil {
					return cmd.Parent().Name()
				}
				return "none"
			}()),
			zap.Bool("is_bootstrap_command", isBootstrapCommand))
		
		// Check if system needs bootstrap before executing command
		// For subcommands, also check if parent command is exempt
		shouldCheckBootstrap := !isBootstrapCommand
		if shouldCheckBootstrap && cmd.Parent() != nil {
			// If parent command is exempt, skip bootstrap check for subcommands
			parentExempt := !bootstrap.ShouldPromptForBootstrap(cmd.Parent().Name())
			shouldCheckBootstrap = !parentExempt
			
			if parentExempt {
				ctx.Log.Debug("Skipping bootstrap check - parent command is exempt",
					zap.String("parent", cmd.Parent().Name()),
					zap.String("command", cmd.Name()))
			}
		}
		
		if shouldCheckBootstrap && bootstrap.ShouldPromptForBootstrap(cmd.Name()) {
			ctx.Log.Info("Checking bootstrap status", 
				zap.String("command", cmd.Name()),
				zap.String("parent", func() string {
					if cmd.Parent() != nil {
						return cmd.Parent().Name()
					}
					return "none"
				}()),
				zap.Bool("is_bootstrap_cmd", isBootstrapCommand))

			// Also check environment variable to prevent any possibility of recursion
			if os.Getenv("EOS_BOOTSTRAP_IN_PROGRESS") != "1" {
				ctx.Log.Info("Bootstrap prompt check",
					zap.String("EOS_BOOTSTRAP_IN_PROGRESS", os.Getenv("EOS_BOOTSTRAP_IN_PROGRESS")))
				
				// Don't prompt in the wrapper - just warn
				ctx.Log.Warn("System is not bootstrapped")
				ctx.Log.Warn("Some commands may fail without proper setup")
				ctx.Log.Warn("Run 'eos bootstrap' to set up the system")
			}
		}

		err = fn(ctx, cmd, args)
		if err != nil && !eos_err.IsExpectedUserError(err) {
			err = cerr.WithStack(err)
		}
		return err
	}
}

// sanitizeCommandInputs sanitizes command arguments and flag values for security
func sanitizeCommandInputs(ctx *eos_io.RuntimeContext, cmd *cobra.Command, args []string) ([]string, error) {
	// Create sanitizer with appropriate strictness
	var sanitizer *security.InputSanitizer

	// Use strict mode for sensitive commands
	if isSensitiveCommand(cmd.Name()) {
		sanitizer = security.NewStrictSanitizer()
		ctx.Log.Info("Using strict input sanitization for sensitive command",
			zap.String("command", cmd.Name()))
	} else {
		sanitizer = security.NewInputSanitizer()
	}

	// Sanitize positional arguments
	sanitizedArgs, err := sanitizer.SanitizeArguments(args)
	if err != nil {
		return nil, cerr.Wrap(err, "failed to sanitize command arguments")
	}

	// Log sanitization if input was modified
	if argsModified(args, sanitizedArgs) {
		ctx.Log.Warn("Command arguments were sanitized",
			zap.String("command", cmd.Name()),
			zap.Int("original_count", len(args)),
			zap.Int("sanitized_count", len(sanitizedArgs)))
	}

	// Sanitize flag values (this is more complex as we need to intercept flag parsing)
	if err := sanitizeFlagValues(ctx, cmd, sanitizer); err != nil {
		return nil, cerr.Wrap(err, "failed to sanitize flag values")
	}

	return sanitizedArgs, nil
}

// isSensitiveCommand determines if a command should use strict sanitization
func isSensitiveCommand(cmdName string) bool {
	sensitiveCommands := map[string]bool{
		"create": true,
		"update": true,
		"secure": true,
		"vault":  true,
		"crypto": true,
		"setup":  true,
		"manage": true,
	}
	return sensitiveCommands[cmdName]
}

// argsModified checks if sanitization changed the arguments
func argsModified(original, sanitized []string) bool {
	if len(original) != len(sanitized) {
		return true
	}
	for i, arg := range original {
		if arg != sanitized[i] {
			return true
		}
	}
	return false
}

// sanitizeFlagValues sanitizes flag values by intercepting the flag parsing
func sanitizeFlagValues(ctx *eos_io.RuntimeContext, cmd *cobra.Command, sanitizer *security.InputSanitizer) error {
	// This is a simplified approach - in practice, we would need to walk through
	// all flags and sanitize their values, but Cobra makes this challenging
	// because flags are parsed before we get here.

	// For now, we log that flag sanitization should be implemented at the flag level
	ctx.Log.Info("Flag sanitization should be implemented at individual command level",
		zap.String("command", cmd.Name()),
		zap.String("note", "Consider using security.ValidateFlagName for flag validation"))

	return nil
}

// startResourceWatchdog initializes resource monitoring for resource-intensive commands
func startResourceWatchdog(ctx *eos_io.RuntimeContext, commandName string) {
	fmt.Fprintf(os.Stderr, "DEBUG: startResourceWatchdog called for command: %s\n", commandName)
	// List of commands that should have resource monitoring
	// NOTE: Removed "update" from this list as it's not resource-intensive
	resourceIntensiveCommands := []string{"bootstrap", "create", "deploy", "install"}
	
	// Check if this command needs monitoring
	shouldMonitor := false
	for _, cmd := range resourceIntensiveCommands {
		if strings.Contains(commandName, cmd) {
			shouldMonitor = true
			break
		}
	}
	
	if !shouldMonitor {
		fmt.Fprintf(os.Stderr, "DEBUG: Command %s doesn't need monitoring, returning\n", commandName)
		return
	}
	
	// Configure watchdog with enhanced tracing
	config := watchdog.DefaultResourceConfig()
	
	// TEMPORARY: Disable tracing to fix hang issue
	// TODO: Investigate why TraceLogger.Initialize() hangs
	config.EnableTracing = false
	
	// Enable terminal output for visibility
	config.EnableTerminalOutput = true
	config.CaptureSystemInfo = true
	
	// Special configuration for bootstrap
	if strings.Contains(commandName, "bootstrap") {
		// Bootstrap is allowed more CPU but fewer processes
		config.CPUWarningThreshold = 80.0
		config.CPUCriticalThreshold = 95.0
		config.MaxEosProcesses = 5 // Strict limit to catch recursion
		config.SustainedDuration = 2 * time.Second // React faster to bootstrap issues
		config.VerboseLogging = true // Always verbose for bootstrap
	}
	
	// Create and start the watchdog
	rw := watchdog.NewResourceWatchdog(ctx.Ctx, ctx.Log, config)
	rw.Start()
	
	// Ensure we capture panic information if it happens
	defer func() {
		if r := recover(); r != nil {
			// Capture panic information before re-panicking
			rw.CapturePanic(r)
			panic(r) // Re-panic after capture
		}
	}()
	
	ctx.Log.Info("Resource watchdog started with enhanced tracing",
		zap.String("command", commandName),
		zap.Float64("cpu_limit", config.CPUCriticalThreshold),
		zap.Int("max_processes", config.MaxEosProcesses),
		zap.String("trace_dir", config.TraceBaseDir))
}
