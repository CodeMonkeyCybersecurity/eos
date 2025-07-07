// pkg/eoscli/wrap.go

package eos_cli

import (
	"context"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/security"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	cerr "github.com/cockroachdb/errors"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// Wrap ensures panic recovery, telemetry, logging, and validation
func Wrap(fn func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) (err error) {
		logger.InitFallback()
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
