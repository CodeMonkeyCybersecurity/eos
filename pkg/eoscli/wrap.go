package eoscli

import (
	"context"
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eoserr"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eosio"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

const RequiresShellAnnotation = "requires_shell"

// Wrap wraps a Cobra command handler with EOS runtime setup.
func Wrap(fn func(ctx *eosio.RuntimeContext, cmd *cobra.Command, args []string) error) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		requiresShell := cmd.Annotations[RequiresShellAnnotation] == "true"

		logger.InitializeWithFallback()
		baseLog := logger.L()
		if baseLog == nil {
			return fmt.Errorf("logger initialization failed before RequireEosUserOrReexec")
		}

		invokedBy, err := eosio.GetInvokedUsername()
		if err != nil {
			baseLog.Warn("Failed to detect invoking user", zap.Error(err))
			invokedBy = "unknown"
		}
		log := baseLog.With(zap.String("invoked_by", invokedBy))
		logger.SetLogger(log)

		if err := eosio.RequireEosUserOrReexecWithShell(log, requiresShell); err != nil {
			log.Error("❌ Privilege check failed", zap.Error(err))
			return fmt.Errorf("privilege check failed: %w", err)
		}

		const timeout = 1 * time.Minute
		start := time.Now()
		ctxWithTimeout, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		ctx := &eosio.RuntimeContext{Log: log, Ctx: ctxWithTimeout, Timestamp: start}
		log.Info("🚀 Command execution started", zap.String("command", cmd.Name()), zap.Time("timestamp", start), zap.Duration("timeout", timeout))

		addr, addrErr := vault.EnsureVaultEnv(log)
		if addrErr != nil {
			log.Warn("⚠️ Failed to resolve VAULT_ADDR", zap.Error(addrErr))
		}
		log.Info("🔐 VAULT_ADDR resolved", zap.String("VAULT_ADDR", addr))

		var errExec error
		defer func() {
			duration := time.Since(start)
			logger.LogCommandLifecycle(cmd.Name())(&errExec)
			if errExec != nil {
				if eoserr.IsExpectedUserError(errExec) {
					log.Warn("⚠️ EOS user error", zap.Error(errExec), zap.Duration("duration", duration))
				} else {
					log.Error("❌ EOS command failed", zap.Error(errExec), zap.Duration("duration", duration))
				}
			} else {
				log.Info("✅ EOS command finished successfully", zap.Duration("duration", duration))
			}
		}()

		errExec = fn(ctx, cmd, args)
		return errExec
	}
}