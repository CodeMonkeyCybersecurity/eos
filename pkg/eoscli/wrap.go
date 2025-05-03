// pkg/eoscli/wrap.go

package eoscli

import (
	"context"
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eoserr"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eosio"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// Wrap decorates a cobra command handler to inject EOS runtime context.
func Wrap(fn func(ctx *eosio.RuntimeContext, cmd *cobra.Command, args []string) error) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		logger.InitFallback() // <- ensure fallback logging

		log := eosio.ContextualLogger(2, nil).Named(cmd.Name())
		eosio.LogRuntimeExecutionContext()

		if err := eosio.RequireEosUserOrReexec(); err != nil {
			zap.L().Error("❌ Privilege check failed", zap.Error(err))
			return fmt.Errorf("privilege check failed: %w", err)
		}

		const timeout = 1 * time.Minute
		start := time.Now()

		ctxWithTimeout, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		ctx := &eosio.RuntimeContext{
			Log:       log,
			Ctx:       ctxWithTimeout,
			Timestamp: time.Now(),
		}

		zap.L().Info("🚀 Command execution started", zap.Time("timestamp", ctx.Timestamp), zap.Duration("timeout", timeout))

		addr, addrErr := vault.EnsureVaultEnv()
		if addrErr != nil {
			zap.L().Warn("⚠️ Failed to resolve VAULT_ADDR", zap.Error(addrErr))
		}
		zap.L().Info("🔐 VAULT_ADDR resolved", zap.String("VAULT_ADDR", addr))

		var err error
		defer func() {
			duration := time.Since(start)
			logger.LogCommandLifecycle(cmd.Name())(&err)

			if err != nil {
				if eoserr.IsExpectedUserError(err) {
					zap.L().Warn("⚠️ EOS user error", zap.Error(err), zap.Duration("duration", duration))
				} else {
					zap.L().Error("❌ EOS command failed", zap.Error(err), zap.Duration("duration", duration))
				}
			} else {
				zap.L().Info("✅ EOS command finished successfully", zap.Duration("duration", duration))
			}

			shared.SafeSync()
		}()

		zap.L().Debug("Entering wrapped command function")
		err = fn(ctx, cmd, args)
		return err
	}
}
