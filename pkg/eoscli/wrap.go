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

// Wrap wraps a Cobra command handler, injecting EOS runtime context,
// structured logging, privilege checks, Vault env setup, and error handling.
func Wrap(fn func(ctx *eosio.RuntimeContext, cmd *cobra.Command, args []string) error) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		logger.InitFallback()

		log := eosio.ContextualLogger(2, nil).Named(cmd.Name())
		eosio.LogRuntimeExecutionContext()

		start := time.Now()

		ctx := &eosio.RuntimeContext{
			Log:       log,
			Ctx:       context.Background(), // no internal timeout now
			Timestamp: start,
		}

		log.Info("🚀 Command execution started", zap.Time("timestamp", ctx.Timestamp))

		addr, addrErr := vault.EnsureVaultEnv()
		if addrErr != nil {
			log.Warn("⚠️ Failed to resolve VAULT_ADDR", zap.Error(addrErr))
		}
		log.Info("🔐 VAULT_ADDR resolved", zap.String("VAULT_ADDR", addr))

		var err error
		defer func() {
			if r := recover(); r != nil {
				log.Error("💥 Panic recovered", zap.Any("panic", r))
				err = fmt.Errorf("panic: %v", r)
			}

			duration := time.Since(start)
			logger.LogCommandLifecycle(cmd.Name())(&err)

			if err != nil {
				if eoserr.IsExpectedUserError(err) {
					log.Warn("⚠️ EOS user error", zap.Error(err), zap.Duration("duration", duration))
				} else {
					log.Error("❌ EOS command failed", zap.Error(err), zap.Duration("duration", duration))
				}
			} else {
				log.Info("✅ EOS command finished successfully", zap.Duration("duration", duration))
			}

			shared.SafeSync()
		}()

		log.Debug("Entering wrapped command function")
		err = fn(ctx, cmd, args)
		return err
	}
}
