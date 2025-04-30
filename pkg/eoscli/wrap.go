// pkg/eoscli/wrap.go

package eoscli

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eoserr"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eosio"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

func Wrap(fn func(ctx *eosio.RuntimeContext, cmd *cobra.Command, args []string) error) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		// Global logger init — safe, idempotent
		logger.InitializeWithFallback()
		log := logger.GetLogger().Named(cmd.Name())

		// Privilege check and re-exec
		if err := eosio.RequireEosUserOrReexec(log); err != nil {
			log.Error("❌ Privilege check failed", zap.Error(err))
			return fmt.Errorf("privilege check failed: %w", err)
		}

		// Refine logger context
		log = eosio.ContextualLogger(2, nil).Named(cmd.Name())
		logger.SetLogger(log)
		logRuntimeExecutionContext(log)

		// Add calling user info
		if u, err := user.LookupId(fmt.Sprint(os.Getuid())); err == nil {
			log = log.With(zap.String("invoked_by", u.Username))
		}

		// Context setup
		const timeout = 1 * time.Minute
		start := time.Now()
		ctxWithTimeout, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		ctx := &eosio.RuntimeContext{
			Log:       log,
			Ctx:       ctxWithTimeout,
			Timestamp: time.Now(),
		}

		log.Info("🚀 Command execution started",
			zap.Time("timestamp", ctx.Timestamp),
			zap.Duration("timeout", timeout),
		)

		// Vault setup
		addr, addrErr := vault.EnsureVaultEnv(log)
		if addrErr != nil {
			log.Warn("⚠️ Failed to resolve VAULT_ADDR", zap.Error(addrErr))
		}
		log.Info("🔐 VAULT_ADDR resolved", zap.String("VAULT_ADDR", addr))

		var err error
		defer func() {
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

			shared.SafeSync(log)
		}()

		err = fn(ctx, cmd, args)
		return err
	}
}
