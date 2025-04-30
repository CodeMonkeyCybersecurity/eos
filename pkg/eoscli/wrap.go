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
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

func Wrap(fn func(ctx *eosio.RuntimeContext, cmd *cobra.Command, args []string) error) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		if err := eosio.RequireEosUserOrReexec(nil); err != nil {
			logger.NewFallbackLogger().Error("❌ Privilege check failed", zap.Error(err))
			return fmt.Errorf("privilege check failed: %w", err)
		}

		userField := zap.Skip()
		if u, err := user.LookupId(fmt.Sprint(os.Getuid())); err == nil {
			userField = zap.String("invoked_by", u.Username)
		}

		log := logger.L().With(userField)
		logger.SetLogger(log)

		// Timeout + context
		const timeout = 1 * time.Minute
		start := time.Now()
		ctxWithTimeout, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		ctx := &eosio.RuntimeContext{Log: log, Ctx: ctxWithTimeout, Timestamp: time.Now()}
		log.Info("🚀 Command execution started", zap.Time("timestamp", ctx.Timestamp), zap.Duration("timeout", timeout))

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
		}()

		err = fn(ctx, cmd, args)
		return err
	}
}
