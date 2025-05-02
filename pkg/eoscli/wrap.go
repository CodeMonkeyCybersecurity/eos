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

// Wrap decorates a cobra command with EOS runtime context, logger, and error handling.
func Wrap(fn func(ctx *eosio.RuntimeContext, cmd *cobra.Command, args []string) error) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		// Try privilege elevation — do NOT log here yet
		if err := eosio.RequireEosUserOrReexec(nil); err != nil {
			return fmt.Errorf("privilege check failed: %w", err)
		}

		// Now initialize logger AFTER escalation
		if err := logger.InitializeWithFallback(nil); err != nil {
			fmt.Fprintf(os.Stderr, "⚠ logger fallback: %v\n", err)
		}

		baseLog := logger.L()
		if baseLog == nil {
			fallback := logger.NewFallbackLogger()
			fallback.Error("logger.L() is nil after escalation")
			os.Exit(1)
		}
		logger.SetLogger(baseLog)

		userField := zap.Skip()
		if u, err := user.LookupId(fmt.Sprint(os.Getuid())); err == nil {
			userField = zap.String("invoked_by", u.Username)
		}
		log := baseLog.With(userField)
		logger.SetLogger(log)

		const timeout = 1 * time.Minute
		start := time.Now()
		ctxWithTimeout, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		ctx := &eosio.RuntimeContext{Log: log, Ctx: ctxWithTimeout, Timestamp: start}
		log.Info("🚀 Command execution started", zap.Time("timestamp", start), zap.Duration("timeout", timeout))

		addr, addrErr := vault.EnsureVaultEnv(log)
		if addrErr != nil {
			log.Warn("⚠️ Failed to resolve VAULT_ADDR", zap.Error(addrErr))
		}
		log.Info("🔐 VAULT_ADDR resolved", zap.String(shared.VaultAddrEnv, addr))

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
