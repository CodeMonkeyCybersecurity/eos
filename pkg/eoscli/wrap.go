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

func Wrap(fn func(ctx *eosio.RuntimeContext, cmd *cobra.Command, args []string) error) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) (errExec error) {
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

		if ok, checkErr := eosio.CanSudoToEos(); checkErr != nil || !ok {
			log.Warn("⚠️ sudo dry-run check for 'eos' user failed",
				zap.Error(checkErr),
				zap.Bool("can_sudo", ok),
				zap.String("hint", "verify 'eos ALL=(ALL) NOPASSWD: ALL' or at least 'sudo -u eos true' works"))
		}

		if err := eosio.RequireEosUserOrReexecWithShell(log, cmd.Annotations[RequiresShellAnnotation] == "true"); err != nil {
			if err == eosio.ErrAlreadyEos {
				log.Info("👤 Already running as 'eos'; continuing without escalation")
			} else if err == eosio.ErrEosReexecCompleted {
				return nil // stop upstream; process already exited
			} else {
				log.Error("❌ Privilege check failed; see earlier sudo error logs", zap.Error(err))
				return fmt.Errorf("privilege check failed: %w", err)
			}
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

		defer func() {
			if r := recover(); r != nil {
				log.Error("❌ Command panicked", zap.Any("recover", r))
				errExec = fmt.Errorf("command panicked: %v", r)
			}
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
