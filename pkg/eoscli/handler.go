/* pkg/eoscli/handler.go */

package eoscli

import (
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// Wrap decorates a cobra command handler to inject EOS runtime context (logger, start time),
// resolves Vault environment configuration, and automatically logs command start/end lifecycle events.
func Wrap(fn func(ctx *RuntimeContext, cmd *cobra.Command, args []string) error) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		var err error

		start := time.Now()
		log := contextualLogger()
		log.Info("🚀 EOS command execution started", zap.Time("start_time", start), zap.String("command", cmd.Name()))

		ctx := &RuntimeContext{
			Log:       log,
			StartTime: start,
		}

		addr, addrErr := vault.EnsureVaultEnv(log)
		if addrErr != nil {
			log.Warn("⚠️ Failed to resolve VAULT_ADDR", zap.Error(addrErr))
		}
		log.Info("🔐 VAULT_ADDR resolved", zap.String("VAULT_ADDR", addr))

		defer logger.LogCommandLifecycle(cmd.Name())(&err)

		err = fn(ctx, cmd, args)

		if err != nil {
			log.Error("⚠️ EOS command failed", zap.Duration("duration", time.Since(start)), zap.String("command", cmd.Name()))
			return err
		}
		log.Info("✅ EOS command finished successfully", zap.Duration("duration", time.Since(start)), zap.String("command", cmd.Name()))
		return nil
	}
}
