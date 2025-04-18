/* pkg/eoscli/handler.go */

package eoscli

import (
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var vaultCheck sync.Once

/* Wrap adds automatic logger injection and scoped metadata based on calling package. */
func Wrap(fn func(cmd *cobra.Command, args []string) error) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		start := time.Now()
		log := contextualLogger()
		log.Info("🚀 EOS command execution started", zap.Time("start_time", start), zap.String("command", cmd.Name()))

		var err error
		defer logger.LogCommandLifecycle(cmd.Name())(&err)

		log.Debug("🔁 Entering vaultCheck.Do() block...")
		vaultCheck.Do(func() {
			log.Debug("🔒 [vaultCheck] Triggered — initializing Vault client and checking readiness")

			vault.EnsureVaultClient(log)

			log.Info("🔍 [vaultCheck] Checking Vault sealed state...")
			if _, vaultErr := vault.EnsureVaultReady(log); vaultErr != nil {
				log.Warn("⚠️ Vault is not fully prepared...", zap.Error(vaultErr))
				log.Warn("Continuing anyway — downstream commands may fail if Vault is required.")
			} else {
				log.Info("✅ Vault is initialized and unsealed")
			}
		})
		log.Debug("🔁 Finished vaultCheck.Do() block")

		err = fn(cmd, args)
		log.Info("✅ EOS command finished", zap.Duration("duration", time.Since(start)), zap.String("command", cmd.Name()))
		return err
	}
}
