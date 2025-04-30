package eoscli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
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

// Wrap decorates a cobra command handler to inject EOS runtime context.
func Wrap(fn func(ctx *eosio.RuntimeContext, cmd *cobra.Command, args []string) error) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {

		// Re-exec as 'eos' user if not already
		currentUser, err := user.Current()
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Failed to detect current user: %v\n", err)
			os.Exit(1)
		}
		if currentUser.Username != "eos" {
			fmt.Fprintf(os.Stderr, "🔐 Elevating to 'eos' user via sudo...\n")
			argsFull := append([]string{"-u", "eos", os.Args[0]}, os.Args[1:]...)
			err := exec.Command("sudo", argsFull...).Run()
			if err != nil {
				fmt.Fprintf(os.Stderr, "❌ sudo failed: %v\n", err)
				os.Exit(1)
			}
			os.Exit(0) // Prevent duplicate execution after sudo
		}

		const timeout = 1 * time.Minute // ⏰ Add default timeout here
		start := time.Now()

		log := eosio.ContextualLogger(2, nil).Named(cmd.Name())

		ctxWithTimeout, cancel := context.WithTimeout(context.Background(), timeout) // ⏰ Set timeout context
		defer cancel()

		ctx := &eosio.RuntimeContext{ // ⏰ Manual RuntimeContext to inject timeout
			Log:       log,
			Ctx:       ctxWithTimeout,
			Timestamp: time.Now(),
		}

		log.Info("🚀 Command execution started",
			zap.Time("timestamp", ctx.Timestamp),
			zap.Duration("timeout", timeout), // Optional but good for logging
		)

		// Setup Vault environment, but log warning if it fails
		addr, addrErr := vault.EnsureVaultEnv(log)
		if addrErr != nil {
			log.Warn("⚠️ Failed to resolve VAULT_ADDR", zap.Error(addrErr))
		}
		log.Info("🔐 VAULT_ADDR resolved", zap.String("VAULT_ADDR", addr))

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
