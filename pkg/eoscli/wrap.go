// pkg/eoscli/wrap.go

package eoscli

import (
	"context"
	"fmt"
	"runtime"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eoserr"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eosio"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/telemetry"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

func Wrap(fn func(ctx *eosio.RuntimeContext, cmd *cobra.Command, args []string) error) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		logger.InitFallback()

		cmd.SilenceUsage = true
		if cmd.Root() != nil {
			cmd.Root().SilenceUsage = true
		}

		log := eosio.ContextualLogger(2, nil).Named(cmd.Name())
		eosio.LogRuntimeExecutionContext()

		// If no logic provided and command is a namespace, show local help
		if fn == nil {
			if len(args) == 0 && cmd.HasSubCommands() {
				return cmd.Usage()
			}
			return nil
		}

		start := time.Now()
		ctx := &eosio.RuntimeContext{
			Log:       log,
			Ctx:       context.Background(),
			Timestamp: start,
		}

		vaultAddr, vaultErr := vault.EnsureVaultEnv()
		if vaultErr != nil {
			log.Warn("⚠️ Failed to resolve VAULT_ADDR", zap.Error(vaultErr))
		} else {
			log.Info("🔐 VAULT_ADDR resolved", zap.String("VAULT_ADDR", vaultAddr))
		}

		var err error
		defer func() {
			if r := recover(); r != nil {
				log.Error("💥 Panic recovered", zap.Any("panic", r))
				err = fmt.Errorf("panic: %v", r)
			}

			duration := time.Since(start)
			logger.LogCommandLifecycle(cmd.Name())(&err)

			telemetry.TrackCommand(
				ctx.Ctx,
				cmd.Use,
				err == nil,
				duration.Milliseconds(),
				map[string]string{
					"os":         runtime.GOOS,
					"arch":       runtime.GOARCH,
					"args":       telemetry.TruncateOrHashArgs(args),
					"vault_addr": vaultAddrOrUnavailable(vaultAddr, vaultErr),
					"version":    shared.Version,
					"category":   telemetry.CommandCategory(cmd.Use),
					"error_type": telemetry.ClassifyError(err),
				},
			)

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
		return fn(ctx, cmd, args)
	}
}

// vaultAddrOrUnavailable safely reports VAULT_ADDR or a placeholder
func vaultAddrOrUnavailable(addr string, err error) string {
	if err != nil || addr == "" {
		return "(unavailable)"
	}
	return addr
}
