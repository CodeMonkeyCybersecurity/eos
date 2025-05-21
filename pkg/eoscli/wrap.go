// pkg/eoscli/wrap.go

package eoscli

import (
	"context"
	"runtime"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eoserr"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eosio"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/telemetry"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	cerr "github.com/cockroachdb/errors"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var errStackedMarker = cerr.New("stack already attached")

func Wrap(fn func(ctx *eosio.RuntimeContext, cmd *cobra.Command, args []string) error) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		logger.InitFallback()

		cmd.SilenceUsage = true
		if cmd.Root() != nil {
			cmd.Root().SilenceUsage = true
		}

		log := eosio.ContextualLogger(2, nil).Named(cmd.Name())
		eosio.LogRuntimeExecutionContext()

		// Fallback to usage if no function defined
		if fn == nil && cmd.HasSubCommands() && len(args) == 0 {
			return cmd.Usage()
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
				err = cerr.AssertionFailedf("panic recovered: %v", r)
				log.Error("💥 Panic recovered", zap.Any("panic", r))
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
					log.Error("❌ EOS command failed", zap.String("error", err.Error()), zap.Duration("duration", duration))
					if cause := cerr.UnwrapAll(err); cause != nil {
						log.Debug("🔍 Root cause", zap.String("cause", cause.Error()))
					}
				}
			} else {
				log.Info("✅ EOS command finished successfully", zap.Duration("duration", duration))
			}

			shared.SafeSync()
		}()

		log.Debug("Entering wrapped command function")
		err = fn(ctx, cmd, args)

		if err != nil && !eoserr.IsExpectedUserError(err) && !cerr.Is(err, errStackedMarker) {
			err = cerr.Mark(cerr.WithStack(err), errStackedMarker)
		}

		return err
	}
}

func vaultAddrOrUnavailable(addr string, err error) string {
	if err != nil || addr == "" {
		return "(unavailable)"
	}
	return addr
}
