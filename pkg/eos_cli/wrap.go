// pkg/eoscli/wrap.go

package eos_cli

import (
	"context"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/verify"
	cerr "github.com/cockroachdb/errors"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

func Wrap(fn func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		logger.InitFallback()

		cmd.SilenceUsage = true
		if cmd.Root() != nil {
			cmd.Root().SilenceUsage = true
		}

		start := time.Now()
		ctx := &eos_io.RuntimeContext{
			Ctx:       context.Background(),
			Timestamp: start,
		}

		log := eos_io.ContextualLogger(ctx, 2, nil).Named(cmd.Name())
		ctx.Log = log

		eos_io.LogRuntimeExecutionContext(ctx)

		vaultAddr, vaultErr := vault.EnsureVaultEnv(ctx)
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
			if err != nil {
				log.Error("Command failed", zap.Duration("duration", duration), zap.Error(err))
			} else {
				log.Info("Command completed", zap.Duration("duration", duration))
			}

			if err != nil {
				if eos_err.IsExpectedUserError(err) {
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

		// --- Inject validation logic if enabled via context ---
		if ctx.Validate != nil {
			v := ctx.Validate
			log.Info("🔍 Validating command input")
			if err := verify.Struct(v.Cfg); err != nil {
				log.Error("🚫 Struct validation failed", zap.Error(err))
				return cerr.WithHint(err, "Fix struct-level configuration")
			}
			if err := verify.ValidateYAMLWithCUE(v.SchemaPath, v.YAMLPath); err != nil {
				log.Error("📄 CUE validation failed", zap.String("schema", v.SchemaPath), zap.Error(err))
				return cerr.WithHint(err, "Fix YAML or schema mismatch")
			}
			denies, err := verify.EnforcePolicy(ctx.Ctx, v.PolicyPath, v.PolicyInput())
			if err != nil {
				log.Error("🔒 Policy enforcement failed", zap.Error(err))
				return cerr.Wrap(err, "Policy enforcement failed")
			}
			if len(denies) > 0 {
				for _, d := range denies {
					log.Warn("🚫 Policy violation", zap.String("reason", d))
				}
				return cerr.Newf("Policy denied: %v", denies)
			}
		}

		log.Debug("Entering wrapped command function")
		err = fn(ctx, cmd, args)

		if err != nil && !eos_err.IsExpectedUserError(err) && !cerr.Is(err, errStackedMarker) {
			err = cerr.Mark(cerr.WithStack(err), errStackedMarker)
		}

		return err
	}
}
