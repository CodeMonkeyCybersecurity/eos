// pkg/eoscli/wrap.go

package eos_cli

import (
	"context"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	cerr "github.com/cockroachdb/errors"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// Wrap ensures panic recovery, telemetry, logging, and validation
func Wrap(fn func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) (err error) {
		logger.InitFallback()
		ctx := eos_io.NewContext(context.Background(), cmd.Name())
		defer ctx.End(&err)

		// Panic recovery
		defer func() {
			if r := recover(); r != nil {
				err = cerr.AssertionFailedf("panic: %v", r)
				ctx.Log.Error("Panic recovered", zap.Any("panic", r))
			}
		}()

		eos_io.LogRuntimeExecutionContext(ctx)

		// Vault environment, telemetry attribute
		vaultAddr, vaultErr := vault.EnsureVaultEnv(ctx)
		if vaultErr != nil {
			ctx.Log.Warn("⚠️ Failed to resolve VAULT_ADDR", zap.Error(vaultErr))
		} else {
			ctx.Log.Info("🔐 VAULT_ADDR resolved", zap.String("VAULT_ADDR", vaultAddr))
			ctx.Attributes["vault_addr"] = vaultAddr
		}

		// Unified validation logic
		if verr := ctx.ValidateAll(); verr != nil {
			ctx.Log.Error("Validation failed", zap.Error(verr))
			return verr
		}

		err = fn(ctx, cmd, args)
		if err != nil && !eos_err.IsExpectedUserError(err) {
			err = cerr.WithStack(err)
		}
		return err
	}
}
