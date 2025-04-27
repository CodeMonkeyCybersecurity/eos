package eoscli

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eoserr"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// PreRunWrapper injects RuntimeContext and wraps RunE with standard lifecycle.
func PreRunWrapper(cmd *cobra.Command, args []string) error {
	ctx := &RuntimeContext{
		Log: GlobalLogger.Named(cmd.Name()), // Child logger scoped to command
		Env: map[string]string{
			"VAULT_ADDR": os.Getenv("VAULT_ADDR"),
		},
		StartTime: time.Now(),
	}

	// Attach context
	newCtx := context.WithValue(cmd.Context(), runtimeContextKey, ctx)
	cmd.SetContext(newCtx)

	// Only wrap if a RunE is defined
	if cmd.RunE != nil {
		originalRunE := cmd.RunE

		cmd.RunE = func(cmd *cobra.Command, args []string) error {
			ctx := GetRuntimeContext(cmd)

			ctx.Log.Info("🚀 Command execution started",
				zap.String("command", cmd.Name()),
				zap.Strings("args", args),
				zap.Time("start_time", ctx.StartTime),
			)

			defer func() {
				if r := recover(); r != nil {
					ctx.Log.Error("🔥 Panic occurred during command execution",
						zap.Any("panic", r),
						zap.String("command", cmd.Name()),
					)
					if debugMode {
						fmt.Fprintf(os.Stderr, "❌ Panic occurred: %+v\n", r)
					} else {
						fmt.Fprintf(os.Stderr, "❌ An unexpected error occurred. Use --debug for details.\n")
					}
					os.Exit(1)
				}
			}()

			err := originalRunE(cmd, args)
			duration := time.Since(ctx.StartTime)

			if err != nil {
				ctx.Log.Error("❌ EOS command failed",
					zap.Error(err),
					zap.String("command", cmd.Name()),
					zap.Duration("duration", duration),
				)
				eoserr.ExitWithError(ctx.Log, "Command failed", err)
			} else {
				ctx.Log.Info("✅ EOS command finished successfully",
					zap.String("command", cmd.Name()),
					zap.Duration("duration", duration),
				)
			}
			return nil
		}
	}

	return nil
}
