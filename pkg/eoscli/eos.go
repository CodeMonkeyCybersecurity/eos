package eoscli

import (
	"context"
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// Define a private type and key for the context.
type contextKey int

const startLoggedKey contextKey = 0

// Wrap wraps a RunE function to log start and end messages.
// It sets a flag in the command's context so that the "start" banner is only printed once.
func Wrap(runE func(cmd *cobra.Command, args []string) error) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		// Check if the start banner has been logged already.
		ctx := cmd.Context()
		if ctx.Value(startLoggedKey) == nil {
			log := logger.GetLogger()
			cmdPath := cmd.CommandPath()
			timestamp := time.Now().Format("2006-01-02 15:04:05")
			startBanner := fmt.Sprintf("───────[ START %s @ %s ]───────", cmdPath, timestamp)
			fmt.Println("\n" + startBanner)
			log.Info("Command started", zap.String("command", cmdPath), zap.String("time", timestamp))
			// Mark as logged.
			ctx = context.WithValue(ctx, startLoggedKey, true)
			cmd.SetContext(ctx)
		}

		// Execute the underlying command.
		err := runE(cmd, args)

		// Always log the end banner.
		log := logger.GetLogger()
		cmdPath := cmd.CommandPath()
		endTime := time.Now().Format("2006-01-02 15:04:05")
		endBanner := fmt.Sprintf("───────[ END %s @ %s ]───────", cmdPath, endTime)
		fmt.Println(endBanner)
		if err != nil {
			log.Error("Command failed", zap.String("command", cmdPath), zap.String("time", endTime), zap.Error(err))
		} else {
			log.Info("Command completed", zap.String("command", cmdPath), zap.String("time", endTime))
		}

		return err
	}
}
