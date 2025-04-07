// pkg/eoscli/eos.go

package handler

import (
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/flags"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

func Wrap(runE func(cmd *cobra.Command, args []string) error) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		log := logger.GetLogger()
		cmdPath := cmd.CommandPath()
		timestamp := time.Now().Format("2006-01-02 15:04:05")

		startBanner := fmt.Sprintf("───────[ START %s @ %s ]───────", cmdPath, timestamp)
		fmt.Println("\n" + startBanner)
		log.Info("Command started", zap.String("command", cmdPath), zap.String("time", timestamp))

		// DRY RUN ENFORCEMENT
		if !flags.IsLiveRun() {
			fmt.Println("⚠️  Dry run mode: this command will not apply changes unless --live-run is set.")
			log.Warn("Dry run mode: this command will not apply changes unless --live-run is set.")
		}

		err := runE(cmd, args)

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
