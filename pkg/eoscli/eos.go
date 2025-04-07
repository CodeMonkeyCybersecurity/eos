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

		startMsg := fmt.Sprintf("───────[ START %s @ %s ]───────", cmdPath, time.Now().Format("2006-01-02 15:04:05"))
		log.Info(startMsg)

		// DRY RUN ENFORCEMENT
		if !flags.IsLiveRun() {
			log.Warn("Dry run mode: this command will not apply changes unless --live-run is set.")
		}

		err := runE(cmd, args)

		endMsg := fmt.Sprintf("───────[ END %s @ %s ]───────", cmdPath, time.Now().Format("2006-01-02 15:04:05"))
		if err != nil {
			log.Error(endMsg, zap.Error(err))
		} else {
			log.Info(endMsg)
		}

		return err
	}
}
