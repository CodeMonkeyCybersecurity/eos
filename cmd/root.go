/* cmd/root.go */

package cmd

import (
	"fmt"
	"os"
	"syscall"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/telemetry"
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	// Subcommands
	"github.com/CodeMonkeyCybersecurity/eos/cmd/backup"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/config"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/create"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/delete"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/delphi"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/disable"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/enable"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/hecate"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/list"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/pandora"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/read"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/refresh"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/secure"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/sync"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/update"
	// Internal packages
)

var (
	helpLogged bool
	RootCmd    = &cobra.Command{
		Use:   "eos",
		Short: "Eos CLI for automation, orchestration, and hardening",
		Long:  `Eos is a command-line application for managing ….`,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			// Telemetry + logging
			if err := telemetry.Init("eos"); err != nil {
				fmt.Fprintf(os.Stderr, "⚠️ Telemetry disabled: %v\n", err)
			}
			zap.L().Info("Eos CLI starting")

			// Watchdog
			startGlobalWatchdog(3 * time.Minute)
		},
		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			fmt.Println("⚠️ No subcommand provided. Try `eos help`.")
			return cmd.Help()
		}),
	}
)

func init() {
	// Register every subcommand at import-time
	for _, c := range []*cobra.Command{
		create.CreateCmd,
		read.ReadCmd,
		list.ListCmd,
		update.UpdateCmd,
		delete.DeleteCmd,
		config.ConfigCmd,
		refresh.RefreshCmd,
		secure.SecureCmd,
		disable.DisableCmd,
		backup.BackupCmd,
		enable.EnableCmd,
		sync.SyncCmd,
		hecate.HecateCmd,
		delphi.DelphiCmd,
		pandora.PandoraCmd,
	} {
		RootCmd.AddCommand(c)
	}

	RootCmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		if !helpLogged {
			zap.L().Info("Help triggered", zap.String("cmd", cmd.Name()))
			helpLogged = true
		}
		cmd.Root().Usage()
	})
}

// Execute runs the CLI and handles exit codes.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		if eos_err.IsExpectedUserError(err) {
			zap.L().Warn("User error", zap.Error(err))
			os.Exit(0)
		}
		zap.L().Error("Execution error", zap.Error(err))
		os.Exit(1)
	}
}

func startGlobalWatchdog(max time.Duration) {
	go func() {
		timer := time.NewTimer(max)
		<-timer.C
		fmt.Fprintf(os.Stderr, "💣 EOS watchdog: global timeout (%s) exceeded. Forcing shutdown.\n", max)
		if err := syscall.Kill(syscall.Getpid(), syscall.SIGKILL); err != nil {
			zap.L().Error("Failed to send SIGKILL to self", zap.Error(err))
		}
	}()
}
