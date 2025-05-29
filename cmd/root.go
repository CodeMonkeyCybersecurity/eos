// cmd/root.go

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
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
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

var helpLogged bool // global guard to log help only once

// RootCmd is the base command for eos.
var RootCmd = &cobra.Command{
	Use:   "eos",
	Short: "Eos CLI for automation, orchestration, and hardening",
	Long: `Eos is a command-line application for managing processes, users, hardware, backups,
and reverse proxy configurations via Hecate.`,
	// PersistentPreRun executes before any subcommand.

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		fmt.Println("⚠️  No subcommand provided. Try `eos help`.")
		return cmd.Help()
	}),
}

// RegisterCommands adds all subcommands to the root command.
func RegisterCommands(rc *eos_io.RuntimeContext) {

	RootCmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		if !helpLogged {
			otelzap.Ctx(rc.Ctx).Info("Global help triggered via --help or -h", zap.String("command", cmd.Name()))
			helpLogged = true
			defer otelzap.Ctx(rc.Ctx).Info("Global help display complete", zap.String("command", cmd.Name()))
		}
		if err := cmd.Root().Usage(); err != nil {
			otelzap.Ctx(rc.Ctx).Warn("Failed to print usage", zap.Error(err))
		}
	})

	// Group subcommands for cleanliness
	for _, subCmd := range []*cobra.Command{
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
		RootCmd.AddCommand(subCmd)
	}
}

// Execute initializes and runs the root command.
func Execute(rc *eos_io.RuntimeContext) {
	_ = telemetry.Init("eos")

	otelzap.Ctx(rc.Ctx).Info("Eos CLI starting")
	startGlobalWatchdog(rc, 3*time.Minute)

	RegisterCommands(rc)

	if err := RootCmd.Execute(); err != nil {
		if eos_err.IsExpectedUserError(err) {
			otelzap.Ctx(rc.Ctx).Warn("CLI completed with user error", zap.Error(err))
			os.Exit(0)
		} else {
			otelzap.Ctx(rc.Ctx).Error("CLI execution error", zap.Error(err))
			os.Exit(1)
		}
	}
}

func startGlobalWatchdog(rc *eos_io.RuntimeContext, max time.Duration) {
	go func() {
		timer := time.NewTimer(max)
		<-timer.C
		fmt.Fprintf(os.Stderr, "💣 EOS watchdog: global timeout (%s) exceeded. Forcing shutdown.\n", max)
		if err := syscall.Kill(syscall.Getpid(), syscall.SIGKILL); err != nil {
			otelzap.Ctx(rc.Ctx).Error("Failed to send SIGKILL to self", zap.Error(err))
		}
	}()
}
