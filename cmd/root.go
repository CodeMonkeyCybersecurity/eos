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
	"github.com/CodeMonkeyCybersecurity/eos/cmd/read" // NOTE: This `read` is a TOP-LEVEL command, not delphi/read
	"github.com/CodeMonkeyCybersecurity/eos/cmd/refresh"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/secure"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/sync"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/update"
	// Internal packages
)

// helpLogged removed as it's not needed with default Cobra help
// var helpLogged bool // global guard to log help only once

// RootCmd is the base command for eos.
var RootCmd = &cobra.Command{
	Use:   "eos",
	Short: "Eos CLI for automation, orchestration, and hardening",
	Long: `Eos is a command-line application for managing processes, users, hardware, backups,
and reverse proxy configurations via Hecate.

Use "eos [command] --help" for more information about a command.`, // Added standard Cobra advice

	// ⚠️ IMPORTANT CHANGE: Remove the custom SetHelpFunc on RootCmd.
	// Cobra's default help function is smart enough to show context-specific help.
	// If you need global logging for help, do it in PersistentPreRun or similar.

	// RunE for the root command when no subcommand is provided.
	// This will print the default help for the root command.
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		// This executes if `eos` is run without any subcommand.
		// `cmd.Help()` will show the help for the root command by default.
		return cmd.Help()
	}),
}

// RegisterCommands adds all subcommands to the root command.
// No change needed here, this is good.
func RegisterCommands(rc *eos_io.RuntimeContext) {
	// ⚠️ REMOVED: RootCmd.SetHelpFunc. This was the primary cause of generic help.
	// Cobra's default help generation is hierarchical and contextual.

	// Group subcommands for cleanliness
	for _, subCmd := range []*cobra.Command{
		create.CreateCmd,
		read.ReadCmd, // This is the top-level 'read'
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
		delphi.DelphiCmd, // This is the top-level 'delphi'
		pandora.PandoraCmd,
	} {
		RootCmd.AddCommand(subCmd)
	}
}

// Execute initializes and runs the root command.
// No change needed here.
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
