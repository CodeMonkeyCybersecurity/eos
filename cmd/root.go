// cmd/root.go

package cmd

import (
	"fmt"
	"os"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eoserr"
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	// Subcommands
	"github.com/CodeMonkeyCybersecurity/eos/cmd/create"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/delete"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/delphi"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/disable"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/enable"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/hecate"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/pandora"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/read"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/refresh"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/secure"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/sync"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/update"

	// Internal packages
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
)

var helpLogged bool // global guard to log help only once
const NoSubcommandMsg = "⚠️  No subcommand provided. Try `eos help`."

var subcommands = []*cobra.Command{create.CreateCmd,
	read.ReadCmd,
	update.UpdateCmd,
	delete.DeleteCmd,
	refresh.RefreshCmd,
	secure.SecureCmd,
	disable.DisableCmd,
	enable.EnableCmd,
	sync.SyncCmd,
	hecate.HecateCmd,
	delphi.DelphiCmd,
	pandora.PandoraCmd}

// RootCmd is the base command for the EOS CLI, registering top-level subcommands.
var RootCmd = &cobra.Command{
	Use:   "eos",
	Short: "Eos CLI for automation, orchestration, and hardening",
	Long: `Eos is a command-line application for managing processes, users, hardware, backups,
and reverse proxy configurations via Hecate.`,
	// PersistentPreRun executes before any subcommand.

	RunE: eos.Wrap(func(ctx *eos.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := ctx.Log.Named("root")
		log.Warn(NoSubcommandMsg)
		return fmt.Errorf("no subcommand provided: run `eos help`")
	}),
}

// RegisterCommands attaches all subcommands to the EOS root command.
func RegisterCommands() {
	log := logger.L()

	RootCmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		if !helpLogged {
			log.Info("Global help triggered via --help or -h", zap.String("command", cmd.Name()))
			helpLogged = true
			defer log.Info("Global help display complete", zap.String("command", cmd.Name()))
		}
		if err := cmd.Root().Usage(); err != nil {
			log.Warn("Failed to print usage", zap.Error(err))
		}
	})

	// Group subcommands for cleanliness
	for _, subCmd := range subcommands {
		RootCmd.AddCommand(subCmd)
	}
}

// Execute runs the EOS CLI root command and handles global error handling.
func Execute() {
	if err := logger.InitializeWithFallback(nil); err != nil {
		log := logger.L()
		log.Warn("⚠ Logger fallback in effect", zap.Error(err))
	}
	log := logger.L()
	log.Info("Eos CLI starting")

	eos.SetLogger(log)
	RegisterCommands()

	if err := RootCmd.Execute(); err != nil {
		if eoserr.IsExpectedUserError(err) {
			log.Warn("CLI completed with user error", zap.Error(err))
			os.Exit(2)
		} else {
			log.Error("CLI execution error", zap.Error(err))
			os.Exit(1)
		}
	}
}
