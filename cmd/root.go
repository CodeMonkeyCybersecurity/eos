/* cmd/root.go */

package cmd

import (
	"fmt"
	"os"
	"strings"

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
	"github.com/CodeMonkeyCybersecurity/eos/cmd/inspect"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/pandora"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/refresh"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/secure"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/sync"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/update"

	// Internal packages
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
)

var helpLogged bool // global guard to log help only once

// RootCmd is the base command for eos.
var RootCmd = &cobra.Command{
	Use:   "eos",
	Short: "Eos CLI for automation, orchestration, and hardening",
	Long: `Eos is a command-line application for managing processes, users, hardware, backups,
and reverse proxy configurations via Hecate.`,
	// PersistentPreRun executes before any subcommand.

	RunE: eos.Wrap(func(ctx *eos.RuntimeContext, cmd *cobra.Command, args []string) error {
		fmt.Println("⚠️  No subcommand provided. Try `eos help`.")
		return cmd.Help()
	}),
}

// HelpCmd wraps help so that it can be invoked like a normal command.
var HelpCmd = &cobra.Command{
	Use:   "help",
	Short: "Help about any command",
	Long:  "Displays help for eos or a specific subcommand.",
	RunE: eos.Wrap(func(ctx *eos.RuntimeContext, cmd *cobra.Command, args []string) error {
		// If no arguments, show root help
		if len(args) == 0 {
			return RootCmd.Help()
		}
		// Otherwise, find the command and show its help.
		c, _, err := RootCmd.Find(args)
		if err != nil || c == nil {
			return fmt.Errorf("command not found: %s", strings.Join(args, " "))
		}
		return c.Help()
	}),
}

// RegisterCommands adds all subcommands to the root command.
func RegisterCommands() {
	RootCmd.SetHelpCommand(HelpCmd)

	// Fix: logger.GetLogger is a function, call it
	log := logger.GetLogger()

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
	for _, subCmd := range []*cobra.Command{
		create.CreateCmd,
		inspect.InspectCmd,
		update.UpdateCmd,
		delete.DeleteCmd,
		refresh.RefreshCmd,
		secure.SecureCmd,
		disable.DisableCmd,
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
func Execute() {
	defer func() {
		if err := logger.Sync(); err != nil {
			fmt.Fprintf(os.Stderr, "⚠️  Failed to flush logs: %v\n", err)
		}
	}()

	logger.L().Info("Eos CLI starting")

	RegisterCommands()

	if err := RootCmd.Execute(); err != nil {
		if eoserr.IsExpectedUserError(err) {
			logger.L().Warn("CLI completed with user error", zap.Error(err))
			os.Exit(0) // <-- gracefully allow 0 exit code for user errors
		} else {
			logger.L().Error("CLI execution error", zap.Error(err))
			os.Exit(1)
		}
	}
}
