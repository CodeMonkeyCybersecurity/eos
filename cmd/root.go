/* cmd/root.go */

package cmd

import (
	"fmt"
	"os"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
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

	RunE: eos.Wrap(func(cmd *cobra.Command, args []string) error {
		fmt.Println("⚠️  No subcommand provided. Try `eos help`.")
		return cmd.Help()
	}),
}

// HelpCmd wraps help so that it can be invoked like a normal command.
var HelpCmd = &cobra.Command{
	Use:   "help",
	Short: "Help about any command",
	Long:  "Displays help for eos or a specific subcommand.",
	RunE: eos.Wrap(func(cmd *cobra.Command, args []string) error {
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

	// Override the global help function to use Cobra's default help function,
	// but protect with a global guard to avoid looping.
	RootCmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		if !helpLogged {
			logger.L().Info("Global help triggered via --help or -h", zap.String("command", cmd.Name()))
			helpLogged = true
			defer logger.L().Info("Global help display complete", zap.String("command", cmd.Name()))
		}
		cmd.Root().Usage()
	})

	// List of primary subcommands.
	subCommands := []*cobra.Command{
		create.CreateCmd,
		inspect.InspectCmd,
		update.UpdateCmd,
		delete.DeleteCmd,
		refresh.RefreshCmd,
		secure.SecureCmd,
		disable.DisableCmd,
		enable.EnableCmd,
		sync.SyncCmd,
	}
	for _, subCmd := range subCommands {
		RootCmd.AddCommand(subCmd)
	}

	// Additional standalone commands.
	RootCmd.AddCommand(hecate.HecateCmd)
	RootCmd.AddCommand(delphi.DelphiCmd)
}

// Execute initializes and runs the root command.
func Execute() {
	defer logger.Sync()

	logger.L().Info("Eos CLI starting")

	RegisterCommands()

	if err := RootCmd.Execute(); err != nil {
		logger.L().Error("CLI execution error", zap.Error(err))
		os.Exit(1)
	}
}
