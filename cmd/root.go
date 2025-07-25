// cmd/root.go

package cmd

import (
	"os"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/telemetry"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/watchdog"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"

	// Subcommands - Core verb-first architecture
	"github.com/CodeMonkeyCybersecurity/eos/cmd/backup"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/bootstrap"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/create"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/debug"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/delete"

	// "github.com/CodeMonkeyCybersecurity/eos/cmd/delphi" // TODO: Migrate to verb directories
	"github.com/CodeMonkeyCybersecurity/eos/cmd/list"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/nuke"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/ragequit"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/read"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/self"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/update"
	// "github.com/CodeMonkeyCybersecurity/eos/cmd/salt" // TODO: Migrate to verb directories
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

	// IMPORTANT CHANGE: Remove the custom SetHelpFunc on RootCmd.
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
	// REMOVED: RootCmd.SetHelpFunc. This was the primary cause of generic help.
	// Cobra's default help generation is hierarchical and contextual.

	// Group subcommands for cleanliness - Core verb-first architecture
	for _, subCmd := range []*cobra.Command{
		create.CreateCmd, // VERB-FIRST ARCHITECTURE
		read.ReadCmd,     // VERB-FIRST ARCHITECTURE
		list.ListCmd,     // VERB-FIRST ARCHITECTURE
		update.UpdateCmd, // VERB-FIRST ARCHITECTURE
		delete.DeleteCmd, // VERB-FIRST ARCHITECTURE
		debug.GetDebugCmd(), // VERB-FIRST ARCHITECTURE (debugging tools)
		self.SelfCmd,     // SPECIAL CASE (Eos self-management)
		backup.BackupCmd, // SPECIAL CASE (Complex nomenclature)
		
		// Top-level aliases for convenience
		bootstrap.BootstrapCmd, // Alias for create bootstrap
		nuke.NukeCmd,           // Alias for delete nuke

		// TODO: Migrate these to verb directories (Phase 4)
		// delphi.DelphiCmd,    // TODO: Migrate to verb directories (Phase 4)
		// salt.SaltCmd,        // TODO: Migrate to verb directories (Phase 4)

		// Legacy commands
		ragequit.RagequitCmd,
	} {
		RootCmd.AddCommand(subCmd)
	}
	
	// Add bootstrap subcommands after all init() functions have run
	bootstrap.AddSubcommands()
}

// Execute initializes and runs the root command.
func Execute(rc *eos_io.RuntimeContext) {
	_ = telemetry.Init("eos")

	// Register all subcommands first
	RegisterCommands(rc)

	// Create command watchdog with configurable timeout
	logger := otelzap.Ctx(rc.Ctx)
	
	// Check for custom timeout from environment or use default
	watchdogTimeout := 3 * time.Minute
	if envTimeout := os.Getenv("EOS_WATCHDOG_TIMEOUT"); envTimeout != "" {
		if duration, err := time.ParseDuration(envTimeout); err == nil {
			watchdogTimeout = duration
			logger.Info("Using custom watchdog timeout",
				zap.Duration("timeout", watchdogTimeout))
		}
	}
	
	// Create and use the command watchdog
	cmdWatchdog := watchdog.NewCommandWatchdog(rc.Log, watchdogTimeout)
	
	// Get command name for logging
	cmdName := "eos"
	if len(os.Args) > 1 {
		cmdName = os.Args[1]
	}
	
	// Execute with watchdog protection
	err := cmdWatchdog.Execute(cmdName, os.Args[1:], func() error {
		// Execute the command
		if err := RootCmd.Execute(); err != nil {
			if eos_err.IsExpectedUserError(err) {
				// Expected error (bad usage, file not found, etc.)
				// Show the error but don't use ERROR level logging
				logger.Info("Command completed with expected error",
					zap.Error(err),
					zap.String("error_type", "user_error"))
				os.Exit(0) // Exit with success code for user errors
			} else {
				// Unexpected system error
				logger.Error("Command failed with system error",
					zap.Error(err),
					zap.String("error_type", "system_error"))
				os.Exit(1) // Exit with error code for system errors
			}
		}
		return nil
	})
	
	// This should never be reached due to os.Exit calls above
	if err != nil {
		logger.Error("Unexpected error in command execution", zap.Error(err))
		os.Exit(1)
	}
}
