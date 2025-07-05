// cmd/root.go

package cmd

import (
	"os"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/telemetry"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"

	// Subcommands
	"github.com/CodeMonkeyCybersecurity/eos/cmd/ai"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/backup"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/container"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/create"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/delete"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/delphi"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/disable"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/enable"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/git"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/hecate"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/inspect"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/list"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/manage"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/pandora"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/read" // NOTE: This `read` is a TOP-LEVEL command, not delphi/read
	"github.com/CodeMonkeyCybersecurity/eos/cmd/refresh"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/secure"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/self"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/storage"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/sync"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/update"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/ragequit"
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

	// Group subcommands for cleanliness
	for _, subCmd := range []*cobra.Command{
		ai.AICmd,
		create.CreateCmd,
		container.ContainerCmd,
		crypto.CryptoCmd,
		read.ReadCmd, // This is the top-level 'read'
		list.ListCmd,
		update.UpdateCmd,
		delete.DeleteCmd,
		self.SelfCmd,
		refresh.RefreshCmd,
		secure.SecureCmd,
		disable.DisableCmd,
		backup.BackupCmd,
		enable.EnableCmd,
		storage.StorageCmd,
		sync.SyncCmd,
		git.GitCmd, // Git repository management
		hecate.HecateCmd,
		delphi.DelphiCmd, // This is the top-level 'delphi'
		inspect.InspectCmd, // This is the top-level 'inspect'
		manage.ManageCmd, // System management via SaltStack
		pandora.PandoraCmd,
		ragequit.RagequitCmd,
	} {
		RootCmd.AddCommand(subCmd)
	}
}

// Execute initializes and runs the root command.
// No change needed here.
func Execute(rc *eos_io.RuntimeContext) {
	_ = telemetry.Init("eos")

	// Register all subcommands first
	RegisterCommands(rc)

	// Start global watchdog timer for command execution
	watchdogDuration := 3 * time.Minute
	timer := time.NewTimer(watchdogDuration)
	defer timer.Stop()

	// Channel to signal completion
	done := make(chan bool)

	// Execute command in goroutine
	go func() {
		defer func() {
			done <- true
		}()

		// Execute the command
		if err := RootCmd.Execute(); err != nil {
			if eos_err.IsExpectedUserError(err) {
				// Expected error (bad usage, file not found, etc.)
				// Show the error but don't use ERROR level logging
				logger := otelzap.Ctx(rc.Ctx)
				logger.Info("Command completed with expected error",
					zap.Error(err),
					zap.String("error_type", "user_error"))
				os.Exit(0) // Exit with success code for user errors
			} else {
				// Unexpected system error
				logger := otelzap.Ctx(rc.Ctx)
				logger.Error("Command failed with system error",
					zap.Error(err),
					zap.String("error_type", "system_error"))
				os.Exit(1) // Exit with error code for system errors
			}
		}
	}()

	// Wait for either completion or timeout
	select {
	case <-done:
		// Command completed normally
		return
	case <-timer.C:
		// Watchdog timeout
		logger := otelzap.Ctx(rc.Ctx)
		logger.Fatal("Command execution timeout exceeded",
			zap.Duration("timeout", watchdogDuration),
			zap.String("component", rc.Component))
	}
}