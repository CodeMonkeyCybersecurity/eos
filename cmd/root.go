// cmd/root.go

package cmd

import (
	"os"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"

	// Subcommands - Core verb-first architecture
	"github.com/CodeMonkeyCybersecurity/eos/cmd/backup"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/create"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/debug"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/delete"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/fix"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/list"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/nuke"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/ragequit"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/read"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/restore"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/rollback"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/self"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/sync"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/unsync"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/update"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/upgrade"
)

var (
	// Global flags for verbosity control
	verboseOutput bool
	quietOutput   bool
)

func init() {
	// Add global flags for output verbosity
	// These are persistent flags that apply to all subcommands
	RootCmd.PersistentFlags().BoolVarP(&verboseOutput, "verbose", "v", false,
		"Enable verbose output (show all DEBUG/INFO logs)")
	RootCmd.PersistentFlags().BoolVarP(&quietOutput, "quiet", "q", false,
		"Minimal output (show only errors and final status)")
}

// IsVerbose returns true if --verbose flag was set
func IsVerbose() bool {
	return verboseOutput
}

// IsQuiet returns true if --quiet flag was set
func IsQuiet() bool {
	return quietOutput
}

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
		create.CreateCmd,     // VERB-FIRST ARCHITECTURE
		read.ReadCmd,         // VERB-FIRST ARCHITECTURE
		list.ListCmd,         // VERB-FIRST ARCHITECTURE
		update.UpdateCmd,     // VERB-FIRST ARCHITECTURE
		upgrade.UpgradeCmd,   // VERB-FIRST ARCHITECTURE (version upgrades)
		delete.DeleteCmd,     // VERB-FIRST ARCHITECTURE
		fix.FixCmd,           // VERB-FIRST ARCHITECTURE (auto-fix issues)
		debug.GetDebugCmd(),  // VERB-FIRST ARCHITECTURE (debugging tools)
		sync.SyncCmd,         // VERB-FIRST ARCHITECTURE (service synchronization)
		unsync.UnsyncCmd,     // VERB-FIRST ARCHITECTURE (reverse synchronization)
		self.SelfCmd,         // SPECIAL CASE (Eos self-management)
		backup.BackupCmd,     // SPECIAL CASE (Complex nomenclature)
		restore.RestoreCmd,   // VERB-FIRST ARCHITECTURE (restore from backups)
		rollback.RollbackCmd, // VERB-FIRST ARCHITECTURE (rollback operations)

		// Top-level aliases for convenience
		nuke.NukeCmd, // Alias for delete nuke

		// TODO: Migrate these to verb directories (Phase 4)
		// wazuh.WazuhCmd,    // TODO: Migrate to verb directories (Phase 4)
		// .Cmd,        // TODO: Migrate to verb directories (Phase 4)

		// Legacy commands
		ragequit.RagequitCmd,
	} {
		RootCmd.AddCommand(subCmd)
	}

	// Create repair alias for backward compatibility
	repairCmd := &cobra.Command{
		Use:    "repair",
		Short:  "Alias for 'fix' command (deprecated, use 'fix' instead)",
		Hidden: false,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Redirect to fix command
			fixArgs := append([]string{"fix"}, args...)
			RootCmd.SetArgs(fixArgs)
			return RootCmd.Execute()
		},
	}
	RootCmd.AddCommand(repairCmd)

	// Add subcommands after all init() functions have run
	update.AddSubcommands()
	backup.AddSubcommands()
	rollback.AddSubcommands()
}

// Execute initializes and runs the root command.
func Execute(rc *eos_io.RuntimeContext) {
	// Skip telemetry for now to avoid hangs
	// _ = telemetry.Init("eos")

	// Register all subcommands first
	RegisterCommands(rc)

	// Simple execution without watchdog
	if err := RootCmd.Execute(); err != nil {
		logger := otelzap.Ctx(rc.Ctx)
		if eos_err.IsExpectedUserError(err) {
			logger.Info("Command completed with expected error", zap.Error(err))
			os.Exit(0)
		} else {
			logger.Error("Command failed with system error", zap.Error(err))
			os.Exit(1)
		}
	}
}
