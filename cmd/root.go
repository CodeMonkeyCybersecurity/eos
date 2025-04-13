/* cmd/root.go */

package cmd

import (
	"fmt"
	"os"

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
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
)

// RootCmd is the base command for eos.
var RootCmd = &cobra.Command{
	Use:   "eos",
	Short: "Eos CLI for automation, orchestration, and hardening",
	Long: `Eos is a command-line application for managing processes, users, hardware, backups,
and reverse proxy configurations via Hecate.`,
	// PersistentPreRunE executes before any subcommand.
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// ✅ Always run this first, even for --help
		logger.InitializeWithFallback()

		// 🔐 Set VAULT_ADDR
		if _, err := vault.SetVaultEnv(); err != nil {
			fmt.Printf("⚠️  Failed to set VAULT_ADDR: %v\n", err)
		}

		// 🚀 Setup Vault client for fallback read/writes
		vault.EnsureVaultClient()
	},
	RunE: eos.Wrap(func(cmd *cobra.Command, args []string) error {
		fmt.Println("⚠️  No subcommand provided. Try `eos help`.")
		return cmd.Help()
	}),
}

// RegisterCommands adds all subcommands to the root command.
func RegisterCommands() {
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
	for _, cmd := range subCommands {
		RootCmd.AddCommand(cmd)
	}

	// Register additional standalone commands.
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
