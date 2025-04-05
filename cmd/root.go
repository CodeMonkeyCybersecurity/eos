// cmd/root.go

package cmd

import (
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	// Eos commands
	"github.com/CodeMonkeyCybersecurity/eos/cmd/create"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/delete"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/disable"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/enable"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/inspect"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/logs"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/refresh"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/secure"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/update"

	// Grouping commands
	"github.com/CodeMonkeyCybersecurity/eos/cmd/delphi"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/hecate"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/utils"
)

var log = logger.L()

var RootCmd = &cobra.Command{
	Use:   "eos",
	Short: "eos CLI for managing local and remote environments and reverse proxy configurations",
	Long: `Eos is a command-line application for managing processes, users, hardware, backups, 
and reverse proxy configurations via Hecate.`,
	Run: func(cmd *cobra.Command, args []string) {
		log.Info("eos CLI started successfully.")
		if !utils.CheckSudo() {
			log.Error("Sudo privileges are required to create a backup.")
			return
		}
		configPath := filepath.Join(".", "config", "default.yaml")
		log.Info("Loaded configuration", zap.String("path", configPath))
	},
}

func RegisterCommands() {
	// Register standard Eos commands
	eosCommands := []*cobra.Command{
		create.CreateCmd,
		inspect.InspectCmd,
		update.UpdateCmd,
		delete.DeleteCmd,
		refresh.RefreshCmd,
		logs.LogsCmd,
		secure.SecureCmd,
		disable.DisableCmd,
		enable.EnableCmd,
	}
	for _, cmd := range eosCommands {
		RootCmd.AddCommand(cmd)
	}

	// Register grouping commands once
	RootCmd.AddCommand(hecate.HecateCmd)
	RootCmd.AddCommand(delphi.DelphiCmd)
}

func Execute() {
	// Initialize logger
	if logger.GetLogger() == nil {
		logger.Initialize()
	}
	defer logger.Sync()

	// Register commands and execute the CLI
	RegisterCommands()
	if err := RootCmd.Execute(); err != nil {
		log.Error("CLI execution error", zap.Error(err))
		os.Exit(1)
	}
}
