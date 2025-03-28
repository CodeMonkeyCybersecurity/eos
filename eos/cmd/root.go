// cmd/root.go

package cmd

import (
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	// Eos commands
	"eos/cmd/create"
	"eos/cmd/delete"
	"eos/cmd/deploy"
	"eos/cmd/logs"
	"eos/cmd/read"
	"eos/cmd/refresh"
	"eos/cmd/secure"
	"eos/cmd/update"

	// Grouping commands
	"eos/cmd/delphi"
	"eos/cmd/hecate"

	"eos/pkg/logger"
	"eos/pkg/utils"
)

var log = logger.L()

var RootCmd = &cobra.Command{
	Use:   "eos",
	Short: "Eos CLI for managing local and remote environments and reverse proxy configurations",
	Long: `Eos is a command-line application for managing processes, users, hardware, backups, 
and reverse proxy configurations via Hecate.`,
	Run: func(cmd *cobra.Command, args []string) {
		log.Info("Eos CLI started successfully.")
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
		read.ReadCmd,
		update.UpdateCmd,
		delete.DeleteCmd,
		deploy.DeployCmd,
		refresh.RefreshCmd,
		logs.LogsCmd,
		secure.SecureCmd,
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
