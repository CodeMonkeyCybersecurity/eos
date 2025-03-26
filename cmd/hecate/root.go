// cmd/root.go

/*
Copyright © 2025 CODE MONKEY CYBERSECURITY git@cybermonkey.net.au

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
*/
package cmd

import (
	"os"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"eos/cmd/backup"
	"eos/cmd/create"
	"eos/cmd/delete"
	"eos/cmd/deploy"
	"eos/cmd/inspect"
	"eos/cmd/restore"
	"eos/cmd/update"

	"eos/pkg/config"
	"eos/pkg/logger"
)

var log = logger.L()

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "hecate",
	Short: "Manage and configure your reverse proxy with Hecate CLI.",
	Long: `Hecate is a command-line tool designed to simplify the management and configuration 
of your reverse proxy setup. It provides a unified interface for tasks such as deploying, 
updating, and monitoring your proxy environment.

Examples:
	# Display the help information for Hecate
  	hecate --help

  	# Deploy a new reverse proxy configuration for a specific application
  	hecate deploy jenkins
   	hecate deploy nextcloud
    	hecate deploy delphi

 	# Check the status of your reverse proxy services
  	hecate inspect

Use Hecate to quickly generate configuration files, manage certificates, and streamline 
the deployment process for your reverse proxy setup.`,

	Run: func(cmd *cobra.Command, args []string) {
		cmd.Println("Using configuration:", config.DefaultConfigPath)
	},
}

// ✅ Register all subcommands dynamically
func RegisterCommands() {
	commands := []*cobra.Command{
		create.CreateCmd,
		inspect.InspectCmd,
		update.UpdateCmd,
		delete.DeleteCmd,
		restore.RestoreCmd,
		deploy.DeployCmd,
		backup.BackupCmd,
	}

	for _, cmd := range commands {
		RootCmd.AddCommand(cmd) // ✅ Registers all commands in a loop
	}
}

// ✅ Execute starts the CLI
func Execute() {
	RegisterCommands()

	// ✅ Prevent duplicate logging initialization
	if logger.GetLogger() == nil {
		logger.Initialize()
	}
	defer logger.Sync() // ✅ Ensure logs are flushed properly

	// ✅ Prevent nil logger issue before logging starts
	if log == nil {
		println("⚠️ Warning: Logger is nil. Defaulting to console output.")
	} else {
		log.Info("🚀 Hecate CLI started successfully.")
	}

	// ✅ Execute the root command and handle errors properly
	if err := RootCmd.Execute(); err != nil {
		if log != nil {
			log.Error("❌ CLI execution error", zap.Error(err))
		} else {
			println("❌ CLI execution error:", err.Error()) // Fallback if logger is nil
		}
		os.Exit(1) // ✅ Exit with error code only if execution fails
	}
}
