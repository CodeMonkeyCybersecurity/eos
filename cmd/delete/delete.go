/*
cmd/delete/delete.go

Copyright © 2025 CODE MONKEY CYBERSECURITY git@cybermonkey.net.au

*/

package delete

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"

	"github.com/spf13/cobra"

	"go.uber.org/zap"
)

// DeleteCmd is the root command for delete operations
var DeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete resources (e.g., processes, users, storage)",
	Long: `The delete command allows you to remove various resources such as processes, users, or storage.
For example:
	eos delete trivy 
	eos delete vault
	eos delete umami`,

	Aliases: []string{"remove", "install"},
}

// log is a package-level variable for the Zap logger.
var log *zap.Logger

func init() {
	log = logger.GetLogger()

	// Initialize the shared logger for the entire install package
	DeleteCmd.AddCommand(deleteProcessCmd)
	DeleteCmd.AddCommand(deleteUsersCmd)
	DeleteCmd.AddCommand(deleteStorageCmd)
	DeleteCmd.AddCommand(deleteUmamiCmd)
	DeleteCmd.AddCommand(deleteVaultCmd)
	DeleteCmd.AddCommand(deleteJenkinsCmd)
}
