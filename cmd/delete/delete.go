/*
Copyright © 2024 Henry Oliver henry@cybermonkey.net.au
*/
//cmd//delete/delete.go
package delete

import (
	"eos/pkg/logger"

	"github.com/spf13/cobra"
	
	"go.uber.org/zap"
)

// DeleteCmd is the root command for delete operations
var DeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete resources (e.g., processes, users, storage)",
	Long:  `The delete command allows you to remove various resources such as processes, users, or storage.
For example:
	eos delete trivy 
	eos delete vault
	eos delete umami`,
}


// log is a package-level variable for the Zap logger.
var log *zap.Logger

func init() {
    // Initialize the shared logger for the entire install package
    log = logger.GetLogger()

	DeleteCmd.AddCommand(deleteProcessCmd)
	DeleteCmd.AddCommand(deleteUsersCmd)
	DeleteCmd.AddCommand(deleteStorageCmd)
	DeleteCmd.AddCommand(deleteUmamiCmd)
}
