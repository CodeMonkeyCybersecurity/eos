// cmd/create/storage.go
package create

import (
	"fmt"


	"github.com/spf13/cobra"
)

// createStorageCmd represents the create command for storage
var CreateStorageCmd = &cobra.Command{
	Use:   "storage",
	Short: "Create new storage resources",
	Long:  `This command allows you to create new storage resources in the system.`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			log.Fatal("Please specify the storage details to create.")
		}
		storageDetails := args[0]
		fmt.Printf("Creating storage: %s...\n", storageDetails)
		// Add your logic to create storage resources
	},
}

func init() {
	CreateCmd.AddCommand(CreateStorageCmd)
}
