// cmd/delete/storage.go
package delete

import (
	"fmt"
	"log"

	"github.com/spf13/cobra"
)

// deleteStorageCmd represents the create command for storage
var deleteStorageCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete new storage resources",
	Long:  `This command allows you to delete storage resources in the system.`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			log.Fatalf("Please specify the storage details to delete.")
		}
		storageDetails := args[0]
		fmt.Printf("Deleting storage: %s...\n", storageDetails)
		// Add your logic to delete storage resources
	},
}

func init() {
	DeleteCmd.AddCommand(deleteStorageCmd)
}
