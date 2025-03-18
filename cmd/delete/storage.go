// cmd/delete/storage.go
package delete

import (
	"fmt"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// deleteStorageCmd represents the command for deleting storage resources.
var deleteStorageCmd = &cobra.Command{
	Use:   "storage",
	Short: "Delete storage resources",
	Long:  `This command allows you to delete storage resources in the system.`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			log.Fatal("Please specify the storage details to delete.")
		}
		storageDetails := args[0]
		log.Info(fmt.Sprintf("Deleting storage: %s...", storageDetails))
		// Add your logic to delete storage resources
	},
}
