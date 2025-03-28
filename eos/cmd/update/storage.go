// cmd/update/storage.go
package update

import (
	"fmt"

	"github.com/spf13/cobra"
)

// updateStorageCmd handles updating storage information
var updateStorageCmd = &cobra.Command{
	Use:   "storage",
	Short: "Update storage",
	Long:  `Use this command to update storage configurations or details.`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			fmt.Println("Please specify the storage to update.")
			return
		}
		storage := args[0]
		fmt.Printf("Updating storage: %s\n", storage)
		// Add your logic here
	},
}
