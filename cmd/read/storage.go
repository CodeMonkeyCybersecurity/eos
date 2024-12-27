// cmd/read/storage.go
package read

import (
	"fmt"
	"log"

	"github.com/spf13/cobra"
)

// readStorageCmd represents the create command for storage
var readStorageCmd = &cobra.Command{
	Use:   "read",
	Short: "Read new storage resources",
	Long:  `This command allows you to read storage resources in the system.`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			log.Fatalf("Please specify the storage details to read.")
		}
		storageDetails := args[0]
		fmt.Printf("Reading storage: %s...\n", storageDetails)
		// Add your logic to read storage resources
	},
}

func init() {
	ReadCmd.AddCommand(readStorageCmd)
}
