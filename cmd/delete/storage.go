// cmd/delete/storage.go
package delete

import (
	"fmt"

	"github.com/spf13/cobra"
eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
)

// deleteStorageCmd represents the command for deleting storage resources.
var DeleteStorageCmd = &cobra.Command{
	Use:   "storage",
	Short: "Delete storage resources",
	Long:  `This command allows you to delete storage resources in the system.`,
	RunE: eos.Wrap(func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			log.Fatal("Please specify the storage details to delete.")
		}
		storageDetails := args[0]
		log.Info(fmt.Sprintf("Deleting storage: %s...", storageDetails))
		// Add your logic to delete storage resources
		return nil 
	}),
}

func init() {

	DeleteCmd.AddCommand(DeleteStorageCmd)

}
