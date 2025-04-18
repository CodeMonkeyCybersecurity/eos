// cmd/create/storage.go
package create

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/spf13/cobra"
)

// createStorageCmd represents the create command for storage
var CreateStorageCmd = &cobra.Command{
	Use:   "storage",
	Short: "Create new storage resources",
	Long:  `This command allows you to create new storage resources in the system.`,
	RunE: eos.Wrap(func(ctx *eos.RuntimeContext, cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			log.Fatal("Please specify the storage details to create.")
		}
		storageDetails := args[0]
		fmt.Printf("Creating storage: %s...\n", storageDetails)
		// Add your logic to create storage resources
		return nil
	}),
}

func init() {
	CreateCmd.AddCommand(CreateStorageCmd)
}
