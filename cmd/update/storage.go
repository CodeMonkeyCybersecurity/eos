// cmd/update/storage.go
package update

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
)

// updateStorageCmd handles updating storage information
var UpdateStorageCmd = &cobra.Command{
	Use:   "storage",
	Short: "Update storage",
	Long:  `Use this command to update storage configurations or details.`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			fmt.Println("Please specify the storage to update.")
			return nil
		}
		storage := args[0]
		fmt.Printf("Updating storage: %s\n", storage)
		// Add your logic here
		return nil
	}),
}

// init registers subcommands for the update command
func init() {
	UpdateCmd.AddCommand(UpdateStorageCmd)
}
