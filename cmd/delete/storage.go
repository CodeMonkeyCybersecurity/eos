// cmd/delete/storage.go
package delete

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eosio"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// deleteStorageCmd represents the command for deleting storage resources.
var DeleteStorageCmd = &cobra.Command{
	Use:   "storage",
	Short: "Delete storage resources",
	Long:  `This command allows you to delete storage resources in the debian.`,
	RunE: eos.Wrap(func(ctx *eosio.RuntimeContext, cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			zap.L().Fatal("Please specify the storage details to delete.")
		}
		storageDetails := args[0]
		zap.L().Info(fmt.Sprintf("Deleting storage: %s...", storageDetails))
		// Add your logic to delete storage resources
		return nil
	}),
}

func init() {

	DeleteCmd.AddCommand(DeleteStorageCmd)

}
