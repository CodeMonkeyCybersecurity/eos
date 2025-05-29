// cmd/delete/storage.go
package delete

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

// deleteStorageCmd represents the command for deleting storage resources.
var DeleteStorageCmd = &cobra.Command{
	Use:   "storage",
	Short: "Delete storage resources",
	Long:  `This command allows you to delete storage resources in the eos_unix.`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			otelzap.Ctx(rc.Ctx).Fatal("Please specify the storage details to delete.")
		}
		storageDetails := args[0]
		otelzap.Ctx(rc.Ctx).Info(fmt.Sprintf("Deleting storage: %s...", storageDetails))
		// Add your logic to delete storage resources
		return nil
	}),
}

func init() {

	DeleteCmd.AddCommand(DeleteStorageCmd)

}
