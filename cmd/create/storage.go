// cmd/create/storage.go
package create

import (

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

// createStorageCmd represents the create command for storage
var CreateStorageCmd = &cobra.Command{
	Use:   "storage",
	Short: "Create new storage resources",
	Long:  `This command allows you to create new storage resources in the eos_unix.`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			otelzap.Ctx(rc.Ctx).Fatal("Please specify the storage details to create.")
		}
		storageDetails := args[0]
		logger.Info("terminal prompt: Creating storage: %s...", storageDetails)
		// Add your logic to create storage resources
		return nil
	}),
}

func init() {
	CreateCmd.AddCommand(CreateStorageCmd)
}
