// cmd/create/storage.go
package create

import (
	"fmt"

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
		logger := otelzap.Ctx(rc.Ctx)
		if len(args) < 1 {
			logger.Fatal("Please specify the storage details to create.")
		}
		storageDetails := args[0]
		logger.Info(fmt.Sprintf("terminal prompt: Creating storage: %s...", storageDetails))
		// Add your logic to create storage resources
		return nil
	}),
}

func init() {
	CreateCmd.AddCommand(CreateStorageCmd)
}
