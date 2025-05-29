// cmd/delete/process.go
package delete

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// deleteProcessCmd represents the command to delete a process.
var DeleteProcessCmd = &cobra.Command{
	Use:   "process",
	Short: "Delete process",
	Long:  `Delete a process by specifying the target process.`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			otelzap.Ctx(rc.Ctx).Fatal("Please specify the process to delete.")
		}
		process := args[0]
		otelzap.Ctx(rc.Ctx).Info("Deleting process", zap.String("process", process))
		// Add your delete logic here.
		return nil
	}),
}

func init() {

	// Initialize the shared logger for the entire install package
	DeleteCmd.AddCommand(DeleteProcessCmd)

}
