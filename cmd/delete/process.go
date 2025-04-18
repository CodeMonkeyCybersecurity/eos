// cmd/delete/process.go
package delete

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// deleteProcessCmd represents the command to delete a process.
var DeleteProcessCmd = &cobra.Command{
	Use:   "process",
	Short: "Delete process",
	Long:  `Delete a process by specifying the target process.`,
	RunE: eos.Wrap(func(ctx *eos.RuntimeContext, cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			log.Fatal("Please specify the process to delete.")
		}
		process := args[0]
		log.Info("Deleting process", zap.String("process", process))
		// Add your delete logic here.
		return nil
	}),
}

func init() {

	// Initialize the shared logger for the entire install package
	DeleteCmd.AddCommand(DeleteProcessCmd)

}
