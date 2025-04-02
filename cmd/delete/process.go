// cmd/delete/process.go
package delete

import (
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// deleteProcessCmd represents the command to delete a process.
var DeleteProcessCmd = &cobra.Command{
	Use:   "process",
	Short: "Delete process",
	Long:  `Delete a process by specifying the target process.`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			log.Fatal("Please specify the process to delete.")
		}
		process := args[0]
		log.Info("Deleting process", zap.String("process", process))
		// Add your delete logic here.
	},
}

func init() {

	// Initialize the shared logger for the entire install package
	DeleteCmd.AddCommand(DeleteProcessCmd)

}
