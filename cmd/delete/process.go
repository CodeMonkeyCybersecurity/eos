// cmd/delete/process.go
package delete

import (
	"fmt"

	"github.com/spf13/cobra"
)

// deleteProcessesCmd represents the command to delete process
var deleteProcessCmd = &cobra.Command{
	Use:   "process",
	Short: "Delete process",
	Long:  `Delete process by specifying the target process.`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			fmt.Println("Please specify the process to delete.")
			return
		}
		process := args[0]
		fmt.Printf("Deleting process: %s...\n", process)
		// Add your delete logic here
	},
}
