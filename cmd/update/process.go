// cmd/update/process.go
package update

import (
	"fmt"

	"github.com/spf13/cobra"
)

// updateProcessCmd handles updating process
var updateProcessCmd = &cobra.Command{
	Use:   "process",
	Short: "Update process",
	Long:  `Use this command to update details about running process.`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			fmt.Println("Please specify the process to update.")
			return
		}
		process := args[0]
		fmt.Printf("Updating process: %s\n", process)
		// Add your logic here
	},
}

func init() {
	UpdateCmd.AddCommand(updateProcessCmd)
}
