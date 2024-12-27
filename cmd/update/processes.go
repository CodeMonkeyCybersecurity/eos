// cmd/update/processes.go
package update

import (
	"fmt"

	"github.com/spf13/cobra"
)

// updateProcessesCmd handles updating processes
var updateProcessesCmd = &cobra.Command{
	Use:   "processes",
	Short: "Update processes",
	Long:  `Use this command to update details about running processes.`,
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
	CreateCmd.AddCommand(updateProcessesCmd)
}
