// cmd/create/processes.go
package create

import (
	"fmt"
	"log"

	"github.com/spf13/cobra"
)

// createProcessCmd represents the create command for processes
var createProcessCmd = &cobra.Command{
	Use:   "process",
	Short: "Create a new process",
	Long:  `This command allows you to create a new process in the system.`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			log.Fatalf("Please provide details to create a process.")
		}
		processDetails := args[0]
		fmt.Printf("Creating process: %s...\n", processDetails)
		// Add your logic to create a process
	},
}

func init() {
	CreateCmd.AddCommand(createProcessCmd)
}
