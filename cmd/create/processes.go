// cmd/create/processes.go
package create

import (
	"fmt"
	"log"

	"github.com/spf13/cobra"
)

// createProcessesCmd represents the create command for processes
var createProcessesCmd = &cobra.Command{
	Use:   "processes",
	Short: "Create new processes",
	Long:  `This command allows you to create new processes in the system.`,
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
	CreateCmd.AddCommand(createProcessesCmd)
}
