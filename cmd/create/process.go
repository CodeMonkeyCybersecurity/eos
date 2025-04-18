// cmd/create/processes.go

package create

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/spf13/cobra"
)

// createProcessCmd represents the create command for processes
var CreateProcessCmd = &cobra.Command{
	Use:   "process",
	Short: "Create a new process",
	Long:  `This command allows you to create a new process in the system.`,
	RunE: eos.Wrap(func(ctx *eos.RuntimeContext, cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			log.Fatal("Please provide details to create a process.")
		}
		processDetails := args[0]
		fmt.Printf("Creating process: %s...\n", processDetails)
		// Add your logic to create a process
		return nil
	}),
}

func init() {
	CreateCmd.AddCommand(CreateProcessCmd)
}
