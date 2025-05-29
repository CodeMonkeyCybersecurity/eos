// cmd/update/process.go
package update

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
)

// updateProcessCmd handles updating process
var UpdateProcessCmd = &cobra.Command{
	Use:   "process",
	Short: "Update process",
	Long:  `Use this command to update details about running process.`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			fmt.Println("Please specify the process to update.")
			return nil
		}
		process := args[0]
		fmt.Printf("Updating process: %s\n", process)
		// Add your logic here
		return nil
	}),
}

func init() {
	UpdateCmd.AddCommand(UpdateProcessCmd)
}
