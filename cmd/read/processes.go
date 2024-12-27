// cmd/read/processes.go
package read

import (
	"fmt"

	"github.com/spf13/cobra"
)

// readProcessesCmd represents the command to read processes
var readProcessesCmd = &cobra.Command{
	Use:   "processes",
	Short: "Read processes",
	Long:  `Retrieve information about processes.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Reading processes...")
		// Add your read logic here
	},
}
