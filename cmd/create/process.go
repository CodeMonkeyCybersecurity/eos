// cmd/create/processes.go

package create

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

// createProcessCmd represents the create command for processes
var CreateProcessCmd = &cobra.Command{
	Use:   "process",
	Short: "Create a new process",
	Long:  `This command allows you to create a new process in the eos_unix.`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		if len(args) < 1 {
			logger.Fatal("Please provide details to create a process.")
		}
		processDetails := args[0]
		logger.Info(fmt.Sprintf("terminal prompt: Creating process: %s...", processDetails))
		// Add your logic to create a process
		return nil
	}),
}

func init() {
	CreateCmd.AddCommand(CreateProcessCmd)
}
