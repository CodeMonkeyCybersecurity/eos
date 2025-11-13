// cmd/inspect/process.go
package read

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ReadProcessesCmd represents the command to read processes
var ReadProcessesCmd = &cobra.Command{
	Use:   "process",
	Short: "Retrieve detailed information about running processes",
	Long: `This command retrieves detailed information about all running processes on the system
by reading the /proc directory and outputs it in a table format.`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {

		otelzap.Ctx(rc.Ctx).Info("Executing read process command", zap.Strings("args", args))

		// Retrieve process details
		process, err := eos_unix.GetProcessDetails(rc.Ctx)
		if err != nil {
			otelzap.Ctx(rc.Ctx).Error("Failed to retrieve process details", zap.Error(err))
			return err
		}

		// Log success and print the process table
		otelzap.Ctx(rc.Ctx).Info("Successfully retrieved process details", zap.Int("processCount", len(process)))
		eos_unix.PrintProcessTable(rc.Ctx, process)
		return nil
	}),
}

/* init registers subcommands for the read command */
func init() {
	ReadCmd.AddCommand(ReadProcessesCmd)
}
