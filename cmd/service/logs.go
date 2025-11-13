package service

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/internal/service"
	eos_cli "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
)

// LogsCmd will stream initialization logs once persisted log routing exists.
var LogsCmd = &cobra.Command{
	Use:   "logs <service>",
	Short: "View initialization logs for a service",
	Long: `Streams initialization logs recorded by the service executor. Logging
persistence is slated for a follow-up milestone, so this command currently
just verifies the definition exists and points to the roadmap for details.`,
	Args: cobra.ExactArgs(1),
	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		serviceName := args[0]
		_, err := service.LoadDefinition(serviceName)
		if err != nil {
			return err
		}

		cmd.Println(fmt.Sprintf("Log streaming for %s is scheduled in the upcoming roadmap milestone.", serviceName))
		return nil
	}),
}
