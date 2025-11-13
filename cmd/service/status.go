package service

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/internal/service"
	eos_cli "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
)

// StatusCmd will expose service execution status once state management lands.
var StatusCmd = &cobra.Command{
	Use:   "status <service>",
	Short: "Show stored initialization status for a service",
	Long: `Displays high-level information about an initialization run once state
tracking is implemented. At present the command simply confirms the definition
can be loaded and communicates the implementation roadmap.`,
	Args: cobra.ExactArgs(1),
	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		serviceName := args[0]
		def, err := service.LoadDefinition(serviceName)
		if err != nil {
			return err
		}

		cmd.Println(fmt.Sprintf("Service %s has %d declared steps.", def.Name, len(def.Initialization.Steps)))
		cmd.Println("State tracking is not yet available; roadmap entries will enable persisted status.")
		return nil
	}),
}
