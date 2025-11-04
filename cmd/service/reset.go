package service

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/internal/service"
	eos_cli "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
)

// ResetCmd will clear service state files once state manager lands.
var ResetCmd = &cobra.Command{
	Use:   "reset <service>",
	Short: "Reset initialization state for a service",
	Long: `Resets the stored state for a service once persisted execution tracking
has been introduced. For now it validates that the definition can be located
and informs the operator where roadmap work will deliver full support.`,
	Args: cobra.ExactArgs(1),
	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		serviceName := args[0]
		_, err := service.LoadDefinition(serviceName)
		if err != nil {
			return err
		}

		cmd.Println(fmt.Sprintf("State reset for %s is not yet implemented. See ROADMAP.md for schedule.", serviceName))
		return nil
	}),
}
