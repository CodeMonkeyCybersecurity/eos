package service

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/internal/service"
	eos_cli "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// HealthCmd reports health status for a service definition.
var HealthCmd = &cobra.Command{
	Use:   "health <service>",
	Short: "Evaluate the declared health check for a service",
	Long: `Loads the service definition and surfaces the configured health check.
Runtime health probing is still under implementation. In the interim this
command confirms the configuration is discoverable and ready for future tests.`,
	Args: cobra.ExactArgs(1),
	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		serviceName := args[0]
		def, err := service.LoadDefinition(serviceName)
		if err != nil {
			return err
		}

		rc.Log.Info("Service health definition detected",
			zap.String("service", def.Name),
			zap.String("health_type", def.HealthCheck.Type),
			zap.String("health_url", def.HealthCheck.URL),
		)

		cmd.Println(fmt.Sprintf("Health check (%s): %s", def.HealthCheck.Type, def.HealthCheck.URL))
		cmd.Println("Warning: automated health execution pending implementation; tracked in roadmap.")
		return nil
	}),
}
