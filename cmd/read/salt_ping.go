// cmd/read/salt_ping.go
package read

import (
	"fmt"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var consulHealthCmd = &cobra.Command{
	Use:     "consul-health [service]",
	Aliases: []string{"health-check", "consul-ping"},
	Short:   "Check Consul service health and connectivity",
	Long: `Check Consul service health and connectivity across the cluster.

This command queries Consul for service health status and reports
which services are healthy and responsive. It's useful for checking
service health before running operations.

Examples:
  eos read consul-health                         # Check all services
  eos read consul-health web                     # Check web services
  eos read consul-health --node web01            # Check specific node
  eos read consul-health --datacenter dc1        # Check specific datacenter
  
Health States:
  passing  - Service is healthy
  warning  - Service has warnings
  critical - Service is unhealthy
  maintenance - Service is in maintenance mode`,

	Args: cobra.MaximumNArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		// Parse service - default to all services if not provided
		service := ""
		if len(args) > 0 {
			service = args[0]
		}

		// Parse flags
		node, _ := cmd.Flags().GetString("node")
		datacenter, _ := cmd.Flags().GetString("datacenter")
		timeout, _ := cmd.Flags().GetDuration("timeout")
		_, _ = cmd.Flags().GetBool("json")
		_, _ = cmd.Flags().GetBool("verbose")

		logger.Info("Checking Consul service health",
			zap.String("service", service),
			zap.String("node", node),
			zap.String("datacenter", datacenter),
			zap.Duration("timeout", timeout))

		// TODO: Implement Consul health check integration
		logger.Info("terminal prompt: Consul health check not yet implemented")
		logger.Info("terminal prompt: Service:", zap.String("service", service))
		logger.Info("terminal prompt: Use 'consul members' and 'consul catalog services' directly for now")
		return fmt.Errorf("Consul health check integration pending - use consul CLI directly")
	}),
}

func init() {
	consulHealthCmd.Flags().String("node", "", "Check specific node")
	consulHealthCmd.Flags().String("datacenter", "", "Check specific datacenter")
	consulHealthCmd.Flags().Duration("timeout", 10*time.Second, "Timeout for health check")
	consulHealthCmd.Flags().Bool("json", false, "Output results in JSON format")
	consulHealthCmd.Flags().BoolP("verbose", "v", false, "Verbose output with detailed health information")

	ReadCmd.AddCommand(consulHealthCmd)
}
