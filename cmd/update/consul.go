// cmd/update/consul.go
package update

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var (
	consulPorts  string
	consulDryRun bool
)

// ConsulCmd updates Consul configuration
var ConsulCmd = &cobra.Command{
	Use:   "consul",
	Short: "Update Consul configuration",
	Long: `Update Consul's configuration by modifying settings and restarting the service.

The command intelligently updates:
1. Consul HCL configuration file (/etc/consul.d/consul.hcl)
2. Restarts Consul service to apply changes
3. Verifies new configuration is accessible

Examples:
  # Change HTTP port from current to HashiCorp default
  eos update consul --ports 8161 -> default
  eos update consul --ports 8161 -> 8500

  # Change DNS port
  eos update consul --ports 8389 -> 8600

  # Preview changes without applying
  eos update consul --ports 8161 -> default --dry-run

The "default" keyword uses HashiCorp standard ports:
  - HTTP port: 8500
  - DNS port: 8600
  - RPC port: 8300
  - Serf LAN: 8301
  - Serf WAN: 8302

Syntax: --ports FROM -> TO
  FROM: Current port number (or "default")
  TO: New port number (or "default")

Code Monkey Cybersecurity - "Cybersecurity. With humans."`,
	RunE: eos.Wrap(runConsulUpdate),
}

func init() {
	ConsulCmd.Flags().StringVar(&consulPorts, "ports", "",
		"Port migration in format: FROM -> TO (e.g., '8161 -> default' or '8161 -> 8500')")
	ConsulCmd.Flags().BoolVar(&consulDryRun, "dry-run", false,
		"Preview changes without applying them")
}

func runConsulUpdate(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Validate ports flag is specified
	if consulPorts == "" {
		return eos_err.NewUserError(
			"Port migration must be specified.\n\n" +
				"Examples:\n" +
				"  eos update consul --ports 8161 -> default\n" +
				"  eos update consul --ports 8161 -> 8500\n" +
				"  eos update consul --ports 8389 -> 8600")
	}

	logger.Info("Starting Consul update",
		zap.String("ports", consulPorts),
		zap.Bool("dry_run", consulDryRun))

	// Parse port migration syntax (business logic in pkg/)
	portMigration, err := consul.ParsePortMigrationSyntax(consulPorts)
	if err != nil {
		return err
	}

	// Prepare configuration for update
	updateConfig := &consul.UpdatePortsConfig{
		PortMigration: portMigration,
		DryRun:        consulDryRun,
		ConfigPath:    "/etc/consul.d/consul.hcl",
	}

	// Delegate to business logic in pkg/consul
	return consul.UpdateConsulPorts(rc, updateConfig)
}
