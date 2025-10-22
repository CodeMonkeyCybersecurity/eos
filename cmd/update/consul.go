// cmd/update/consul.go
package update

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul"
	consulfix "github.com/CodeMonkeyCybersecurity/eos/pkg/consul/fix"
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
	consulFix    bool
)

// ConsulCmd updates Consul configuration
var ConsulCmd = &cobra.Command{
	Use:   "consul",
	Short: "Update Consul configuration",
	Long: `Update Consul's configuration by modifying settings and restarting the service.

The command intelligently updates:
1. Consul HCL configuration file (/etc/consul.d/consul.hcl)
2. Configuration drift correction (--fix)
3. Restarts Consul service to apply changes
4. Verifies new configuration is accessible

Configuration Drift Correction:
  --fix       Detect and correct drift from canonical state
  --dry-run   Preview changes without applying (works with --fix and --ports)

  The --fix flag compares current Consul installation against the canonical
  state from 'eos create consul' and automatically corrects:
  - File permissions (config, data directories)
  - File ownership (consul user/group)
  - Missing helper scripts
  - Systemd service configuration

  Like combing through the configuration to correct any settings that drifted.

Examples:
  # Detect and fix all configuration drift
  eos update consul --fix

  # Show what would be fixed (dry-run)
  eos update consul --fix --dry-run

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
		"Preview changes without applying them (works with --fix and --ports)")
	ConsulCmd.Flags().BoolVar(&consulFix, "fix", false,
		"Fix configuration drift from canonical state (use --dry-run to preview)")
}

func runConsulUpdate(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Count operations (--dry-run is a modifier, not an operation)
	operationCount := 0
	if consulFix {
		operationCount++
	}
	if consulPorts != "" {
		operationCount++
	}

	// Only allow ONE operation at a time
	if operationCount > 1 {
		return eos_err.NewUserError(
			"Cannot specify multiple operations simultaneously.\n\n" +
				"Choose ONE of:\n" +
				"  --fix     Fix configuration drift\n" +
				"  --ports   Migrate ports\n\n" +
				"Use --dry-run to preview changes for any operation.\n\n" +
				"Examples:\n" +
				"  eos update consul --fix\n" +
				"  eos update consul --fix --dry-run\n" +
				"  eos update consul --ports 8161 -> default --dry-run")
	}

	// Handle --fix flag (configuration drift correction)
	if consulFix {
		logger.Info("Running configuration drift correction",
			zap.Bool("dry_run", consulDryRun))

		// Delegate to pkg/consul/fix - same logic as 'eos fix consul'
		config := &consulfix.Config{
			DryRun:          consulDryRun,
			PermissionsOnly: false,
			SkipRestart:     false,
		}

		return consulfix.RunFixes(rc, config)
	}

	// Validate ports flag is specified
	if consulPorts == "" {
		return eos_err.NewUserError(
			"Must specify either --ports or --fix.\n\n" +
				"Fix configuration drift:\n" +
				"  eos update consul --fix\n" +
				"  eos update consul --fix --dry-run  (preview without applying)\n\n" +
				"Port migration:\n" +
				"  eos update consul --ports 8161 -> default\n" +
				"  eos update consul --ports 8161 -> 8500 --dry-run\n" +
				"  eos update consul --ports 8389 -> 8600")
	}

	logger.Info("Starting Consul port update",
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
