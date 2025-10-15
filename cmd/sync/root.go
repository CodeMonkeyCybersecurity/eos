// cmd/sync/root.go
package sync

import (
	"fmt"
	"sort"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/sync"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/sync/connectors"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var (
	syncDryRun        bool
	syncForce         bool
	syncSkipBackup    bool
	syncSkipHealthCheck bool
)

func init() {
	// Register all available connectors
	sync.RegisterConnector(connectors.NewConsulVaultConnector())
	sync.RegisterConnector(connectors.NewConsulTailscaleAutoConnector())
}

// SyncCmd is the root command for service synchronization
var SyncCmd = &cobra.Command{
	Use:   "sync <service1> <service2>",
	Short: "Connect and synchronize two services",
	Long: `Connect and synchronize two services bidirectionally.

The sync command establishes connections between two services, enabling them
to work together. Service order doesn't matter - the command automatically
detects the correct connector to use.

Currently supported service pairs:
  - consul ↔ vault: Configure Vault to use Consul as storage backend,
                    register Vault in Consul service catalog
  - consul ↔ tailscale: Configure local Consul to bind to Tailscale IP
                        (order doesn't matter: "consul tailscale" or "tailscale consul")

For joining Consul nodes into a cluster:
  - eos sync consul --nodes vhost7 vhost11    # Join multiple Consul nodes together
  - See: eos sync consul --help

Safety Features:
  - Pre-flight checks verify both services are installed and running
  - Configuration backups created before any changes (unless --skip-backup)
  - Health validation after synchronization
  - Idempotent operations (safe to run multiple times)
  - Atomic operations with automatic rollback on failure

Examples:
  # Sync Consul and Vault (order doesn't matter)
  eos sync consul vault
  eos sync vault consul

  # Configure local Consul to use Tailscale IP
  eos sync consul tailscale
  eos sync tailscale consul

  # Join Consul nodes into a cluster
  eos sync consul --nodes vhost7
  eos sync consul --nodes vhost7 vhost11 vhost15

  # Preview changes without applying (dry-run)
  eos sync consul vault --dry-run

  # Force sync even if already connected
  eos sync consul vault --force

  # Skip backup (use with caution in development)
  eos sync consul vault --skip-backup

Code Monkey Cybersecurity - "Cybersecurity. With humans."`,
	Args: cobra.ExactArgs(2),
	RunE: eos.Wrap(runSync),
}

func init() {
	SyncCmd.Flags().BoolVar(&syncDryRun, "dry-run", false,
		"Preview changes without applying them")
	SyncCmd.Flags().BoolVar(&syncForce, "force", false,
		"Force sync even if services are already connected")
	SyncCmd.Flags().BoolVar(&syncSkipBackup, "skip-backup", false,
		"Skip configuration backup (use with caution)")
	SyncCmd.Flags().BoolVar(&syncSkipHealthCheck, "skip-health-check", false,
		"Skip health check after synchronization")
}

func runSync(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	service1 := strings.ToLower(strings.TrimSpace(args[0]))
	service2 := strings.ToLower(strings.TrimSpace(args[1]))

	logger.Info("Starting service synchronization",
		zap.String("service1", service1),
		zap.String("service2", service2),
		zap.Bool("dry_run", syncDryRun))

	// Normalize service pair (alphabetical order for consistent lookup)
	servicePair := normalizeServicePair(service1, service2)
	logger.Debug("Normalized service pair",
		zap.String("pair", servicePair))

	// Get connector for this service pair
	connector, err := sync.GetConnector(servicePair)
	if err != nil {
		return eos_err.NewUserError(
			"Service pair not supported: %s ↔ %s\n\n"+
				"Currently supported pairs:\n"+
				"  - consul ↔ vault\n"+
				"  - consul ↔ tailscale (auto-discovers and joins Consul nodes)\n\n"+
				"For explicit node targeting:\n"+
				"  - eos sync consul --vhost7 --vhost11\n\n"+
				"Error: %v",
			service1, service2, err)
	}

	logger.Info("Found connector",
		zap.String("connector", connector.Name()),
		zap.String("description", connector.Description()))

	// Create sync config
	config := &sync.SyncConfig{
		Service1:          service1,
		Service2:          service2,
		DryRun:            syncDryRun,
		Force:             syncForce,
		SkipBackup:        syncSkipBackup,
		SkipHealthCheck:   syncSkipHealthCheck,
	}

	// Execute sync
	if err := sync.ExecuteSync(rc, connector, config); err != nil {
		logger.Error("Service synchronization failed", zap.Error(err))
		return err
	}

	logger.Info("================================================================================")
	logger.Info("Service synchronization completed successfully")
	logger.Info("================================================================================")
	logger.Info("",
		zap.String("service1", service1),
		zap.String("service2", service2))
	logger.Info("")
	logger.Info("Services are now connected and configured to work together")
	logger.Info("")
	logger.Info("Code Monkey Cybersecurity - 'Cybersecurity. With humans.'")
	logger.Info("================================================================================")

	return nil
}

// normalizeServicePair creates a consistent service pair identifier
// by sorting services alphabetically. This allows order-independent lookup.
//
// Examples:
//   normalizeServicePair("consul", "vault") -> "consul-vault"
//   normalizeServicePair("vault", "consul") -> "consul-vault"
func normalizeServicePair(service1, service2 string) string {
	services := []string{service1, service2}
	sort.Strings(services)
	return fmt.Sprintf("%s-%s", services[0], services[1])
}
