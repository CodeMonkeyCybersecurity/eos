// cmd/sync/sync.go
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

// TODO: refactor
var (
	syncDryRun          bool
	syncForce           bool
	syncSkipBackup      bool
	syncSkipHealthCheck bool
	// Service flags
	syncConsul    bool
	syncVault     bool
	syncTailscale bool
	syncAuthentik bool
	syncWazuh     bool
	syncDocker    bool
)

func init() {
	// Register all available connectors
	sync.RegisterConnector(connectors.NewConsulVaultConnector())
	sync.RegisterConnector(connectors.NewConsulTailscaleAutoConnector())
	sync.RegisterConnector(connectors.NewAuthentikWazuhConnector())
	sync.RegisterConnector(connectors.NewWazuhDockerConnector())
}

// SyncCmd is the root command for service synchronization
var SyncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Connect and synchronize two services",
	Long: `Connect and synchronize two services bidirectionally.

The sync command establishes connections between two services, enabling them
to work together using service flags. The command automatically detects the
correct connector to use based on which services are specified.

Currently supported service pairs:
  - --consul --vault: Enable Vault Consul secrets engine for dynamic token generation,
                      register Vault in Consul service catalog (Pattern 3: Raft + Secrets Engine)
  - --consul --tailscale: Configure local Consul to bind to Tailscale IP
  - --authentik --wazuh: Configure Wazuh SSO integration with Authentik
  - --wazuh --docker: Configure Wazuh DockerListener for container event monitoring

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
  # Sync Consul and Vault
  eos sync --consul --vault

  # Configure local Consul to use Tailscale IP
  eos sync --consul --tailscale

  # Configure Wazuh SSO with Authentik
  eos sync --authentik --wazuh

  # Enable Wazuh Docker container monitoring
  eos sync --wazuh --docker

  # Preview changes without applying (dry-run)
  eos sync --consul --vault --dry-run

  # Force sync even if already connected
  eos sync --consul --vault --force

  # Skip backup (use with caution in development)
  eos sync --consul --vault --skip-backup

Code Monkey Cybersecurity - "Cybersecurity. With humans."`,
	Args: cobra.NoArgs,
	RunE: eos.Wrap(runSync),
}

func init() {
	// Service selection flags
	SyncCmd.Flags().BoolVar(&syncConsul, "consul", false,
		"Sync Consul service")
	SyncCmd.Flags().BoolVar(&syncVault, "vault", false,
		"Sync Vault service")
	SyncCmd.Flags().BoolVar(&syncTailscale, "tailscale", false,
		"Sync Tailscale service")
	SyncCmd.Flags().BoolVar(&syncAuthentik, "authentik", false,
		"Sync Authentik service")
	SyncCmd.Flags().BoolVar(&syncWazuh, "wazuh", false,
		"Sync Wazuh service")
	SyncCmd.Flags().BoolVar(&syncDocker, "docker", false,
		"Sync Docker container monitoring with Wazuh")

	// Operation flags
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

	// Collect selected services from flags
	var selectedServices []string
	if syncConsul {
		selectedServices = append(selectedServices, "consul")
	}
	if syncVault {
		selectedServices = append(selectedServices, "vault")
	}
	if syncTailscale {
		selectedServices = append(selectedServices, "tailscale")
	}
	if syncAuthentik {
		selectedServices = append(selectedServices, "authentik")
	}
	if syncWazuh {
		selectedServices = append(selectedServices, "wazuh")
	}
	if syncDocker {
		selectedServices = append(selectedServices, "docker")
	}

	// Validate exactly 2 services selected
	if len(selectedServices) == 0 {
		return eos_err.NewUserError(
			"No services specified. Please specify exactly 2 services to sync.\n\n" +
				"Available services: --consul, --vault, --tailscale, --authentik, --wazuh, --docker\n\n" +
				"Examples:\n" +
				"  eos sync --consul --vault\n" +
				"  eos sync --authentik --wazuh\n" +
				"  eos sync --consul --tailscale")
	}
	if len(selectedServices) == 1 {
		return eos_err.NewUserError(
			"Only one service specified (%s). Please specify exactly 2 services to sync.\n\n"+
				"Examples:\n"+
				"  eos sync --consul --vault\n"+
				"  eos sync --authentik --wazuh",
			selectedServices[0])
	}
	if len(selectedServices) > 2 {
		return eos_err.NewUserError(
			"Too many services specified (%d). Please specify exactly 2 services to sync.\n\n"+
				"You specified: %s",
			len(selectedServices), strings.Join(selectedServices, ", "))
	}

	service1 := selectedServices[0]
	service2 := selectedServices[1]

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
				"  - consul ↔ tailscale (auto-discovers and joins Consul nodes)\n"+
				"  - docker ↔ wazuh (configures Wazuh DockerListener)\n\n"+
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
		Service1:        service1,
		Service2:        service2,
		DryRun:          syncDryRun,
		Force:           syncForce,
		SkipBackup:      syncSkipBackup,
		SkipHealthCheck: syncSkipHealthCheck,
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

// TODO: refactor
// normalizeServicePair creates a consistent service pair identifier
// by sorting services alphabetically. This allows order-independent lookup.
//
// Examples:
//
//	normalizeServicePair("consul", "vault") -> "consul-vault"
//	normalizeServicePair("vault", "consul") -> "consul-vault"
func normalizeServicePair(service1, service2 string) string {
	services := []string{service1, service2}
	sort.Strings(services)
	return fmt.Sprintf("%s-%s", services[0], services[1])
}
