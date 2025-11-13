package rollback

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/cephfs"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var (
	// Common flags
	cephMonHosts   []string
	cephUser       string
	cephConfigFile string
	cephUseConsul  bool

	// Rollback flags
	cephSnapshotName   string
	cephSnapshotVolume string
	cephSubVolume      string
)

var rollbackCephCmd = &cobra.Command{
	Use:   "ceph",
	Short: "Rollback Ceph volumes to snapshots",
	Long: `Rollback CephFS volumes to a previous snapshot state.

SAFETY FEATURES:
- Automatic safety snapshot of current state before rollback
- Validation of snapshot existence
- Clone and restore workflow
- Comprehensive logging for audit trail

WARNING: Rollback is a destructive operation. All data changes since the snapshot
will be lost. A safety snapshot of the current state is created automatically.

EXAMPLES:
  # Rollback volume to a snapshot
  eos rollback ceph --snapshot backup-2025 --snapshot-volume mydata

  # Rollback a specific subvolume
  eos rollback ceph --snapshot backup-2025 --snapshot-volume mydata --subvolume app1

WORKFLOW:
  1. Verify snapshot exists
  2. Create safety snapshot of current state (pre-rollback-TIMESTAMP)
  3. Clone snapshot to temporary volume
  4. Wait for clone completion
  5. Swap data (future: currently provides manual instructions)

FLAGS:
  Common:
    --monitors           Ceph monitor addresses
    --user              Ceph user name (default: admin)
    --config            Path to ceph.conf file
    --use-consul        Discover monitors from Consul

  Rollback:
    --snapshot NAME      Snapshot to rollback to (required)
    --snapshot-volume    Volume containing snapshot (required)
    --subvolume NAME     Specific subvolume to rollback (optional)`,

	RunE: eos_cli.Wrap(runCephRollback),
}

func init() {
	// Common flags
	rollbackCephCmd.Flags().StringSliceVar(&cephMonHosts, "monitors", []string{}, "Ceph monitor addresses")
	rollbackCephCmd.Flags().StringVar(&cephUser, "user", "admin", "Ceph user name")
	rollbackCephCmd.Flags().StringVar(&cephConfigFile, "config", "", "Path to ceph.conf file")
	rollbackCephCmd.Flags().BoolVar(&cephUseConsul, "use-consul", false, "Discover monitors from Consul")

	// Rollback flags
	rollbackCephCmd.Flags().StringVar(&cephSnapshotName, "snapshot", "", "Snapshot to rollback to")
	rollbackCephCmd.Flags().StringVar(&cephSnapshotVolume, "snapshot-volume", "", "Volume containing snapshot")
	rollbackCephCmd.Flags().StringVar(&cephSubVolume, "subvolume", "", "Specific subvolume to rollback")

	// Mark required flags
	_ = rollbackCephCmd.MarkFlagRequired("snapshot")        // Error only if flag doesn't exist (build-time error)
	_ = rollbackCephCmd.MarkFlagRequired("snapshot-volume") // Error only if flag doesn't exist (build-time error)

	RollbackCmd.AddCommand(rollbackCephCmd)
}

func runCephRollback(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting CephFS snapshot rollback",
		zap.String("snapshot", cephSnapshotName),
		zap.String("volume", cephSnapshotVolume))

	// Create Ceph client
	logger.Info("Initializing Ceph client")

	clientConfig := &cephfs.ClientConfig{
		MonHosts:      cephMonHosts,
		User:          cephUser,
		ConfigFile:    cephConfigFile,
		ConsulEnabled: cephUseConsul,
	}

	client, err := cephfs.NewCephClient(rc, clientConfig)
	if err != nil {
		return fmt.Errorf("failed to initialize Ceph client: %w", err)
	}
	defer func() { _ = client.Close() }()

	// Perform rollback
	if err := client.RollbackToSnapshot(rc, cephSnapshotVolume, cephSnapshotName, cephSubVolume); err != nil {
		return fmt.Errorf("failed to rollback to snapshot: %w", err)
	}

	logger.Info("Snapshot rollback completed",
		zap.String("snapshot", cephSnapshotName),
		zap.String("volume", cephSnapshotVolume))

	return nil
}
