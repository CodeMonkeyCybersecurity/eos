package update

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/ceph"
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

	// Volume update flags
	cephVolumeName           string
	cephVolumeNewSize        int64
	cephVolumeDataPool       string
	cephVolumeNewReplication int

	// Snapshot update flags
	cephSnapshotName      string
	cephSnapshotVolume    string
	cephSnapshotProtect   bool
	cephSnapshotUnprotect bool

	// Pool update flags
	cephPoolName       string
	cephPoolNewSize    int
	cephPoolNewPGNum   int
	cephPoolMaxBytes   int64
	cephPoolMaxObjects int64

	// Safety flags
	cephSkipSnapshot bool

	// Fix flags
	cephFix             bool
	cephDryRun          bool
	cephBootstrapMon    bool
	cephPermissionsOnly bool
)

var updateCephCmd = &cobra.Command{
	Use:   "ceph",
	Short: "Update Ceph resources (volumes, snapshots, pools) or fix drift",
	Long: `Update configuration of CephFS storage resources or apply automated drift corrections.

DRIFT CORRECTION (--fix):
The --fix flag automatically corrects common Ceph configuration drift issues:
- Monitor not bootstrapped → Bootstrap and start monitor
- Services not running → Start systemd services
- Services not enabled → Enable for auto-start on boot
- Permission issues → Fix file/directory permissions

SAFETY FEATURES:
- Automatic safety snapshots before updates (unless --skip-snapshot)
- Validation of new settings before applying
- Rollback capability via snapshots
- Dry-run mode (--dry-run) to preview changes

EXAMPLES:
  # Apply automated drift corrections
  eos update ceph --fix

  # Preview fixes without applying (dry-run)
  eos update ceph --fix --dry-run

  # Bootstrap monitor automatically if needed
  eos update ceph --fix --bootstrap-mon

  # Only fix permissions, don't modify services
  eos update ceph --fix --permissions-only

  # Update volume size
  eos update ceph --volume mydata --size 200GB

  # Update volume replication
  eos update ceph --volume mydata --replication 5 --data-pool mydata_data

  # Protect a snapshot
  eos update ceph --snapshot backup-2025 --snapshot-volume mydata --protect

  # Unprotect a snapshot
  eos update ceph --snapshot backup-2025 --snapshot-volume mydata --unprotect

  # Update pool settings
  eos update ceph --pool mypool --pool-size 5 --pool-pg-num 256

  # Set pool quota
  eos update ceph --pool mypool --max-bytes 1TB --max-objects 1000000

FLAGS:
  Fix/Drift Correction:
    --fix                 Apply automated drift corrections
    --dry-run            Preview fixes without applying
    --bootstrap-mon      Bootstrap monitor if never initialized
    --permissions-only   Only fix permissions, not services

  Common:
    --monitors         Ceph monitor addresses
    --user            Ceph user name (default: admin)
    --config          Path to ceph.conf file
    --use-consul      Discover monitors from Consul

  Volume:
    --volume NAME      Update volume with specified name
    --size BYTES       New volume size
    --replication NUM  New replication size
    --data-pool NAME   Data pool name (for replication update)

  Snapshot:
    --snapshot NAME         Update snapshot with specified name
    --snapshot-volume NAME  Volume containing snapshot
    --protect              Protect snapshot from deletion
    --unprotect            Remove protection from snapshot

  Pool:
    --pool NAME           Update pool with specified name
    --pool-size NUM       New replication size
    --pool-pg-num NUM     New PG number
    --max-bytes NUM       Maximum bytes quota
    --max-objects NUM     Maximum objects quota

  Safety:
    --skip-snapshot       Skip automatic safety snapshot`,

	RunE: eos_cli.Wrap(runCephUpdate),
}

func init() {
	// Common flags
	updateCephCmd.Flags().StringSliceVar(&cephMonHosts, "monitors", []string{}, "Ceph monitor addresses")
	updateCephCmd.Flags().StringVar(&cephUser, "user", "admin", "Ceph user name")
	updateCephCmd.Flags().StringVar(&cephConfigFile, "config", "", "Path to ceph.conf file")
	updateCephCmd.Flags().BoolVar(&cephUseConsul, "use-consul", false, "Discover monitors from Consul")

	// Volume flags
	updateCephCmd.Flags().StringVar(&cephVolumeName, "volume", "", "Update volume with specified name")
	updateCephCmd.Flags().Int64Var(&cephVolumeNewSize, "size", 0, "New volume size in bytes")
	updateCephCmd.Flags().IntVar(&cephVolumeNewReplication, "replication", 0, "New replication size")
	updateCephCmd.Flags().StringVar(&cephVolumeDataPool, "data-pool", "", "Data pool name")

	// Snapshot flags
	updateCephCmd.Flags().StringVar(&cephSnapshotName, "snapshot", "", "Update snapshot with specified name")
	updateCephCmd.Flags().StringVar(&cephSnapshotVolume, "snapshot-volume", "", "Volume containing snapshot")
	updateCephCmd.Flags().BoolVar(&cephSnapshotProtect, "protect", false, "Protect snapshot from deletion")
	updateCephCmd.Flags().BoolVar(&cephSnapshotUnprotect, "unprotect", false, "Remove protection from snapshot")

	// Pool flags
	updateCephCmd.Flags().StringVar(&cephPoolName, "pool", "", "Update pool with specified name")
	updateCephCmd.Flags().IntVar(&cephPoolNewSize, "pool-size", 0, "New replication size")
	updateCephCmd.Flags().IntVar(&cephPoolNewPGNum, "pool-pg-num", 0, "New PG number")
	updateCephCmd.Flags().Int64Var(&cephPoolMaxBytes, "max-bytes", 0, "Maximum bytes quota")
	updateCephCmd.Flags().Int64Var(&cephPoolMaxObjects, "max-objects", 0, "Maximum objects quota")

	// Safety flags
	updateCephCmd.Flags().BoolVar(&cephSkipSnapshot, "skip-snapshot", false, "Skip automatic safety snapshot")

	// Fix flags
	updateCephCmd.Flags().BoolVar(&cephFix, "fix", false, "Apply automated drift corrections")
	updateCephCmd.Flags().BoolVar(&cephDryRun, "dry-run", false, "Preview fixes without applying")
	updateCephCmd.Flags().BoolVar(&cephBootstrapMon, "bootstrap-mon", false, "Bootstrap monitor if never initialized")
	updateCephCmd.Flags().BoolVar(&cephPermissionsOnly, "permissions-only", false, "Only fix permissions, not services")

	UpdateCmd.AddCommand(updateCephCmd)
}

func runCephUpdate(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if this is a fix operation
	if cephFix {
		return runCephFix(rc)
	}

	// Determine what to update based on flags
	if cephVolumeName == "" && cephSnapshotName == "" && cephPoolName == "" {
		return fmt.Errorf("must specify one of: --volume, --snapshot, --pool, or --fix")
	}

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

	// Execute requested operation
	if cephVolumeName != "" {
		return updateVolume(rc, client)
	}

	if cephSnapshotName != "" {
		return updateSnapshot(rc, client)
	}

	if cephPoolName != "" {
		return updatePool(rc, client)
	}

	return nil
}

func updateVolume(rc *eos_io.RuntimeContext, client *cephfs.CephClient) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Updating CephFS volume",
		zap.String("volume", cephVolumeName),
		zap.Bool("skipSnapshot", cephSkipSnapshot))

	opts := &cephfs.VolumeUpdateOptions{
		NewSize:        cephVolumeNewSize,
		NewReplication: cephVolumeNewReplication,
		DataPool:       cephVolumeDataPool,
		SkipSnapshot:   cephSkipSnapshot,
	}

	if err := client.UpdateVolume(rc, cephVolumeName, opts); err != nil {
		return fmt.Errorf("failed to update volume: %w", err)
	}

	logger.Info("Volume updated successfully",
		zap.String("volume", cephVolumeName))

	return nil
}

func updateSnapshot(rc *eos_io.RuntimeContext, client *cephfs.CephClient) error {
	logger := otelzap.Ctx(rc.Ctx)

	if cephSnapshotVolume == "" {
		return fmt.Errorf("--snapshot-volume is required when updating a snapshot")
	}

	if !cephSnapshotProtect && !cephSnapshotUnprotect {
		return fmt.Errorf("must specify either --protect or --unprotect")
	}

	if cephSnapshotProtect && cephSnapshotUnprotect {
		return fmt.Errorf("cannot specify both --protect and --unprotect")
	}

	if cephSnapshotProtect {
		logger.Info("Protecting CephFS snapshot",
			zap.String("snapshot", cephSnapshotName),
			zap.String("volume", cephSnapshotVolume))

		if err := client.ProtectSnapshot(rc, cephSnapshotVolume, cephSnapshotName, ""); err != nil {
			return fmt.Errorf("failed to protect snapshot: %w", err)
		}

		logger.Info("Snapshot protected successfully",
			zap.String("snapshot", cephSnapshotName))
	}

	if cephSnapshotUnprotect {
		logger.Info("Unprotecting CephFS snapshot",
			zap.String("snapshot", cephSnapshotName),
			zap.String("volume", cephSnapshotVolume))

		if err := client.UnprotectSnapshot(rc, cephSnapshotVolume, cephSnapshotName, ""); err != nil {
			return fmt.Errorf("failed to unprotect snapshot: %w", err)
		}

		logger.Info("Snapshot unprotected successfully",
			zap.String("snapshot", cephSnapshotName))
	}

	return nil
}

func updatePool(rc *eos_io.RuntimeContext, client *cephfs.CephClient) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Updating Ceph pool",
		zap.String("pool", cephPoolName))

	opts := &cephfs.PoolUpdateOptions{
		NewSize:    cephPoolNewSize,
		NewPGNum:   cephPoolNewPGNum,
		MaxBytes:   cephPoolMaxBytes,
		MaxObjects: cephPoolMaxObjects,
	}

	if err := client.UpdatePool(rc, cephPoolName, opts); err != nil {
		return fmt.Errorf("failed to update pool: %w", err)
	}

	logger.Info("Pool updated successfully",
		zap.String("pool", cephPoolName))

	return nil
}

// runCephFix runs the automated drift correction engine
func runCephFix(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting Ceph drift correction...")

	// Create fix options
	opts := ceph.FixOptions{
		DryRun:          cephDryRun,
		PermissionsOnly: cephPermissionsOnly,
		BootstrapMon:    cephBootstrapMon,
		RestartServices: true, // Always restart services after fixes
	}

	// Create fix engine
	engine := ceph.NewFixEngine(rc, opts)

	// Run fixes
	results, err := engine.RunFixes()
	if err != nil {
		return fmt.Errorf("fix engine failed: %w", err)
	}

	// Check if any fixes failed
	failedCount := 0
	for _, result := range results {
		if result.Applied && !result.Success {
			failedCount++
		}
	}

	if failedCount > 0 {
		return fmt.Errorf("%d fix(es) failed - see output above for details", failedCount)
	}

	if cephDryRun {
		logger.Info("")
		logger.Info("DRY RUN completed successfully")
		logger.Info("Run without --dry-run to apply these fixes")
	} else {
		logger.Info("")
		logger.Info("Drift correction completed successfully")
	}

	return nil
}
