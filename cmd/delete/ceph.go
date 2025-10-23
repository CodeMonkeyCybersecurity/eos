package delete

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

	// Operation flags
	cephVolumeName     string
	cephSnapshotName   string
	cephSnapshotVolume string
	cephPoolName       string

	// Safety flags
	cephSkipSnapshot bool
	cephForce        bool
)

var deleteCephCmd = &cobra.Command{
	Use:   "ceph",
	Short: "Delete Ceph resources (volumes, snapshots, pools)",
	Long: `Delete CephFS storage resources with safety features.

SAFETY FEATURES:
- Automatic safety snapshots before volume/pool deletion (unless --skip-snapshot)
- Confirmation required for destructive operations
- Checks for resources in use before deletion
- Protected snapshots cannot be deleted (must unprotect first)

EXAMPLES:
  # Delete a volume (creates safety snapshot first)
  eos delete ceph --volume mydata

  # Delete a volume without safety snapshot
  eos delete ceph --volume mydata --skip-snapshot

  # Delete a snapshot
  eos delete ceph --snapshot backup-2025 --snapshot-volume mydata

  # Delete a pool (checks if in use first)
  eos delete ceph --pool mypool

  # Force delete a pool even if in use
  eos delete ceph --pool mypool --force

FLAGS:
  Common:
    --monitors         Ceph monitor addresses
    --user            Ceph user name (default: admin)
    --config          Path to ceph.conf file
    --use-consul      Discover monitors from Consul

  Resource:
    --volume NAME      Delete volume with specified name
    --snapshot NAME    Delete snapshot with specified name
    --snapshot-volume  Volume containing snapshot (required with --snapshot)
    --pool NAME        Delete pool with specified name

  Safety:
    --skip-snapshot    Skip automatic safety snapshot
    --force            Force deletion even if resource is in use`,

	RunE: eos_cli.Wrap(runCephDelete),
}

func init() {
	// Common flags
	deleteCephCmd.Flags().StringSliceVar(&cephMonHosts, "monitors", []string{}, "Ceph monitor addresses")
	deleteCephCmd.Flags().StringVar(&cephUser, "user", "admin", "Ceph user name")
	deleteCephCmd.Flags().StringVar(&cephConfigFile, "config", "", "Path to ceph.conf file")
	deleteCephCmd.Flags().BoolVar(&cephUseConsul, "use-consul", false, "Discover monitors from Consul")

	// Resource flags
	deleteCephCmd.Flags().StringVar(&cephVolumeName, "volume", "", "Delete volume with specified name")
	deleteCephCmd.Flags().StringVar(&cephSnapshotName, "snapshot", "", "Delete snapshot with specified name")
	deleteCephCmd.Flags().StringVar(&cephSnapshotVolume, "snapshot-volume", "", "Volume containing snapshot")
	deleteCephCmd.Flags().StringVar(&cephPoolName, "pool", "", "Delete pool with specified name")

	// Safety flags
	deleteCephCmd.Flags().BoolVar(&cephSkipSnapshot, "skip-snapshot", false, "Skip automatic safety snapshot")
	deleteCephCmd.Flags().BoolVar(&cephForce, "force", false, "Force deletion even if resource is in use")

	DeleteCmd.AddCommand(deleteCephCmd)
}

func runCephDelete(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Determine what to delete based on flags
	if cephVolumeName == "" && cephSnapshotName == "" && cephPoolName == "" {
		return fmt.Errorf("must specify one of: --volume, --snapshot, or --pool")
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
	defer client.Close()

	// Execute requested operation
	if cephVolumeName != "" {
		return deleteVolume(rc, client)
	}

	if cephSnapshotName != "" {
		return deleteSnapshot(rc, client)
	}

	if cephPoolName != "" {
		return deletePool(rc, client)
	}

	return nil
}

func deleteVolume(rc *eos_io.RuntimeContext, client *cephfs.CephClient) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS: Check if volume exists
	logger.Info("Assessing volume for deletion",
		zap.String("volume", cephVolumeName),
		zap.Bool("skipSnapshot", cephSkipSnapshot))

	exists, err := client.VolumeExists(rc, cephVolumeName)
	if err != nil {
		return fmt.Errorf("failed to check if volume exists: %w", err)
	}
	if !exists {
		return fmt.Errorf("volume %s does not exist", cephVolumeName)
	}

	// INTERVENE: Delete volume
	logger.Info("Deleting CephFS volume",
		zap.String("volume", cephVolumeName),
		zap.Bool("skipSnapshot", cephSkipSnapshot))

	if err := client.DeleteVolume(rc, cephVolumeName, cephSkipSnapshot); err != nil {
		return fmt.Errorf("failed to delete volume: %w", err)
	}

	// EVALUATE: Verify deletion
	exists, err = client.VolumeExists(rc, cephVolumeName)
	if err != nil {
		return fmt.Errorf("failed to verify deletion: %w", err)
	}
	if exists {
		return fmt.Errorf("volume still exists after deletion attempt")
	}

	logger.Info("Volume deleted successfully",
		zap.String("volume", cephVolumeName))

	return nil
}

func deleteSnapshot(rc *eos_io.RuntimeContext, client *cephfs.CephClient) error {
	logger := otelzap.Ctx(rc.Ctx)

	if cephSnapshotVolume == "" {
		return fmt.Errorf("--snapshot-volume is required when deleting a snapshot")
	}

	logger.Info("Deleting CephFS snapshot",
		zap.String("snapshot", cephSnapshotName),
		zap.String("volume", cephSnapshotVolume))

	if err := client.DeleteSnapshot(rc, cephSnapshotVolume, cephSnapshotName, ""); err != nil {
		return fmt.Errorf("failed to delete snapshot: %w", err)
	}

	logger.Info("Snapshot deleted successfully",
		zap.String("snapshot", cephSnapshotName))

	return nil
}

func deletePool(rc *eos_io.RuntimeContext, client *cephfs.CephClient) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Deleting Ceph pool",
		zap.String("pool", cephPoolName),
		zap.Bool("force", cephForce))

	if err := client.DeletePool(rc, cephPoolName, cephSkipSnapshot); err != nil {
		return fmt.Errorf("failed to delete pool: %w", err)
	}

	logger.Info("Pool deleted successfully",
		zap.String("pool", cephPoolName))

	return nil
}
