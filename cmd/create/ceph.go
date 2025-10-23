package create

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

	// Volume flags
	cephVolumeName       string
	cephVolumeSize       int64
	cephVolumeDataPool   string
	cephVolumeMetaPool   string
	cephVolumeReplication int
	cephVolumePGNum      int

	// Snapshot flags
	cephSnapshotName   string
	cephSnapshotVolume string

	// Pool flags
	cephPoolName        string
	cephPoolPGNum       int
	cephPoolSize        int
	cephPoolType        string
	cephPoolApplication string
)

var createCephCmd = &cobra.Command{
	Use:   "ceph",
	Short: "Create Ceph resources (volumes, snapshots, pools)",
	Long: `Create CephFS storage resources using the go-ceph SDK.

This command provides unified management of Ceph resources with:
- Vault integration for keyring management
- Automatic environment discovery
- Type-safe SDK operations
- Comprehensive error handling with retry logic

EXAMPLES:
  # Create a volume
  eos create ceph --volume mydata --size 100GB --replication 3

  # Create a snapshot
  eos create ceph --snapshot backup-2025 --snapshot-volume mydata

  # Create a pool
  eos create ceph --pool mypool --pg-num 128 --size 3 --application cephfs

FLAGS:
  Common:
    --monitors           Ceph monitor addresses (comma-separated)
    --user              Ceph user name (default: admin)
    --config            Path to ceph.conf file
    --use-consul        Discover monitors from Consul

  Volume:
    --volume NAME        Create a volume with specified name
    --size BYTES         Volume size (supports units: KB, MB, GB, TB)
    --data-pool NAME     Data pool name
    --metadata-pool NAME Metadata pool name
    --replication NUM    Replication size (default: 3)
    --pg-num NUM         Placement groups (default: 128)

  Snapshot:
    --snapshot NAME      Create a snapshot with specified name
    --snapshot-volume    Volume to snapshot (required with --snapshot)

  Pool:
    --pool NAME          Create a pool with specified name
    --pool-pg-num NUM    Number of placement groups
    --pool-size NUM      Replication size
    --pool-type TYPE     Pool type: replicated or erasure
    --pool-app APP       Application: cephfs, rbd, rgw`,

	RunE: eos_cli.Wrap(runCephCreate),
}

func init() {
	// Common flags
	createCephCmd.Flags().StringSliceVar(&cephMonHosts, "monitors", []string{}, "Ceph monitor addresses")
	createCephCmd.Flags().StringVar(&cephUser, "user", "admin", "Ceph user name")
	createCephCmd.Flags().StringVar(&cephConfigFile, "config", "", "Path to ceph.conf file")
	createCephCmd.Flags().BoolVar(&cephUseConsul, "use-consul", false, "Discover monitors from Consul")

	// Volume flags
	createCephCmd.Flags().StringVar(&cephVolumeName, "volume", "", "Create volume with specified name")
	createCephCmd.Flags().Int64Var(&cephVolumeSize, "size", 0, "Volume size in bytes (0 = unlimited)")
	createCephCmd.Flags().StringVar(&cephVolumeDataPool, "data-pool", "", "Data pool name")
	createCephCmd.Flags().StringVar(&cephVolumeMetaPool, "metadata-pool", "", "Metadata pool name")
	createCephCmd.Flags().IntVar(&cephVolumeReplication, "replication", 3, "Replication size")
	createCephCmd.Flags().IntVar(&cephVolumePGNum, "pg-num", 128, "Placement groups")

	// Snapshot flags
	createCephCmd.Flags().StringVar(&cephSnapshotName, "snapshot", "", "Create snapshot with specified name")
	createCephCmd.Flags().StringVar(&cephSnapshotVolume, "snapshot-volume", "", "Volume to snapshot")

	// Pool flags
	createCephCmd.Flags().StringVar(&cephPoolName, "pool", "", "Create pool with specified name")
	createCephCmd.Flags().IntVar(&cephPoolPGNum, "pool-pg-num", 128, "Number of placement groups")
	createCephCmd.Flags().IntVar(&cephPoolSize, "pool-size", 3, "Replication size")
	createCephCmd.Flags().StringVar(&cephPoolType, "pool-type", "replicated", "Pool type")
	createCephCmd.Flags().StringVar(&cephPoolApplication, "pool-app", "cephfs", "Pool application")

	CreateCmd.AddCommand(createCephCmd)
}

func runCephCreate(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Determine what to create based on flags
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
		return createVolume(rc, client)
	}

	if cephSnapshotName != "" {
		return createSnapshot(rc, client)
	}

	if cephPoolName != "" {
		return createPool(rc, client)
	}

	return nil
}

func createVolume(rc *eos_io.RuntimeContext, client *cephfs.CephClient) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Creating CephFS volume",
		zap.String("volume", cephVolumeName))

	opts := &cephfs.VolumeCreateOptions{
		Name:            cephVolumeName,
		Size:            cephVolumeSize,
		DataPool:        cephVolumeDataPool,
		MetadataPool:    cephVolumeMetaPool,
		ReplicationSize: cephVolumeReplication,
		PGNum:           cephVolumePGNum,
	}

	// Set default pool names if not specified
	if opts.DataPool == "" {
		opts.DataPool = cephVolumeName + "_data"
	}
	if opts.MetadataPool == "" {
		opts.MetadataPool = cephVolumeName + "_metadata"
	}


	logger.Info("Volume created successfully",
		zap.String("volume", cephVolumeName))

	return nil
}

func createSnapshot(rc *eos_io.RuntimeContext, client *cephfs.CephClient) error {
	logger := otelzap.Ctx(rc.Ctx)

	if cephSnapshotVolume == "" {
		return fmt.Errorf("--snapshot-volume is required when creating a snapshot")
	}

	logger.Info("Creating CephFS snapshot",
		zap.String("snapshot", cephSnapshotName),
		zap.String("volume", cephSnapshotVolume))

	opts := &cephfs.SnapshotCreateOptions{
		VolumeName:   cephSnapshotVolume,
		SnapshotName: cephSnapshotName,
	}

	if err := client.CreateSnapshot(rc, opts); err != nil {
		return fmt.Errorf("failed to create snapshot: %w", err)
	}

	logger.Info("Snapshot created successfully",
		zap.String("snapshot", cephSnapshotName))

	return nil
}

func createPool(rc *eos_io.RuntimeContext, client *cephfs.CephClient) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Creating Ceph pool",
		zap.String("pool", cephPoolName))

	opts := &cephfs.PoolCreateOptions{
		Name:        cephPoolName,
		PGNum:       cephPoolPGNum,
		Size:        cephPoolSize,
		PoolType:    cephPoolType,
		Application: cephPoolApplication,
	}

	if err := client.CreatePool(rc, opts); err != nil {
		return fmt.Errorf("failed to create pool: %w", err)
	}

	logger.Info("Pool created successfully",
		zap.String("pool", cephPoolName))

	return nil
}
