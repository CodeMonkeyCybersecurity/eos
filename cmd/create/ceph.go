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
	cephVolumeName        string
	cephVolumeSize        int64
	cephVolumeDataPool    string
	cephVolumeMetaPool    string
	cephVolumeReplication int
	cephVolumePGNum       int

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

func runInteractiveCephCreate(rc *eos_io.RuntimeContext, cmd *cobra.Command) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting interactive Ceph resource creation")
	fmt.Println("\nCeph Resource Creation Wizard")
	fmt.Println("==============================")
	fmt.Println("\nWhat would you like to create?")
	fmt.Println("  1) Volume   - CephFS volume for file storage")
	fmt.Println("  2) Snapshot - Snapshot of an existing volume")
	fmt.Println("  3) Pool     - Storage pool for data replication")
	fmt.Println()

	choice, err := eos_io.PromptInput(rc, "Enter choice (1-3) [1]: ", "choice")
	if err != nil {
		return fmt.Errorf("failed to get choice: %w", err)
	}
	if choice == "" {
		choice = "1"
	}

	switch choice {
	case "1":
		// Create volume interactively
		cephVolumeName, err = eos_io.PromptInput(rc, "Volume name [mydata]: ", "volume_name")
		if err != nil {
			return fmt.Errorf("failed to get volume name: %w", err)
		}
		if cephVolumeName == "" {
			cephVolumeName = "mydata"
		}

		sizeStr, err := eos_io.PromptInput(rc, "Volume size (e.g., 100GB, 1TB, or 0 for unlimited) [0]: ", "volume_size")
		if err != nil {
			return fmt.Errorf("failed to get volume size: %w", err)
		}
		if sizeStr == "" || sizeStr == "0" {
			cephVolumeSize = 0 // Unlimited
		}

		replStr, err := eos_io.PromptInput(rc, "Replication size [3]: ", "replication")
		if err != nil {
			return fmt.Errorf("failed to get replication: %w", err)
		}
		if replStr == "" {
			cephVolumeReplication = 3
		} else {
			_, _ = fmt.Sscanf(replStr, "%d", &cephVolumeReplication)
		}

		// Set defaults for pools
		cephVolumeDataPool = cephVolumeName + "_data"
		cephVolumeMetaPool = cephVolumeName + "_metadata"

	case "2":
		// Create snapshot interactively
		cephSnapshotVolume, err = eos_io.PromptInput(rc, "Volume to snapshot: ", "snapshot_volume")
		if err != nil {
			return fmt.Errorf("failed to get volume name: %w", err)
		}
		if cephSnapshotVolume == "" {
			return fmt.Errorf("volume name is required for snapshots")
		}

		defaultSnapName := fmt.Sprintf("snapshot-%s", cephSnapshotVolume)
		cephSnapshotName, err = eos_io.PromptInput(rc, fmt.Sprintf("Snapshot name [%s]: ", defaultSnapName), "snapshot_name")
		if err != nil {
			return fmt.Errorf("failed to get snapshot name: %w", err)
		}
		if cephSnapshotName == "" {
			cephSnapshotName = defaultSnapName
		}

	case "3":
		// Create pool interactively
		cephPoolName, err = eos_io.PromptInput(rc, "Pool name [mypool]: ", "pool_name")
		if err != nil {
			return fmt.Errorf("failed to get pool name: %w", err)
		}
		if cephPoolName == "" {
			cephPoolName = "mypool"
		}

		pgStr, err := eos_io.PromptInput(rc, "Number of placement groups (PGs) [128]: ", "pg_num")
		if err != nil {
			return fmt.Errorf("failed to get PG number: %w", err)
		}
		if pgStr == "" {
			cephPoolPGNum = 128
		} else {
			_, _ = fmt.Sscanf(pgStr, "%d", &cephPoolPGNum)
		}

		sizeStr, err := eos_io.PromptInput(rc, "Replication size [3]: ", "replication_size")
		if err != nil {
			return fmt.Errorf("failed to get replication size: %w", err)
		}
		if sizeStr == "" {
			cephPoolSize = 3
		} else {
			_, _ = fmt.Sscanf(sizeStr, "%d", &cephPoolSize)
		}

		cephPoolType, err = eos_io.PromptInput(rc, "Pool type (replicated/erasure) [replicated]: ", "pool_type")
		if err != nil {
			return fmt.Errorf("failed to get pool type: %w", err)
		}
		if cephPoolType == "" {
			cephPoolType = "replicated"
		}

		cephPoolApplication, err = eos_io.PromptInput(rc, "Application (cephfs/rbd/rgw) [cephfs]: ", "application")
		if err != nil {
			return fmt.Errorf("failed to get application: %w", err)
		}
		if cephPoolApplication == "" {
			cephPoolApplication = "cephfs"
		}

	default:
		return fmt.Errorf("invalid choice: %s", choice)
	}

	// Now run the normal creation flow
	return runCephCreate(rc, cmd, nil)
}

func runCephCreate(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// If no flags specified, offer interactive mode
	if cephVolumeName == "" && cephSnapshotName == "" && cephPoolName == "" {
		return runInteractiveCephCreate(rc, cmd)
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

	// Actually create the volume
	if err := client.CreateVolume(rc, opts); err != nil {
		return fmt.Errorf("failed to create volume: %w", err)
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
