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

var cephfsCmd = &cobra.Command{
	Use:   "cephfs",
	Short: "Deploy CephFS cluster on bare metal with SaltStack and Terraform orchestration",
	Long: `Deploy CephFS cluster on bare metal using the three-tier orchestration:
1. SaltStack generates Terraform configurations from pillar data
2. Terraform applies these configurations to deploy CephFS via cephadm
3. CephFS runs on bare metal (not containerized) for optimal I/O performance

The deployment includes:
- Cluster initialization with configurable FSID
- OSD deployment with all-available-devices spec
- Network configuration (public and cluster networks)
- SSH-based remote execution for cephadm operations
- Comprehensive health checks and verification

Prerequisites:
- Ubuntu 22.04 LTS or later
- Root access on all target nodes
- SSH key authentication configured
- Minimum 4GB RAM per OSD node
- Available block devices for OSD storage`,

	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		logger.Info("Starting CephFS cluster deployment")

		// Get configuration from flags
		clusterFSID, _ := cmd.Flags().GetString("cluster-fsid")
		adminHost, _ := cmd.Flags().GetString("admin-host")
		sshUser, _ := cmd.Flags().GetString("ssh-user")
		cephImage, _ := cmd.Flags().GetString("ceph-image")
		publicNetwork, _ := cmd.Flags().GetString("public-network")
		clusterNetwork, _ := cmd.Flags().GetString("cluster-network")
		osdDevices, _ := cmd.Flags().GetStringSlice("osd-devices")
		skipVerify, _ := cmd.Flags().GetBool("skip-verify")
		saltOnly, _ := cmd.Flags().GetBool("salt-only")
		terraformOnly, _ := cmd.Flags().GetBool("terraform-only")

		// Create configuration
		config := &cephfs.Config{
			ClusterFSID:    clusterFSID,
			AdminHost:      adminHost,
			SSHUser:        sshUser,
			CephImage:      cephImage,
			PublicNetwork:  publicNetwork,
			ClusterNetwork: clusterNetwork,
			OSDDevices:     osdDevices,
			SkipVerify:     skipVerify,
			SaltOnly:       saltOnly,
			TerraformOnly:  terraformOnly,
		}

		// Orchestrate deployment phases
		if !config.TerraformOnly {
			logger.Info("Phase 1: SaltStack configuration generation")
			return fmt.Errorf("SaltStack-based CephFS deployment has been migrated to HashiCorp stack. Please contact your administrator for distributed storage deployment assistance")
		}

		if !config.SaltOnly {
			logger.Info("Phase 2: Terraform infrastructure deployment")
			if err := cephfs.DeployTerraform(rc, config); err != nil {
				logger.Error("Terraform deployment failed", zap.Error(err))
				return err
			}
		}

		if !config.SkipVerify && !config.SaltOnly {
			logger.Info("Phase 3: CephFS cluster verification")
			if err := cephfs.VerifyCluster(rc, config); err != nil {
				logger.Error("CephFS cluster verification failed", zap.Error(err))
				return err
			}
		}

		logger.Info("CephFS deployment completed successfully")
		return nil
	}),
}

func init() {
	// Core deployment configuration
	cephfsCmd.Flags().String("cluster-fsid", "", "Ceph cluster FSID (UUID format, generated if not provided)")
	cephfsCmd.Flags().String("admin-host", "", "Admin host for cephadm operations (required)")
	cephfsCmd.Flags().String("ssh-user", "root", "SSH user for remote operations")
	cephfsCmd.Flags().String("ceph-image", "quay.io/ceph/ceph:v18.2.1", "Ceph container image to use")

	// Network configuration
	cephfsCmd.Flags().String("public-network", "", "Public network CIDR (e.g., 10.0.0.0/24)")
	cephfsCmd.Flags().String("cluster-network", "", "Cluster network CIDR (e.g., 10.1.0.0/24)")

	// Storage configuration
	cephfsCmd.Flags().StringSlice("osd-devices", []string{}, "Specific OSD devices to use (defaults to all available)")

	// Control flags
	cephfsCmd.Flags().Bool("skip-verify", false, "Skip cluster health verification")
	cephfsCmd.Flags().Bool("salt-only", false, "Only generate SaltStack configuration, don't deploy")
	cephfsCmd.Flags().Bool("terraform-only", false, "Only run Terraform deployment, skip SaltStack generation")

	// Mark required flags
	if err := cephfsCmd.MarkFlagRequired("admin-host"); err != nil {
		panic(fmt.Sprintf("Failed to mark admin-host flag as required: %v", err))
	}
	if err := cephfsCmd.MarkFlagRequired("public-network"); err != nil {
		panic(fmt.Sprintf("Failed to mark public-network flag as required: %v", err))
	}
	if err := cephfsCmd.MarkFlagRequired("cluster-network"); err != nil {
		panic(fmt.Sprintf("Failed to mark cluster-network flag as required: %v", err))
	}

	// Register with parent command
	CreateCmd.AddCommand(cephfsCmd)
}

var createStorageCephFSCmd = &cobra.Command{
	Use:   "storage-cephfs",
	Short: "Create CephFS storage components",
	Long: `Create and configure CephFS distributed storage volumes.
	
CephFS provides a distributed file system with high availability and performance,
ideal for shared storage across multiple nodes.`,
}

var createCephFSVolumeCmd = &cobra.Command{
	Use:   "volume [name]",
	Short: "Create a CephFS volume",
	Long: `Create a CephFS distributed storage volume.

This command creates a new CephFS filesystem with dedicated data and metadata pools.
The volume provides a distributed, scalable file system that can be mounted on multiple
nodes simultaneously.

Examples:
  # Create a basic CephFS volume
  eos create storage-cephfs volume shared-data
  
  # Create a volume with custom pools
  eos create storage-cephfs volume webfiles --data-pool web_data --metadata-pool web_meta
  
  # Create a volume with custom replication
  eos create storage-cephfs volume critical-data --replication 5
  
  # Create a volume with more placement groups for larger deployments
  eos create storage-cephfs volume bigdata --pg-num 256 --replication 3`,
	Args: cobra.ExactArgs(1),
	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		name := args[0]

		replication, _ := cmd.Flags().GetInt("replication")
		pgNum, _ := cmd.Flags().GetInt("pg-num")

		config := &cephfs.Config{
			Name:            name,
			DataPool:        cmd.Flag("data-pool").Value.String(),
			MetadataPool:    cmd.Flag("metadata-pool").Value.String(),
			ReplicationSize: replication,
			PGNum:           pgNum,
		}

		// Set default pool names if not specified
		if config.DataPool == "" {
			config.DataPool = name + "_data"
		}
		if config.MetadataPool == "" {
			config.MetadataPool = name + "_metadata"
		}

		logger.Info("Creating CephFS volume",
			zap.String("name", name),
			zap.String("dataPool", config.DataPool),
			zap.String("metadataPool", config.MetadataPool),
			zap.Int("replication", replication))

		return cephfs.CreateVolume(rc, config)
	}),
}

var createCephFSMountCmd = &cobra.Command{
	Use:   "mount [volume-name] [mount-point]",
	Short: "Mount a CephFS volume",
	Long: `Mount an existing CephFS volume to a local directory.

This command configures and mounts a CephFS filesystem at the specified mount point.
It handles authentication, creates the mount directory if needed, and configures
/etc/fstab for persistent mounts.

Examples:
  # Mount a CephFS volume with default settings
  eos create storage-cephfs mount shared-data /mnt/shared
  
  # Mount with specific monitors
  eos create storage-cephfs mount webfiles /var/www/shared --monitors 10.0.1.10:6789,10.0.1.11:6789
  
  # Mount with custom user and credentials
  eos create storage-cephfs mount appdata /opt/data --user appuser --secret-file /etc/ceph/ceph.client.appuser.keyring
  
  # Mount with performance optimizations
  eos create storage-cephfs mount fastdata /mnt/fast --performance
  
  # Mount with custom options
  eos create storage-cephfs mount readonly /mnt/readonly --mount-options noatime,ro`,
	Args: cobra.ExactArgs(2),
	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		volumeName := args[0]
		mountPoint := args[1]

		monitors, _ := cmd.Flags().GetStringSlice("monitors")
		mountOptions, _ := cmd.Flags().GetStringSlice("mount-options")
		usePerformance, _ := cmd.Flags().GetBool("performance")

		config := &cephfs.Config{
			Name:         volumeName,
			MountPoint:   mountPoint,
			MonitorHosts: monitors,
			User:         cmd.Flag("user").Value.String(),
			SecretFile:   cmd.Flag("secret-file").Value.String(),
			MountOptions: mountOptions,
		}

		// Add performance options if requested
		if usePerformance {
			config.MountOptions = append(config.MountOptions, cephfs.MountOptions["performance"]...)
			logger.Info("Using performance-optimized mount options")
		}

		logger.Info("Mounting CephFS volume",
			zap.String("volume", volumeName),
			zap.String("mountPoint", mountPoint),
			zap.Strings("monitors", monitors))

		return cephfs.CreateMountPoint(rc, config)
	}),
}

func init() {
	// Add subcommands
	createStorageCephFSCmd.AddCommand(createCephFSVolumeCmd)
	createStorageCephFSCmd.AddCommand(createCephFSMountCmd)

	// Volume creation flags
	createCephFSVolumeCmd.Flags().String("data-pool", "", "Data pool name")
	createCephFSVolumeCmd.Flags().String("metadata-pool", "", "Metadata pool name")
	createCephFSVolumeCmd.Flags().Int("replication", 3, "Replication size")
	createCephFSVolumeCmd.Flags().Int("pg-num", 128, "Number of placement groups")

	// Mount flags
	createCephFSMountCmd.Flags().StringSlice("monitors", []string{"localhost:6789"}, "Ceph monitor addresses")
	createCephFSMountCmd.Flags().String("user", "admin", "Ceph user")
	createCephFSMountCmd.Flags().String("secret-file", "/etc/ceph/ceph.client.admin.keyring", "Path to secret file")
	createCephFSMountCmd.Flags().StringSlice("mount-options", []string{}, "Additional mount options")
	createCephFSMountCmd.Flags().Bool("performance", false, "Use performance-optimized mount options")
}
