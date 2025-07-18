package openstack

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/telemetry"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// configureStorage sets up storage backends for OpenStack
func configureStorage(rc *eos_io.RuntimeContext, config *Config) error {
	ctx, span := telemetry.Start(rc.Ctx, "openstack.configureStorage")
	defer span.End()
	rc = &eos_io.RuntimeContext{Ctx: ctx}

	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Configuring OpenStack storage",
		zap.String("backend", string(config.StorageBackend)))

	// Skip if not a storage node or controller
	if config.Mode == ModeCompute {
		logger.Debug("Skipping storage configuration on compute node")
		return nil
	}

	// Install Cinder if needed
	if contains(config.GetEnabledServices(), ServiceCinder) {
		if err := configureCinder(rc, config); err != nil {
			return fmt.Errorf("failed to configure Cinder: %w", err)
		}
	}

	// Configure storage backend
	switch config.StorageBackend {
	case StorageLVM:
		return configureLVMBackend(rc, config)
	case StorageCeph:
		return configureCephBackend(rc, config)
	case StorageNFS:
		return configureNFSBackend(rc, config)
	default:
		return fmt.Errorf("unsupported storage backend: %s", config.StorageBackend)
	}
}

// configureCinder sets up the Cinder volume service
func configureCinder(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Configuring Cinder volume service")

	// Install Cinder packages
	packages := []string{
		"cinder-api",
		"cinder-scheduler",
		"python3-cinderclient",
	}

	// Add volume service for storage nodes
	if config.Mode == ModeStorage || config.Mode == ModeAllInOne {
		packages = append(packages, "cinder-volume", "tgt", "thin-provisioning-tools")
	}

	installCmd := exec.CommandContext(rc.Ctx, "apt-get", "install", "-y")
	installCmd.Args = append(installCmd.Args, packages...)
	if err := installCmd.Run(); err != nil {
		return fmt.Errorf("failed to install Cinder packages: %w", err)
	}

	// Configure Cinder
	if err := generateCinderConfiguration(rc, config); err != nil {
		return fmt.Errorf("failed to generate Cinder configuration: %w", err)
	}

	// Initialize database if controller
	if config.IsControllerNode() {
		if err := initializeCinderDatabase(rc, config); err != nil {
			return fmt.Errorf("failed to initialize Cinder database: %w", err)
		}
	}

	// Start Cinder services
	services := []string{"cinder-api", "cinder-scheduler"}
	if config.Mode == ModeStorage || config.Mode == ModeAllInOne {
		services = append(services, "cinder-volume", "tgt")
	}

	for _, svc := range services {
		if err := startService(rc, svc); err != nil {
			return fmt.Errorf("failed to start %s: %w", svc, err)
		}
	}

	return nil
}

// configureLVMBackend sets up LVM as the storage backend
func configureLVMBackend(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Configuring LVM storage backend")

	// Install LVM packages
	packages := []string{"lvm2", "thin-provisioning-tools"}
	installCmd := exec.CommandContext(rc.Ctx, "apt-get", "install", "-y")
	installCmd.Args = append(installCmd.Args, packages...)
	if err := installCmd.Run(); err != nil {
		return fmt.Errorf("failed to install LVM packages: %w", err)
	}

	// Create volume group if it doesn't exist
	vgName := config.LVMVolumeGroup
	if vgName == "" {
		vgName = "cinder-volumes"
	}

	if err := createLVMVolumeGroup(rc, vgName); err != nil {
		return fmt.Errorf("failed to create volume group: %w", err)
	}

	// Configure LVM filter
	if err := configureLVMFilter(rc); err != nil {
		return fmt.Errorf("failed to configure LVM filter: %w", err)
	}

	// Configure Cinder for LVM
	cinderLVMConfig := fmt.Sprintf(`[lvm]
volume_driver = cinder.volume.drivers.lvm.LVMVolumeDriver
volume_group = %s
target_protocol = iscsi
target_helper = tgtadm
volume_backend_name = lvm
lvm_type = thin
`, vgName)

	configPath := "/etc/cinder/cinder.conf.d/lvm.conf"
	configDir := filepath.Dir(configPath)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	if err := os.WriteFile(configPath, []byte(cinderLVMConfig), 0640); err != nil {
		return fmt.Errorf("failed to write LVM config: %w", err)
	}

	// Update main Cinder config to include LVM backend
	if err := updateCinderBackends(rc, "lvm"); err != nil {
		return fmt.Errorf("failed to update Cinder backends: %w", err)
	}

	logger.Info("LVM storage backend configured successfully")
	return nil
}

// configureCephBackend sets up Ceph as the storage backend
func configureCephBackend(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Configuring Ceph storage backend")

	// Install Ceph client packages
	packages := []string{
		"ceph-common",
		"python3-rbd",
		"python3-rados",
	}

	installCmd := exec.CommandContext(rc.Ctx, "apt-get", "install", "-y")
	installCmd.Args = append(installCmd.Args, packages...)
	if err := installCmd.Run(); err != nil {
		return fmt.Errorf("failed to install Ceph packages: %w", err)
	}

	// Create Ceph configuration directory
	cephConfigDir := "/etc/ceph"
	if err := os.MkdirAll(cephConfigDir, 0755); err != nil {
		return fmt.Errorf("failed to create Ceph config directory: %w", err)
	}

	// Generate ceph.conf
	cephConfig := fmt.Sprintf(`[global]
mon_host = %s
auth_cluster_required = cephx
auth_service_required = cephx
auth_client_required = cephx
`, strings.Join(config.CephMonitors, ","))

	cephConfigPath := filepath.Join(cephConfigDir, "ceph.conf")
	if err := os.WriteFile(cephConfigPath, []byte(cephConfig), 0644); err != nil {
		return fmt.Errorf("failed to write ceph.conf: %w", err)
	}

	// Configure Ceph pool if not exists
	poolName := config.CephPool
	if poolName == "" {
		poolName = "volumes"
	}

	if err := createCephPool(rc, poolName); err != nil {
		logger.Warn("Failed to create Ceph pool", zap.Error(err))
	}

	// Configure Cinder for Ceph
	cinderCephConfig := fmt.Sprintf(`[ceph]
volume_driver = cinder.volume.drivers.rbd.RBDDriver
rbd_pool = %s
rbd_ceph_conf = /etc/ceph/ceph.conf
rbd_flatten_volume_from_snapshot = false
rbd_max_clone_depth = 5
rbd_store_chunk_size = 4
rados_connect_timeout = -1
glance_api_version = 2
rbd_user = cinder
rbd_secret_uuid = %s
volume_backend_name = ceph
`, poolName, generateUUID())

	configPath := "/etc/cinder/cinder.conf.d/ceph.conf"
	configDir := filepath.Dir(configPath)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	if err := os.WriteFile(configPath, []byte(cinderCephConfig), 0640); err != nil {
		return fmt.Errorf("failed to write Ceph config: %w", err)
	}

	// Update main Cinder config to include Ceph backend
	if err := updateCinderBackends(rc, "ceph"); err != nil {
		return fmt.Errorf("failed to update Cinder backends: %w", err)
	}

	// Configure Glance for Ceph if enabled
	if contains(config.GetEnabledServices(), ServiceGlance) {
		if err := configureGlanceCeph(rc, config); err != nil {
			logger.Warn("Failed to configure Glance for Ceph", zap.Error(err))
		}
	}

	// Configure Nova for Ceph if enabled
	if contains(config.GetEnabledServices(), ServiceNova) {
		if err := configureNovaCeph(rc, config); err != nil {
			logger.Warn("Failed to configure Nova for Ceph", zap.Error(err))
		}
	}

	logger.Info("Ceph storage backend configured successfully")
	return nil
}

// configureNFSBackend sets up NFS as the storage backend
func configureNFSBackend(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Configuring NFS storage backend")

	// Install NFS packages
	packages := []string{"nfs-common"}
	installCmd := exec.CommandContext(rc.Ctx, "apt-get", "install", "-y")
	installCmd.Args = append(installCmd.Args, packages...)
	if err := installCmd.Run(); err != nil {
		return fmt.Errorf("failed to install NFS packages: %w", err)
	}

	// Create mount point
	nfsMountPoint := "/var/lib/cinder/nfs"
	if err := os.MkdirAll(nfsMountPoint, 0755); err != nil {
		return fmt.Errorf("failed to create NFS mount point: %w", err)
	}

	// Configure NFS shares file
	nfsSharesFile := "/etc/cinder/nfs_shares"
	nfsShare := fmt.Sprintf("%s:%s\n", config.NFSServer, config.NFSExportPath)
	if err := os.WriteFile(nfsSharesFile, []byte(nfsShare), 0640); err != nil {
		return fmt.Errorf("failed to write NFS shares file: %w", err)
	}

	// Set ownership
	uid, gid, err := eos_unix.LookupUser(rc.Ctx, "cinder")
	if err == nil {
		if err := os.Chown(nfsSharesFile, uid, gid); err != nil {
			logger.Warn("Failed to set ownership on NFS shares file", zap.Error(err))
		}
	}

	// Configure Cinder for NFS
	cinderNFSConfig := fmt.Sprintf(`[nfs]
volume_driver = cinder.volume.drivers.nfs.NfsDriver
nfs_shares_config = /etc/cinder/nfs_shares
nfs_mount_point_base = %s
nfs_mount_options = vers=4,minorversion=1
volume_backend_name = nfs
`, nfsMountPoint)

	configPath := "/etc/cinder/cinder.conf.d/nfs.conf"
	configDir := filepath.Dir(configPath)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	if err := os.WriteFile(configPath, []byte(cinderNFSConfig), 0640); err != nil {
		return fmt.Errorf("failed to write NFS config: %w", err)
	}

	// Update main Cinder config to include NFS backend
	if err := updateCinderBackends(rc, "nfs"); err != nil {
		return fmt.Errorf("failed to update Cinder backends: %w", err)
	}

	logger.Info("NFS storage backend configured successfully")
	return nil
}

// Helper functions

func generateCinderConfiguration(rc *eos_io.RuntimeContext, config *Config) error {
	// Generate main Cinder configuration
	cinderConfig := generateCinderConfig(config)

	configPath := "/etc/cinder/cinder.conf"
	if err := os.WriteFile(configPath, []byte(cinderConfig), 0640); err != nil {
		return fmt.Errorf("failed to write Cinder config: %w", err)
	}

	// Set ownership
	uid, gid, err := eos_unix.LookupUser(rc.Ctx, "cinder")
	if err == nil {
		if err := os.Chown(configPath, uid, gid); err != nil {
			otelzap.Ctx(rc.Ctx).Warn("Failed to set ownership on Cinder config", zap.Error(err))
		}
	}

	return nil
}

func initializeCinderDatabase(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Initializing Cinder database")

	// Create database
	createDBCmd := fmt.Sprintf(`mysql -u root -p%s -e "CREATE DATABASE IF NOT EXISTS cinder;"`, 
		config.DBPassword)
	if err := exec.CommandContext(rc.Ctx, "bash", "-c", createDBCmd).Run(); err != nil {
		return fmt.Errorf("failed to create Cinder database: %w", err)
	}

	// Grant privileges
	grantCmd := fmt.Sprintf(`mysql -u root -p%s -e "GRANT ALL PRIVILEGES ON cinder.* TO 'cinder'@'localhost' IDENTIFIED BY '%s';"`,
		config.DBPassword, config.DBPassword)
	if err := exec.CommandContext(rc.Ctx, "bash", "-c", grantCmd).Run(); err != nil {
		return fmt.Errorf("failed to grant Cinder database privileges: %w", err)
	}

	// Sync database
	syncCmd := exec.CommandContext(rc.Ctx, "cinder-manage", "db", "sync")
	syncCmd.Env = append(os.Environ(), fmt.Sprintf("OS_DATABASE_PASSWORD=%s", config.DBPassword))
	if err := syncCmd.Run(); err != nil {
		return fmt.Errorf("failed to sync Cinder database: %w", err)
	}

	return nil
}

func createLVMVolumeGroup(rc *eos_io.RuntimeContext, vgName string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if volume group exists
	checkCmd := exec.CommandContext(rc.Ctx, "vgdisplay", vgName)
	if checkCmd.Run() == nil {
		logger.Debug("Volume group already exists", zap.String("vg", vgName))
		return nil
	}

	logger.Info("Creating LVM volume group", zap.String("vg", vgName))

	// Find available disk or create loop device
	// In production, this would be more sophisticated
	loopFile := fmt.Sprintf("/var/lib/cinder/%s.img", vgName)
	loopDir := filepath.Dir(loopFile)

	if err := os.MkdirAll(loopDir, 0755); err != nil {
		return fmt.Errorf("failed to create loop file directory: %w", err)
	}

	// Create 50GB sparse file for testing
	createCmd := exec.CommandContext(rc.Ctx, "truncate", "-s", "50G", loopFile)
	if err := createCmd.Run(); err != nil {
		return fmt.Errorf("failed to create loop file: %w", err)
	}

	// Setup loop device
	losetupCmd := exec.CommandContext(rc.Ctx, "losetup", "-f", loopFile, "--show")
	output, err := losetupCmd.Output()
	if err != nil {
		return fmt.Errorf("failed to setup loop device: %w", err)
	}

	loopDevice := strings.TrimSpace(string(output))

	// Create physical volume
	pvcreateCmd := exec.CommandContext(rc.Ctx, "pvcreate", loopDevice)
	if err := pvcreateCmd.Run(); err != nil {
		return fmt.Errorf("failed to create physical volume: %w", err)
	}

	// Create volume group
	vgcreateCmd := exec.CommandContext(rc.Ctx, "vgcreate", vgName, loopDevice)
	if err := vgcreateCmd.Run(); err != nil {
		return fmt.Errorf("failed to create volume group: %w", err)
	}

	return nil
}

func configureLVMFilter(rc *eos_io.RuntimeContext) error {
	// Configure LVM to only scan devices we want
	lvmConfig := `devices {
    filter = [ "a|^/dev/sda|", "a|^/dev/sdb|", "a|^/dev/loop|", "r|.*|" ]
}`

	configPath := "/etc/lvm/lvm.conf.d/openstack.conf"
	configDir := filepath.Dir(configPath)

	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create LVM config directory: %w", err)
	}

	if err := os.WriteFile(configPath, []byte(lvmConfig), 0644); err != nil {
		return fmt.Errorf("failed to write LVM filter config: %w", err)
	}

	// Update initramfs
	updateCmd := exec.CommandContext(rc.Ctx, "update-initramfs", "-u")
	return updateCmd.Run()
}

func updateCinderBackends(rc *eos_io.RuntimeContext, backend string) error {
	// This would update the main cinder.conf to enable the backend
	// Simplified for this example
	return nil
}

func createCephPool(rc *eos_io.RuntimeContext, poolName string) error {
	// Check if pool exists
	checkCmd := exec.CommandContext(rc.Ctx, "ceph", "osd", "pool", "ls")
	output, err := checkCmd.Output()
	if err == nil && strings.Contains(string(output), poolName) {
		return nil
	}

	// Create pool
	createCmd := exec.CommandContext(rc.Ctx, "ceph", "osd", "pool", "create", poolName, "128")
	if err := createCmd.Run(); err != nil {
		return fmt.Errorf("failed to create Ceph pool: %w", err)
	}

	// Initialize pool
	initCmd := exec.CommandContext(rc.Ctx, "rbd", "pool", "init", poolName)
	return initCmd.Run()
}

func configureGlanceCeph(rc *eos_io.RuntimeContext, config *Config) error {
	// Configure Glance to use Ceph for image storage
	glanceCephConfig := `[glance_store]
stores = rbd
default_store = rbd
rbd_store_pool = images
rbd_store_user = glance
rbd_store_ceph_conf = /etc/ceph/ceph.conf
rbd_store_chunk_size = 8
`

	configPath := "/etc/glance/glance-api.conf.d/ceph.conf"
	configDir := filepath.Dir(configPath)

	if err := os.MkdirAll(configDir, 0755); err != nil {
		return err
	}

	return os.WriteFile(configPath, []byte(glanceCephConfig), 0640)
}

func configureNovaCeph(rc *eos_io.RuntimeContext, config *Config) error {
	// Configure Nova to use Ceph for ephemeral storage
	novaCephConfig := `[libvirt]
images_type = rbd
images_rbd_pool = vms
images_rbd_ceph_conf = /etc/ceph/ceph.conf
rbd_user = cinder
rbd_secret_uuid = %s
`

	configPath := "/etc/nova/nova.conf.d/ceph.conf"
	configDir := filepath.Dir(configPath)

	if err := os.MkdirAll(configDir, 0755); err != nil {
		return err
	}

	return os.WriteFile(configPath, []byte(fmt.Sprintf(novaCephConfig, generateUUID())), 0640)
}

func startService(rc *eos_io.RuntimeContext, service string) error {
	// Enable service
	enableCmd := exec.CommandContext(rc.Ctx, "systemctl", "enable", service)
	if err := enableCmd.Run(); err != nil {
		return fmt.Errorf("failed to enable service: %w", err)
	}

	// Start service
	startCmd := exec.CommandContext(rc.Ctx, "systemctl", "start", service)
	if err := startCmd.Run(); err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}

	return nil
}

func generateUUID() string {
	// In production, use a proper UUID generator
	cryptoOps := crypto.NewRandomOperations()
	uuid, err := cryptoOps.GenerateRandomString(nil, 32, crypto.CharsetAlphaNum)
	if err != nil {
		return "00000000-0000-0000-0000-000000000000"
	}
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		uuid[0:8], uuid[8:12], uuid[12:16], uuid[16:20], uuid[20:32])
}