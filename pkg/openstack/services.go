package openstack

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/telemetry"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// installGlance installs and configures the Glance image service
func installGlance(rc *eos_io.RuntimeContext, config *Config) error {
	ctx, span := telemetry.Start(rc.Ctx, "openstack.installGlance")
	defer span.End()
	rc = &eos_io.RuntimeContext{Ctx: ctx}

	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Installing Glance image service")

	// Install packages
	packages := []string{"glance", "python3-glanceclient"}
	if err := installPackages(rc, packages); err != nil {
		return fmt.Errorf("failed to install Glance packages: %w", err)
	}

	// Create database
	if config.IsControllerNode() {
		if err := createServiceDatabase(rc, "glance", config.DBPassword); err != nil {
			return fmt.Errorf("failed to create Glance database: %w", err)
		}
	}

	// Configure Glance
	if err := configureGlanceService(rc, config); err != nil {
		return fmt.Errorf("failed to configure Glance: %w", err)
	}

	// Sync database
	syncCmd := exec.CommandContext(rc.Ctx, "glance-manage", "db_sync")
	syncCmd.Env = append(os.Environ(), fmt.Sprintf("OS_DATABASE_PASSWORD=%s", config.DBPassword))
	if err := syncCmd.Run(); err != nil {
		return fmt.Errorf("failed to sync Glance database: %w", err)
	}

	// Start and enable services
	services := []string{"glance-api"}
	for _, svc := range services {
		if err := enableAndStartService(rc, svc); err != nil {
			return fmt.Errorf("failed to start %s: %w", svc, err)
		}
	}

	// Create image store directory
	imageDir := "/var/lib/glance/images"
	if err := os.MkdirAll(imageDir, 0755); err != nil {
		return fmt.Errorf("failed to create image directory: %w", err)
	}

	// Set ownership
	uid, gid, err := eos_unix.LookupUser(rc.Ctx, "glance")
	if err == nil {
		if err := os.Chown(imageDir, uid, gid); err != nil {
			logger.Warn("Failed to set ownership on image directory", zap.Error(err))
		}
	}

	logger.Info("Glance installation completed")
	return nil
}

// installNova installs and configures the Nova compute service
func installNova(rc *eos_io.RuntimeContext, config *Config) error {
	ctx, span := telemetry.Start(rc.Ctx, "openstack.installNova")
	defer span.End()
	rc = &eos_io.RuntimeContext{Ctx: ctx}

	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Installing Nova compute service")

	// Determine packages based on node type
	var packages []string
	if config.IsControllerNode() {
		packages = []string{
			"nova-api",
			"nova-conductor",
			"nova-novncproxy",
			"nova-scheduler",
			"python3-novaclient",
			"placement-api",
		}
	} else if config.Mode == ModeCompute {
		packages = []string{
			"nova-compute",
			"python3-novaclient",
		}

		// Add hypervisor support
		if supportsKVM(rc) {
			packages = append(packages, "nova-compute-kvm")
		} else {
			packages = append(packages, "nova-compute-qemu")
		}
	}

	if err := installPackages(rc, packages); err != nil {
		return fmt.Errorf("failed to install Nova packages: %w", err)
	}

	// Controller-specific setup
	if config.IsControllerNode() {
		// Create databases
		databases := []string{"nova", "nova_api", "nova_cell0"}
		for _, db := range databases {
			if err := createServiceDatabase(rc, db, config.DBPassword); err != nil {
				return fmt.Errorf("failed to create %s database: %w", db, err)
			}
		}

		// Configure Nova
		if err := configureNovaController(rc, config); err != nil {
			return fmt.Errorf("failed to configure Nova controller: %w", err)
		}

		// Sync databases
		if err := syncNovaDatabases(rc, config); err != nil {
			return fmt.Errorf("failed to sync Nova databases: %w", err)
		}

		// Create cell mappings
		if err := createCellMappings(rc); err != nil {
			return fmt.Errorf("failed to create cell mappings: %w", err)
		}

		// Start controller services
		controllerServices := []string{
			"nova-api",
			"nova-scheduler",
			"nova-conductor",
			"nova-novncproxy",
		}
		for _, svc := range controllerServices {
			if err := enableAndStartService(rc, svc); err != nil {
				return fmt.Errorf("failed to start %s: %w", svc, err)
			}
		}
	}

	// Compute node setup
	if config.Mode == ModeCompute || config.Mode == ModeAllInOne {
		if err := configureNovaCompute(rc, config); err != nil {
			return fmt.Errorf("failed to configure Nova compute: %w", err)
		}

		// Start compute service
		if err := enableAndStartService(rc, "nova-compute"); err != nil {
			return fmt.Errorf("failed to start nova-compute: %w", err)
		}

		// Discover compute hosts (for controller)
		if config.IsControllerNode() {
			time.Sleep(10 * time.Second) // Wait for compute to register
			discoverCmd := exec.CommandContext(rc.Ctx, "nova-manage", "cell_v2", "discover_hosts")
			if err := discoverCmd.Run(); err != nil {
				logger.Warn("Failed to discover compute hosts", zap.Error(err))
			}
		}
	}

	logger.Info("Nova installation completed")
	return nil
}

// installNeutron installs and configures the Neutron networking service
func installNeutron(rc *eos_io.RuntimeContext, config *Config) error {
	ctx, span := telemetry.Start(rc.Ctx, "openstack.installNeutron")
	defer span.End()
	rc = &eos_io.RuntimeContext{Ctx: ctx}

	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Installing Neutron networking service")

	// Packages have already been installed in network.go
	// This function handles service-specific configuration

	// Controller setup
	if config.IsControllerNode() {
		// Create database
		if err := createServiceDatabase(rc, "neutron", config.DBPassword); err != nil {
			return fmt.Errorf("failed to create Neutron database: %w", err)
		}

		// Configure Neutron server
		if err := configureNeutronServer(rc, config); err != nil {
			return fmt.Errorf("failed to configure Neutron server: %w", err)
		}

		// Sync database
		syncCmd := exec.CommandContext(rc.Ctx, "neutron-db-manage",
			"--config-file", "/etc/neutron/neutron.conf",
			"--config-file", "/etc/neutron/plugins/ml2/ml2_conf.ini",
			"upgrade", "head")
		if err := syncCmd.Run(); err != nil {
			return fmt.Errorf("failed to sync Neutron database: %w", err)
		}

		// Start server
		if err := enableAndStartService(rc, "neutron-server"); err != nil {
			return fmt.Errorf("failed to start neutron-server: %w", err)
		}
	}

	// Start agent services (all nodes)
	agents := []string{
		"neutron-openvswitch-agent",
		"neutron-dhcp-agent",
		"neutron-metadata-agent",
	}

	// Add L3 agent if not pure compute node
	if config.Mode != ModeCompute {
		agents = append(agents, "neutron-l3-agent")
	}

	for _, agent := range agents {
		if err := enableAndStartService(rc, agent); err != nil {
			logger.Warn("Failed to start agent", 
				zap.String("agent", agent),
				zap.Error(err))
		}
	}

	logger.Info("Neutron installation completed")
	return nil
}

// installCinder installs and configures the Cinder block storage service
func installCinder(rc *eos_io.RuntimeContext, config *Config) error {
	ctx, span := telemetry.Start(rc.Ctx, "openstack.installCinder")
	defer span.End()
	rc = &eos_io.RuntimeContext{Ctx: ctx}

	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Installing Cinder block storage service")

	// Note: Main Cinder installation is handled in storage.go
	// This handles additional service configuration

	// Restart Cinder services after storage backend configuration
	services := []string{"cinder-scheduler", "cinder-api"}
	if config.Mode == ModeStorage || config.Mode == ModeAllInOne {
		services = append(services, "cinder-volume")
	}

	for _, svc := range services {
		restartCmd := exec.CommandContext(rc.Ctx, "systemctl", "restart", svc)
		if err := restartCmd.Run(); err != nil {
			logger.Warn("Failed to restart service",
				zap.String("service", svc),
				zap.Error(err))
		}
	}

	logger.Info("Cinder installation completed")
	return nil
}

// installSwift installs and configures the Swift object storage service
func installSwift(rc *eos_io.RuntimeContext, config *Config) error {
	ctx, span := telemetry.Start(rc.Ctx, "openstack.installSwift")
	defer span.End()
	rc = &eos_io.RuntimeContext{Ctx: ctx}

	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Installing Swift object storage service")

	// Install packages
	packages := []string{
		"swift",
		"swift-proxy",
		"python3-swiftclient",
		"python3-keystoneclient",
		"python3-keystonemiddleware",
		"rsync",
		"xinetd",
	}

	// Add storage node packages
	if config.Mode == ModeStorage || config.Mode == ModeAllInOne {
		packages = append(packages,
			"swift-account",
			"swift-container",
			"swift-object",
			"xfsprogs",
		)
	}

	if err := installPackages(rc, packages); err != nil {
		return fmt.Errorf("failed to install Swift packages: %w", err)
	}

	// Configure Swift
	if err := configureSwift(rc, config); err != nil {
		return fmt.Errorf("failed to configure Swift: %w", err)
	}

	// Create rings (controller only)
	if config.IsControllerNode() {
		if err := createSwiftRings(rc, config); err != nil {
			return fmt.Errorf("failed to create Swift rings: %w", err)
		}
	}

	// Start services
	swiftServices := []string{"swift-proxy"}
	if config.Mode == ModeStorage || config.Mode == ModeAllInOne {
		swiftServices = append(swiftServices,
			"swift-account", "swift-account-auditor", "swift-account-reaper", "swift-account-replicator",
			"swift-container", "swift-container-auditor", "swift-container-replicator", "swift-container-updater",
			"swift-object", "swift-object-auditor", "swift-object-replicator", "swift-object-updater",
		)
	}

	for _, svc := range swiftServices {
		if err := enableAndStartService(rc, svc); err != nil {
			logger.Warn("Failed to start Swift service",
				zap.String("service", svc),
				zap.Error(err))
		}
	}

	logger.Info("Swift installation completed")
	return nil
}

// installHorizon installs and configures the Horizon dashboard
func installHorizon(rc *eos_io.RuntimeContext, config *Config) error {
	ctx, span := telemetry.Start(rc.Ctx, "openstack.installHorizon")
	defer span.End()
	rc = &eos_io.RuntimeContext{Ctx: ctx}

	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Installing Horizon dashboard")

	// Install packages
	packages := []string{"openstack-dashboard", "python3-django-horizon"}
	if err := installPackages(rc, packages); err != nil {
		return fmt.Errorf("failed to install Horizon packages: %w", err)
	}

	// Configure Horizon
	if err := configureHorizon(rc, config); err != nil {
		return fmt.Errorf("failed to configure Horizon: %w", err)
	}

	// Configure Apache for Horizon
	if err := configureApacheHorizon(rc, config); err != nil {
		return fmt.Errorf("failed to configure Apache for Horizon: %w", err)
	}

	// Collect static files
	collectCmd := exec.CommandContext(rc.Ctx, "python3", "/usr/share/openstack-dashboard/manage.py",
		"collectstatic", "--noinput")
	collectCmd.Env = append(os.Environ(), "DJANGO_SETTINGS_MODULE=openstack_dashboard.settings")
	if err := collectCmd.Run(); err != nil {
		logger.Warn("Failed to collect static files", zap.Error(err))
	}

	// Compress static files
	compressCmd := exec.CommandContext(rc.Ctx, "python3", "/usr/share/openstack-dashboard/manage.py",
		"compress", "--force")
	compressCmd.Env = append(os.Environ(), "DJANGO_SETTINGS_MODULE=openstack_dashboard.settings")
	if err := compressCmd.Run(); err != nil {
		logger.Warn("Failed to compress static files", zap.Error(err))
	}

	// Restart Apache
	if err := restartService(rc, "apache2"); err != nil {
		return fmt.Errorf("failed to restart Apache: %w", err)
	}

	logger.Info("Horizon installation completed")
	return nil
}

// installHeat installs and configures the Heat orchestration service
func installHeat(rc *eos_io.RuntimeContext, config *Config) error {
	ctx, span := telemetry.Start(rc.Ctx, "openstack.installHeat")
	defer span.End()
	rc = &eos_io.RuntimeContext{Ctx: ctx}

	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Installing Heat orchestration service")

	// Install packages
	packages := []string{
		"heat-api",
		"heat-api-cfn",
		"heat-engine",
		"python3-heatclient",
	}

	if err := installPackages(rc, packages); err != nil {
		return fmt.Errorf("failed to install Heat packages: %w", err)
	}

	// Create database
	if err := createServiceDatabase(rc, "heat", config.DBPassword); err != nil {
		return fmt.Errorf("failed to create Heat database: %w", err)
	}

	// Configure Heat
	if err := configureHeat(rc, config); err != nil {
		return fmt.Errorf("failed to configure Heat: %w", err)
	}

	// Sync database
	syncCmd := exec.CommandContext(rc.Ctx, "heat-manage", "db_sync")
	if err := syncCmd.Run(); err != nil {
		return fmt.Errorf("failed to sync Heat database: %w", err)
	}

	// Start services
	heatServices := []string{"heat-api", "heat-api-cfn", "heat-engine"}
	for _, svc := range heatServices {
		if err := enableAndStartService(rc, svc); err != nil {
			return fmt.Errorf("failed to start %s: %w", svc, err)
		}
	}

	logger.Info("Heat installation completed")
	return nil
}

// Helper functions

func installPackages(rc *eos_io.RuntimeContext, packages []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Installing packages", zap.Int("count", len(packages)))

	installCmd := exec.CommandContext(rc.Ctx, "apt-get", "install", "-y")
	installCmd.Args = append(installCmd.Args, packages...)
	installCmd.Stdout = os.Stdout
	installCmd.Stderr = os.Stderr

	return installCmd.Run()
}

func createServiceDatabase(rc *eos_io.RuntimeContext, service, password string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Creating database", zap.String("service", service))

	// Create database
	createCmd := fmt.Sprintf(`mysql -u root -p%s -e "CREATE DATABASE IF NOT EXISTS %s;"`,
		password, service)
	if err := exec.CommandContext(rc.Ctx, "bash", "-c", createCmd).Run(); err != nil {
		return err
	}

	// Grant local privileges
	grantLocal := fmt.Sprintf(`mysql -u root -p%s -e "GRANT ALL PRIVILEGES ON %s.* TO '%s'@'localhost' IDENTIFIED BY '%s';"`,
		password, service, service, password)
	if err := exec.CommandContext(rc.Ctx, "bash", "-c", grantLocal).Run(); err != nil {
		return err
	}

	// Grant remote privileges
	grantRemote := fmt.Sprintf(`mysql -u root -p%s -e "GRANT ALL PRIVILEGES ON %s.* TO '%s'@'%%' IDENTIFIED BY '%s';"`,
		password, service, service, password)
	exec.CommandContext(rc.Ctx, "bash", "-c", grantRemote).Run()

	return nil
}

func enableAndStartService(rc *eos_io.RuntimeContext, service string) error {
	// Enable service
	enableCmd := exec.CommandContext(rc.Ctx, "systemctl", "enable", service)
	if err := enableCmd.Run(); err != nil {
		return fmt.Errorf("failed to enable %s: %w", service, err)
	}

	// Start service
	startCmd := exec.CommandContext(rc.Ctx, "systemctl", "start", service)
	if err := startCmd.Run(); err != nil {
		return fmt.Errorf("failed to start %s: %w", service, err)
	}

	return nil
}

func restartService(rc *eos_io.RuntimeContext, service string) error {
	restartCmd := exec.CommandContext(rc.Ctx, "systemctl", "restart", service)
	return restartCmd.Run()
}

func supportsKVM(rc *eos_io.RuntimeContext) bool {
	// Check for KVM support
	kvmCmd := exec.CommandContext(rc.Ctx, "kvm-ok")
	return kvmCmd.Run() == nil
}

// Service-specific configuration functions

func configureGlanceService(rc *eos_io.RuntimeContext, config *Config) error {
	// This would generate and write Glance configuration
	// Similar to generateServiceConfig in configure.go
	return nil
}

func configureNovaController(rc *eos_io.RuntimeContext, config *Config) error {
	// Configure Nova for controller node
	return nil
}

func configureNovaCompute(rc *eos_io.RuntimeContext, config *Config) error {
	// Configure Nova for compute node
	// Set hypervisor type, VNC settings, etc.
	return nil
}

func syncNovaDatabases(rc *eos_io.RuntimeContext, config *Config) error {
	// Sync Nova API database
	apiSync := exec.CommandContext(rc.Ctx, "nova-manage", "api_db", "sync")
	if err := apiSync.Run(); err != nil {
		return fmt.Errorf("failed to sync Nova API database: %w", err)
	}

	// Register cell0
	cell0Cmd := exec.CommandContext(rc.Ctx, "nova-manage", "cell_v2", "map_cell0")
	cell0Cmd.Run() // Ignore error if already exists

	// Create cell1
	cell1Cmd := exec.CommandContext(rc.Ctx, "nova-manage", "cell_v2", "create_cell",
		"--name=cell1", "--verbose")
	cell1Cmd.Run() // Ignore error if already exists

	// Sync main database
	dbSync := exec.CommandContext(rc.Ctx, "nova-manage", "db", "sync")
	if err := dbSync.Run(); err != nil {
		return fmt.Errorf("failed to sync Nova database: %w", err)
	}

	return nil
}

func createCellMappings(rc *eos_io.RuntimeContext) error {
	// Verify Nova cell mappings
	verifyCmd := exec.CommandContext(rc.Ctx, "nova-manage", "cell_v2", "list_cells")
	output, err := verifyCmd.Output()
	if err != nil {
		return fmt.Errorf("failed to list cells: %w", err)
	}

	// Check if cells are properly configured
	if !strings.Contains(string(output), "cell0") || !strings.Contains(string(output), "cell1") {
		return fmt.Errorf("Nova cells not properly configured")
	}

	return nil
}

func configureNeutronServer(rc *eos_io.RuntimeContext, config *Config) error {
	// Configure Neutron server
	// This is handled in configure.go
	return nil
}

func configureSwift(rc *eos_io.RuntimeContext, config *Config) error {
	// Configure Swift proxy and storage nodes
	return nil
}

func createSwiftRings(rc *eos_io.RuntimeContext, config *Config) error {
	// Create Swift rings for object distribution
	ringDir := "/etc/swift"
	
	// Create account ring
	accountCmd := exec.CommandContext(rc.Ctx, "swift-ring-builder",
		filepath.Join(ringDir, "account.builder"),
		"create", "10", "3", "1")
	if err := accountCmd.Run(); err != nil {
		return fmt.Errorf("failed to create account ring: %w", err)
	}

	// Create container ring
	containerCmd := exec.CommandContext(rc.Ctx, "swift-ring-builder",
		filepath.Join(ringDir, "container.builder"),
		"create", "10", "3", "1")
	if err := containerCmd.Run(); err != nil {
		return fmt.Errorf("failed to create container ring: %w", err)
	}

	// Create object ring
	objectCmd := exec.CommandContext(rc.Ctx, "swift-ring-builder",
		filepath.Join(ringDir, "object.builder"),
		"create", "10", "3", "1")
	if err := objectCmd.Run(); err != nil {
		return fmt.Errorf("failed to create object ring: %w", err)
	}

	return nil
}

func configureHorizon(rc *eos_io.RuntimeContext, config *Config) error {
	// Configure Horizon settings
	horizonConfig := fmt.Sprintf(`# OpenStack Dashboard Configuration
import os
from django.utils.translation import ugettext_lazy as _
from openstack_dashboard.settings import HORIZON_CONFIG

DEBUG = False
ALLOWED_HOSTS = ['*']

# OpenStack endpoints
OPENSTACK_HOST = "%s"
OPENSTACK_KEYSTONE_URL = "http://%%s:5000/v3" %% OPENSTACK_HOST
OPENSTACK_KEYSTONE_DEFAULT_ROLE = "member"

# API versions
OPENSTACK_API_VERSIONS = {
    "identity": 3,
    "image": 2,
    "volume": 3,
}

# Keystone settings
OPENSTACK_KEYSTONE_MULTIDOMAIN_SUPPORT = True
OPENSTACK_KEYSTONE_DEFAULT_DOMAIN = "Default"

# Networking
OPENSTACK_NEUTRON_NETWORK = {
    'enable_router': True,
    'enable_quotas': True,
    'enable_distributed_router': False,
    'enable_ha_router': False,
    'enable_fip_topology_check': True,
}

# Caching
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.memcached.PyMemcacheCache',
        'LOCATION': '%s:11211',
    }
}

# Session settings
SESSION_ENGINE = 'django.contrib.sessions.backends.cache'

# Time zone
TIME_ZONE = "UTC"

# Theme
DEFAULT_THEME = 'default'
`, strings.Split(config.InternalEndpoint, "://")[1], 
   strings.Split(config.InternalEndpoint, "://")[1])

	localSettingsPath := "/etc/openstack-dashboard/local_settings.py"
	return os.WriteFile(localSettingsPath, []byte(horizonConfig), 0644)
}

func configureApacheHorizon(rc *eos_io.RuntimeContext, config *Config) error {
	// Apache configuration is handled in the main Apache setup
	// This would add any Horizon-specific Apache configuration
	return nil
}

func configureHeat(rc *eos_io.RuntimeContext, config *Config) error {
	// Configure Heat orchestration service
	return nil
}