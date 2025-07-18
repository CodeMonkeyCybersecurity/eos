package openstack

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/telemetry"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Install performs the complete OpenStack installation following ASSESS → INTERVENE → EVALUATE
func Install(rc *eos_io.RuntimeContext, config *Config) error {
	ctx, span := telemetry.Start(rc.Ctx, "openstack.Install")
	defer span.End()
	rc = &eos_io.RuntimeContext{Ctx: ctx}

	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting OpenStack installation",
		zap.String("mode", string(config.Mode)),
		zap.String("version", getTargetVersion()))

	// ASSESS - Check system state and prerequisites
	logger.Info("ASSESS: Checking system prerequisites")
	if err := assessSystemState(rc, config); err != nil {
		return fmt.Errorf("system assessment failed: %w", err)
	}

	// Create backup if requested
	if config.Backup {
		if err := createBackup(rc, config); err != nil {
			logger.Warn("Failed to create backup", zap.Error(err))
		}
	}

	// INTERVENE - Perform installation steps
	logger.Info("INTERVENE: Beginning OpenStack installation")

	// Step 1: Prepare system
	if err := prepareSystem(rc, config); err != nil {
		return fmt.Errorf("system preparation failed: %w", err)
	}

	// Step 2: Install base packages
	if err := installBasePackages(rc, config); err != nil {
		return fmt.Errorf("base package installation failed: %w", err)
	}

	// Step 3: Configure databases
	if config.IsControllerNode() {
		if err := configureDatabases(rc, config); err != nil {
			return fmt.Errorf("database configuration failed: %w", err)
		}
	}

	// Step 4: Configure message queue
	if config.IsControllerNode() {
		if err := configureMessageQueue(rc, config); err != nil {
			return fmt.Errorf("message queue configuration failed: %w", err)
		}
	}

	// Step 5: Install and configure services
	services := config.GetEnabledServices()
	for _, service := range services {
		logger.Info("Installing service", zap.String("service", string(service)))
		if err := installService(rc, config, service); err != nil {
			return fmt.Errorf("failed to install %s: %w", service, err)
		}
	}

	// Step 6: Configure networking
	if err := configureNetworking(rc, config); err != nil {
		return fmt.Errorf("networking configuration failed: %w", err)
	}

	// Step 7: Configure storage
	if err := configureStorage(rc, config); err != nil {
		return fmt.Errorf("storage configuration failed: %w", err)
	}

	// Step 8: Apply security hardening
	if err := applySecurityHardening(rc, config); err != nil {
		return fmt.Errorf("security hardening failed: %w", err)
	}

	// Step 9: Configure integrations
	if err := configureIntegrations(rc, config); err != nil {
		return fmt.Errorf("integration configuration failed: %w", err)
	}

	// EVALUATE - Verify installation
	logger.Info("EVALUATE: Verifying OpenStack installation")
	if err := verifyInstallation(rc, config); err != nil {
		return fmt.Errorf("installation verification failed: %w", err)
	}

	// Save installation state
	if err := saveInstallationState(rc, config); err != nil {
		logger.Warn("Failed to save installation state", zap.Error(err))
	}

	logger.Info("OpenStack installation completed successfully")
	return nil
}

// assessSystemState checks if the system meets prerequisites
func assessSystemState(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check OS compatibility
	if err := checkOSCompatibility(rc); err != nil {
		return err
	}

	// Check system resources
	if err := checkSystemResources(rc, config); err != nil {
		return err
	}

	// Check network connectivity
	if err := checkNetworkConnectivity(rc, config); err != nil {
		return err
	}

	// Check for conflicting software
	if err := checkConflictingSoftware(rc); err != nil {
		return err
	}

	logger.Info("System assessment completed successfully")
	return nil
}

// prepareSystem prepares the system for OpenStack installation
func prepareSystem(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Create directories
	dirs := []string{
		OpenStackBaseDir,
		OpenStackConfigDir,
		OpenStackLogDir,
		OpenStackStateDir,
		OpenStackBackupDir,
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	// Create OpenStack user and group
	if err := createOpenStackUser(rc); err != nil {
		return fmt.Errorf("failed to create OpenStack user: %w", err)
	}

	// Configure repositories
	if err := configureRepositories(rc, config); err != nil {
		return fmt.Errorf("failed to configure repositories: %w", err)
	}

	// Update system packages
	logger.Info("Updating system packages")
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "sudo",
		Args:    []string{"apt-get", "update", "-y"},
	}); err != nil {
		return fmt.Errorf("failed to update packages: %w", err)
	}

	// Install prerequisites
	prerequisites := []string{
		"software-properties-common",
		"python3-pip",
		"python3-dev",
		"libffi-dev",
		"gcc",
		"libssl-dev",
		"git",
		"curl",
		"wget",
		"gnupg",
		"lsb-release",
		"ca-certificates",
		"apt-transport-https",
	}

	args := []string{"apt-get", "install", "-y"}
	args = append(args, prerequisites...)
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "sudo",
		Args:    args,
	}); err != nil {
		return fmt.Errorf("failed to install prerequisites: %w", err)
	}

	// Set up Python environment
	if err := setupPythonEnvironment(rc); err != nil {
		return fmt.Errorf("failed to setup Python environment: %w", err)
	}

	logger.Info("System preparation completed")
	return nil
}

// installBasePackages installs the base OpenStack packages
func installBasePackages(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Common packages for all nodes
	basePackages := []string{
		"openstack-selinux",
		"python3-openstackclient",
		"openstack-utils",
		"ntp",
		"chrony",
	}

	// Add packages based on deployment mode
	switch config.Mode {
	case ModeAllInOne, ModeController:
		basePackages = append(basePackages,
			"mariadb-server",
			"python3-pymysql",
			"rabbitmq-server",
			"memcached",
			"python3-memcache",
			"etcd",
		)
	}

	logger.Info("Installing base packages", zap.Int("count", len(basePackages)))
	
	args := []string{"apt-get", "install", "-y"}
	args = append(args, basePackages...)
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "sudo",
		Args:    args,
	}); err != nil {
		return fmt.Errorf("failed to install base packages: %w", err)
	}

	// Configure time synchronization
	if err := configureTimeSynchronization(rc, config); err != nil {
		return fmt.Errorf("failed to configure time synchronization: %w", err)
	}

	return nil
}

// installService installs and configures a specific OpenStack service
func installService(rc *eos_io.RuntimeContext, config *Config, service Service) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Installing OpenStack service", zap.String("service", string(service)))

	switch service {
	case ServiceKeystone:
		return installKeystone(rc, config)
	case ServiceGlance:
		return installGlance(rc, config)
	case ServiceNova:
		return installNova(rc, config)
	case ServiceNeutron:
		return installNeutron(rc, config)
	case ServiceCinder:
		return installCinder(rc, config)
	case ServiceSwift:
		return installSwift(rc, config)
	case ServiceHorizon:
		return installHorizon(rc, config)
	case ServiceHeat:
		return installHeat(rc, config)
	default:
		return fmt.Errorf("unknown service: %s", service)
	}
}

// configureIntegrations sets up Vault and Consul integrations
func configureIntegrations(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	if config.VaultIntegration {
		logger.Info("Configuring Vault integration")
		if err := configureVaultIntegration(rc, config); err != nil {
			return fmt.Errorf("Vault integration failed: %w", err)
		}
	}

	if config.ConsulIntegration {
		logger.Info("Configuring Consul integration")
		if err := configureConsulIntegration(rc, config); err != nil {
			return fmt.Errorf("Consul integration failed: %w", err)
		}
	}

	return nil
}

// verifyInstallation performs comprehensive verification of the installation
func verifyInstallation(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Verifying OpenStack installation")

	// Check all services are running
	services := config.GetEnabledServices()
	for _, service := range services {
		if err := verifyService(rc, config, service); err != nil {
			return fmt.Errorf("service %s verification failed: %w", service, err)
		}
	}

	// Verify API endpoints
	if err := verifyAPIEndpoints(rc, config); err != nil {
		return fmt.Errorf("API endpoint verification failed: %w", err)
	}

	// Run basic functionality tests
	if config.IsControllerNode() {
		if err := runFunctionalityTests(rc, config); err != nil {
			return fmt.Errorf("functionality tests failed: %w", err)
		}
	}

	logger.Info("Installation verification completed successfully")
	return nil
}

// saveInstallationState saves the current installation state for future reference
func saveInstallationState(rc *eos_io.RuntimeContext, config *Config) error {
	stateFile := filepath.Join(OpenStackStateDir, "installation.json")
	
	state := &InstallationStatus{
		Installed:   true,
		Version:     getTargetVersion(),
		Mode:        config.Mode,
		LastUpdated: time.Now(),
	}

	// Gather service status
	for _, service := range config.GetEnabledServices() {
		status, _ := getServiceStatus(rc, service)
		state.Services = append(state.Services, status)
	}

	// Save to file
	return eos_io.WriteYAML(rc.Ctx, stateFile, state)
}

// Helper functions

func getTargetVersion() string {
	// In a real implementation, this would determine the OpenStack version
	// based on the distribution and available packages
	return "2024.1" // Caracal release
}

func createOpenStackUser(rc *eos_io.RuntimeContext) error {
	// Check if user exists
	if eos_unix.UserExists(rc, OpenStackUser) {
		// User already exists
		return nil
	}

	// Create group first
	if err := execute.RunSimple(rc.Ctx, "sudo", "groupadd", "-r", OpenStackGroup); err != nil {
		// Ignore error if group exists
		logger := otelzap.Ctx(rc.Ctx)
		logger.Debug("Group creation failed (may already exist)", zap.Error(err))
	}

	// Create user
	if err := eos_unix.CreateUser(rc, OpenStackUser, true, "/bin/false"); err != nil {
		return fmt.Errorf("failed to create OpenStack user: %w", err)
	}
	
	return nil
}

func checkOSCompatibility(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Check if we're on Ubuntu (primary supported OS)
	codename := eos_unix.GetUbuntuCodename(rc)
	if codename != "" {
		// Check Ubuntu version - support 20.04 (focal) and later
		supportedCodenames := []string{"focal", "jammy", "noble"}
		for _, supported := range supportedCodenames {
			if strings.Contains(strings.ToLower(codename), supported) {
				logger.Info("Detected supported Ubuntu version", zap.String("codename", codename))
				return nil
			}
		}
		return eos_err.NewUserError("Unsupported Ubuntu version: %s. OpenStack requires Ubuntu 20.04 (Focal) or later", codename)
	}
	
	// Check for other supported distributions by examining /etc/os-release
	osReleaseData, err := execute.Run(rc.Ctx, execute.Options{
		Command: "cat",
		Args:    []string{"/etc/os-release"},
	})
	if err != nil {
		return fmt.Errorf("failed to determine OS: %w", err)
	}
	
	osRelease := string(osReleaseData)
	if strings.Contains(osRelease, "ID=rhel") || strings.Contains(osRelease, "ID=centos") {
		// Check for RHEL/CentOS 8+
		if strings.Contains(osRelease, "VERSION_ID=\"8") || strings.Contains(osRelease, "VERSION_ID=\"9") {
			logger.Info("Detected supported RHEL/CentOS version")
			return nil
		}
	}
	
	if strings.Contains(osRelease, "ID=debian") {
		// Check for Debian 11+
		if strings.Contains(osRelease, "VERSION_ID=\"11") || strings.Contains(osRelease, "VERSION_ID=\"12") {
			logger.Info("Detected supported Debian version")
			return nil
		}
	}
	
	return eos_err.NewUserError("Unsupported operating system. OpenStack requires Ubuntu 20.04+, RHEL/CentOS 8+, or Debian 11+")
}

func checkSystemResources(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Check minimum resource requirements based on deployment mode
	var minRAM, minDisk int

	switch config.Mode {
	case ModeAllInOne:
		minRAM = 16
		minDisk = 100
	case ModeController:
		minRAM = 8
		minDisk = 50
	case ModeCompute:
		minRAM = 8
		minDisk = 50
	case ModeStorage:
		minRAM = 4
		minDisk = 100
	}

	// Collect system information
	sysInfo, err := system.CollectSystemInfo(rc)
	if err != nil {
		return fmt.Errorf("failed to collect system info: %w", err)
	}

	// Check memory - parse from free command output or /proc/meminfo
	memOutput, err := execute.Run(rc.Ctx, execute.Options{
		Command: "free",
		Args:    []string{"-g"},
	})
	if err != nil {
		return fmt.Errorf("failed to check memory: %w", err)
	}
	
	// Parse memory from output (this is a simplified check)
	memLines := strings.Split(string(memOutput), "\n")
	var totalRAM int
	for _, line := range memLines {
		if strings.HasPrefix(line, "Mem:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				fmt.Sscanf(fields[1], "%d", &totalRAM)
				break
			}
		}
	}
	
	if totalRAM < minRAM {
		return eos_err.NewUserError("Insufficient RAM: %dGB available, %dGB required", 
			totalRAM, minRAM)
	}
	
	// Check disk space - parse df output from sysInfo.DiskUsage
	dfLines := strings.Split(sysInfo.DiskUsage, "\n")
	var rootDiskAvailableGB int
	for _, line := range dfLines {
		if strings.Contains(line, " /") || strings.HasSuffix(line, " /") {
			fields := strings.Fields(line)
			if len(fields) >= 4 {
				// Parse available space (field 3) - remove unit suffix
				availStr := strings.TrimSuffix(fields[3], "G")
				availStr = strings.TrimSuffix(availStr, "M")
				availStr = strings.TrimSuffix(availStr, "K")
				if avail, err := strconv.ParseFloat(availStr, 64); err == nil {
					if strings.HasSuffix(fields[3], "G") {
						rootDiskAvailableGB = int(avail)
					} else if strings.HasSuffix(fields[3], "M") {
						rootDiskAvailableGB = int(avail / 1024)
					} else if strings.HasSuffix(fields[3], "T") {
						rootDiskAvailableGB = int(avail * 1024)
					}
				}
				break
			}
		}
	}
	
	if rootDiskAvailableGB < minDisk {
		return eos_err.NewUserError("Insufficient disk space: %dGB available, %dGB required",
			rootDiskAvailableGB, minDisk)
	}
	
	logger.Info("System resources check passed",
		zap.Int("total_ram_gb", totalRAM),
		zap.Int("required_ram_gb", minRAM),
		zap.Int("required_disk_gb", minDisk))

	return nil
}