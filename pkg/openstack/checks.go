package openstack

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// checkNetworkConnectivity verifies network connectivity requirements
func checkNetworkConnectivity(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Checking network connectivity")

	// Check DNS resolution
	if err := checkDNSResolution(rc); err != nil {
		return fmt.Errorf("DNS resolution check failed: %w", err)
	}

	// Check internet connectivity (for package downloads)
	if err := checkInternetConnectivity(rc); err != nil {
		return fmt.Errorf("internet connectivity check failed: %w", err)
	}

	// Check management network
	if config.ManagementNetwork != "" {
		if err := validateNetworkCIDR(config.ManagementNetwork); err != nil {
			return fmt.Errorf("invalid management network CIDR: %w", err)
		}
	}

	// Check if provider interface exists
	if config.ProviderInterface != "" {
		if err := checkNetworkInterface(rc, config.ProviderInterface); err != nil {
			return fmt.Errorf("provider interface check failed: %w", err)
		}
	}

	// Check connectivity to controller (for non-controller nodes)
	if !config.IsControllerNode() && config.ControllerAddress != "" {
		if err := checkControllerConnectivity(rc, config.ControllerAddress); err != nil {
			return fmt.Errorf("cannot reach controller node: %w", err)
		}
	}

	return nil
}

// checkConflictingSoftware checks for software that might conflict with OpenStack
func checkConflictingSoftware(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Checking for conflicting software")

	conflicts := []struct {
		name    string
		process string
		port    int
	}{
		{"Docker", "dockerd", 0},
		{"Kubernetes", "kubelet", 0},
		{"Apache", "apache2", 80},
		{"Nginx", "nginx", 80},
		{"MySQL/MariaDB", "mysqld", 3306},
		{"PostgreSQL", "postgres", 5432},
		{"RabbitMQ", "rabbitmq-server", 5672},
	}

	var foundConflicts []string

	for _, conflict := range conflicts {
		// Check if process is running
		if conflict.process != "" {
			pidofCmd := exec.CommandContext(rc.Ctx, "pidof", conflict.process)
			if pidofCmd.Run() == nil {
				foundConflicts = append(foundConflicts, 
					fmt.Sprintf("%s (process: %s)", conflict.name, conflict.process))
			}
		}

		// Check if port is in use
		if conflict.port > 0 {
			if isPortInUse(conflict.port) {
				foundConflicts = append(foundConflicts,
					fmt.Sprintf("%s (port: %d)", conflict.name, conflict.port))
			}
		}
	}

	// Check for existing OpenStack services
	openstackServices := []string{
		"keystone", "glance-api", "nova-api", "neutron-server",
		"cinder-api", "swift-proxy", "heat-api",
	}

	for _, svc := range openstackServices {
		statusCmd := exec.CommandContext(rc.Ctx, "systemctl", "is-active", svc)
		if statusCmd.Run() == nil {
			foundConflicts = append(foundConflicts, fmt.Sprintf("OpenStack %s service", svc))
		}
	}

	if len(foundConflicts) > 0 {
		logger.Warn("Found potentially conflicting software",
			zap.Strings("conflicts", foundConflicts))
		return eos_err.NewUserError(
			"Found conflicting software:\n%s\n\nPlease stop or remove these before proceeding",
			strings.Join(foundConflicts, "\n"))
	}

	return nil
}

// checkDNSResolution verifies DNS is working
func checkDNSResolution(rc *eos_io.RuntimeContext) error {
	testDomains := []string{
		"github.com",
		"keyserver.ubuntu.com",
		"apt.releases.hashicorp.com",
	}

	for _, domain := range testDomains {
		_, err := net.LookupHost(domain)
		if err != nil {
			return fmt.Errorf("failed to resolve %s: %w", domain, err)
		}
	}

	return nil
}

// checkInternetConnectivity verifies internet access
func checkInternetConnectivity(rc *eos_io.RuntimeContext) error {
	// Try to reach common package repositories
	testURLs := []string{
		"8.8.8.8",        // Google DNS
		"1.1.1.1",        // Cloudflare DNS
		"archive.ubuntu.com", // Ubuntu archive
	}

	for _, url := range testURLs {
		pingCmd := exec.CommandContext(rc.Ctx, "ping", "-c", "1", "-W", "2", url)
		if pingCmd.Run() == nil {
			return nil // At least one is reachable
		}
	}

	return fmt.Errorf("no internet connectivity detected")
}

// checkNetworkInterface verifies a network interface exists and is up
func checkNetworkInterface(rc *eos_io.RuntimeContext, ifaceName string) error {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("interface %s not found: %w", ifaceName, err)
	}

	if iface.Flags&net.FlagUp == 0 {
		return fmt.Errorf("interface %s is not up", ifaceName)
	}

	// Check if interface has an IP address
	addrs, err := iface.Addrs()
	if err != nil {
		return fmt.Errorf("failed to get addresses for %s: %w", ifaceName, err)
	}

	if len(addrs) == 0 {
		// Interface might be used for provider network, so no IP is OK
		otelzap.Ctx(nil).Debug("Interface has no IP addresses",
			zap.String("interface", ifaceName))
	}

	return nil
}

// checkControllerConnectivity verifies connectivity to controller node
func checkControllerConnectivity(rc *eos_io.RuntimeContext, controllerAddr string) error {
	// Extract host from address (remove protocol if present)
	host := controllerAddr
	if strings.Contains(host, "://") {
		parts := strings.Split(host, "://")
		host = parts[1]
	}

	// Remove port if present
	if strings.Contains(host, ":") {
		hostPort := strings.Split(host, ":")
		host = hostPort[0]
	}

	// Ping test
	pingCmd := exec.CommandContext(rc.Ctx, "ping", "-c", "2", "-W", "2", host)
	if err := pingCmd.Run(); err != nil {
		return fmt.Errorf("cannot ping controller at %s", host)
	}

	// Check critical ports
	criticalPorts := []int{
		3306,  // MySQL
		5672,  // RabbitMQ
		11211, // Memcached
		5000,  // Keystone
	}

	for _, port := range criticalPorts {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 2)
		if err == nil {
			conn.Close()
		}
		// Don't fail if ports aren't open yet - controller might not be fully configured
	}

	return nil
}

// validateNetworkCIDR validates a network CIDR notation
func validateNetworkCIDR(cidr string) error {
	_, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR notation: %w", err)
	}
	return nil
}

// isPortInUse checks if a TCP port is already in use
func isPortInUse(port int) bool {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return true // Port is in use
	}
	ln.Close()
	return false
}

// checkRepositories verifies package repositories are accessible
func configureRepositories(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Configuring package repositories")

	// Detect OS
	codename := eos_unix.GetUbuntuCodename(rc)
	
	// Check if we're on Ubuntu
	if codename != "" {
		// Ubuntu detected
		return configureUbuntuRepositories(rc, codename)
	}
	
	// Check for other distributions by examining /etc/os-release
	osReleaseData, err := execute.Run(rc.Ctx, execute.Options{
		Command: "cat",
		Args:    []string{"/etc/os-release"},
	})
	if err != nil {
		logger.Warn("Could not determine OS, skipping repository configuration", zap.Error(err))
		return nil
	}
	
	osRelease := string(osReleaseData)
	if strings.Contains(osRelease, "ID=debian") {
		return configureDebianRepositories(rc, "")
	} else if strings.Contains(osRelease, "ID=rhel") || strings.Contains(osRelease, "ID=centos") || 
	           strings.Contains(osRelease, "ID=rocky") || strings.Contains(osRelease, "ID=almalinux") {
		return configureRHELRepositories(rc, "")
	}
	
	logger.Warn("Unknown OS, skipping repository configuration")
	return nil
}

// configureUbuntuRepositories adds Ubuntu Cloud Archive repository
func configureUbuntuRepositories(rc *eos_io.RuntimeContext, version string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Map Ubuntu version to OpenStack release
	var cloudArchive string
	switch version {
	case "20.04":
		cloudArchive = "cloud-archive:wallaby"
	case "22.04":
		cloudArchive = "cloud-archive:2024.1"
	case "24.04":
		// Latest Ubuntu usually has current OpenStack
		return nil
	default:
		cloudArchive = "cloud-archive:2024.1"
	}

	// Add cloud archive repository
	logger.Info("Adding Ubuntu Cloud Archive repository", zap.String("archive", cloudArchive))
	
	// Install software-properties-common if needed
	installCmd := exec.CommandContext(rc.Ctx, "apt-get", "install", "-y", "software-properties-common")
	if err := installCmd.Run(); err != nil {
		return fmt.Errorf("failed to install software-properties-common: %w", err)
	}

	// Add cloud archive
	addRepoCmd := exec.CommandContext(rc.Ctx, "add-apt-repository", "-y", cloudArchive)
	if err := addRepoCmd.Run(); err != nil {
		return fmt.Errorf("failed to add cloud archive: %w", err)
	}

	// Update package index
	updateCmd := exec.CommandContext(rc.Ctx, "apt-get", "update")
	if err := updateCmd.Run(); err != nil {
		return fmt.Errorf("failed to update package index: %w", err)
	}

	return nil
}

// configureDebianRepositories adds Debian repositories for OpenStack
func configureDebianRepositories(rc *eos_io.RuntimeContext, version string) error {
	// Debian typically has OpenStack packages in main repository
	// May need backports for newer versions
	
	versionFloat, _ := strconv.ParseFloat(version, 64)
	if versionFloat < 11 {
		return fmt.Errorf("Debian %s is too old for OpenStack 2024.1", version)
	}

	// Add backports if needed
	if versionFloat == 11 {
		backportsLine := "deb http://deb.debian.org/debian bullseye-backports main"
		backportsFile := "/etc/apt/sources.list.d/backports.list"
		
		if err := os.WriteFile(backportsFile, []byte(backportsLine+"\n"), 0644); err != nil {
			return fmt.Errorf("failed to add backports: %w", err)
		}
	}

	return nil
}

// configureRHELRepositories adds RHEL/CentOS repositories for OpenStack
func configureRHELRepositories(rc *eos_io.RuntimeContext, version string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Install RDO repository
	var rdoRelease string
	versionMajor := strings.Split(version, ".")[0]
	
	switch versionMajor {
	case "8":
		rdoRelease = "https://www.rdoproject.org/repos/rdo-release.el8.rpm"
	case "9":
		rdoRelease = "https://www.rdoproject.org/repos/rdo-release.el9.rpm"
	default:
		return fmt.Errorf("unsupported RHEL/CentOS version: %s", version)
	}

	logger.Info("Installing RDO repository", zap.String("release", rdoRelease))
	
	// Install RDO release package
	installCmd := exec.CommandContext(rc.Ctx, "dnf", "install", "-y", rdoRelease)
	if err := installCmd.Run(); err != nil {
		// Try with yum if dnf fails
		installCmd = exec.CommandContext(rc.Ctx, "yum", "install", "-y", rdoRelease)
		if err := installCmd.Run(); err != nil {
			return fmt.Errorf("failed to install RDO repository: %w", err)
		}
	}

	// Install OpenStack release package
	releaseCmd := exec.CommandContext(rc.Ctx, "dnf", "install", "-y", "centos-release-openstack-2024.1")
	if err := releaseCmd.Run(); err != nil {
		logger.Warn("Failed to install OpenStack release package", zap.Error(err))
	}

	return nil
}

// setupPythonEnvironment ensures Python 3 and pip are properly configured
func setupPythonEnvironment(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Setting up Python environment")

	// Ensure Python 3 is installed
	pythonCmd := exec.CommandContext(rc.Ctx, "python3", "--version")
	if err := pythonCmd.Run(); err != nil {
		return fmt.Errorf("Python 3 is not installed")
	}

	// Ensure pip is installed
	pipCmd := exec.CommandContext(rc.Ctx, "pip3", "--version")
	if err := pipCmd.Run(); err != nil {
		// Try to install pip
		installPipCmd := exec.CommandContext(rc.Ctx, "apt-get", "install", "-y", "python3-pip")
		if err := installPipCmd.Run(); err != nil {
			return fmt.Errorf("failed to install pip3: %w", err)
		}
	}

	// Install/upgrade essential Python packages
	essentialPackages := []string{
		"setuptools",
		"wheel",
		"pip",
	}

	for _, pkg := range essentialPackages {
		upgradeCmd := exec.CommandContext(rc.Ctx, "pip3", "install", "--upgrade", pkg)
		if err := upgradeCmd.Run(); err != nil {
			logger.Warn("Failed to upgrade Python package",
				zap.String("package", pkg),
				zap.Error(err))
		}
	}

	return nil
}

// configureTimeSynchronization ensures time sync is configured
func configureTimeSynchronization(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Configuring time synchronization")

	// Check if chrony is installed
	chronyCheck := exec.CommandContext(rc.Ctx, "which", "chrony")
	if chronyCheck.Run() != nil {
		// Install chrony
		installCmd := exec.CommandContext(rc.Ctx, "apt-get", "install", "-y", "chrony")
		if err := installCmd.Run(); err != nil {
			// Try NTP as fallback
			installCmd = exec.CommandContext(rc.Ctx, "apt-get", "install", "-y", "ntp")
			if err := installCmd.Run(); err != nil {
				return fmt.Errorf("failed to install time synchronization service: %w", err)
			}
		}
	}

	// Configure chrony for OpenStack
	chronyConfig := `# OpenStack time synchronization configuration
server 0.pool.ntp.org iburst
server 1.pool.ntp.org iburst
server 2.pool.ntp.org iburst
server 3.pool.ntp.org iburst

# Allow NTP client access from local network
allow 10.0.0.0/8
allow 172.16.0.0/12
allow 192.168.0.0/16

# Serve time even if not synchronized to a time source
local stratum 10
`

	chronyConfigPath := "/etc/chrony/chrony.conf"
	if err := appendToFile(chronyConfigPath, chronyConfig); err != nil {
		logger.Warn("Failed to update chrony configuration", zap.Error(err))
	}

	// Restart chrony
	restartCmd := exec.CommandContext(rc.Ctx, "systemctl", "restart", "chrony")
	if err := restartCmd.Run(); err != nil {
		// Try NTP service
		restartCmd = exec.CommandContext(rc.Ctx, "systemctl", "restart", "ntp")
		_ = restartCmd.Run()
	}

	return nil
}

// appendToFile appends content to a file if it doesn't already exist
func appendToFile(filename, content string) error {
	// Read existing content
	existing, err := os.ReadFile(filename)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	// Check if content already exists
	if strings.Contains(string(existing), "OpenStack time synchronization") {
		return nil // Already configured
	}

	// Append new content
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	_, err = f.WriteString("\n" + content)
	return err
}