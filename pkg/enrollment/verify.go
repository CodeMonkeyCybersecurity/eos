// pkg/enrollment/verify.go
package enrollment

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// VerifyEnrollment verifies that the enrollment was successful
func VerifyEnrollment(rc *eos_io.RuntimeContext, config *EnrollmentConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Starting enrollment verification",
		zap.String("role", config.Role),
		zap.String("master_address", config.MasterAddress))
	
	// Run verification tests
	tests := []VerificationTest{
		{
			Name:        "Salt installation",
			Description: "Verify Salt is installed and configured",
			TestFunc:    func() error { return verifySaltInstallation(rc, config) },
		},
		{
			Name:        "Service status",
			Description: "Verify Salt services are running",
			TestFunc:    func() error { return verifySaltServices(rc, config) },
		},
		{
			Name:        "Network connectivity",
			Description: "Test network connectivity to master",
			TestFunc:    func() error { return verifyNetworkConnectivity(rc, config) },
		},
		{
			Name:        "Key management",
			Description: "Verify Salt key management",
			TestFunc:    func() error { return verifySaltKeys(rc, config) },
		},
		{
			Name:        "Basic functionality",
			Description: "Test basic Salt functionality",
			TestFunc:    func() error { return verifyBasicFunctionality(rc, config) },
		},
	}
	
	// Run all tests
	var failures []string
	for _, test := range tests {
		logger.Info("Running verification test", zap.String("test", test.Name))
		
		if err := test.TestFunc(); err != nil {
			logger.Error("Verification test failed", 
				zap.String("test", test.Name),
				zap.Error(err))
			failures = append(failures, fmt.Sprintf("%s: %v", test.Name, err))
		} else {
			logger.Info("Verification test passed", zap.String("test", test.Name))
		}
	}
	
	if len(failures) > 0 {
		return fmt.Errorf("verification failed: %s", strings.Join(failures, "; "))
	}
	
	logger.Info("Enrollment verification completed successfully")
	return nil
}

// VerificationTest represents a verification test
type VerificationTest struct {
	Name        string
	Description string
	TestFunc    func() error
}

// verifySaltInstallation verifies Salt installation
func verifySaltInstallation(rc *eos_io.RuntimeContext, config *EnrollmentConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Check salt-minion is installed
	if _, err := exec.LookPath("salt-minion"); err != nil {
		return fmt.Errorf("salt-minion not found in PATH")
	}
	
	// Check salt-master if needed
	if config.Role == RoleMaster {
		if _, err := exec.LookPath("salt-master"); err != nil {
			return fmt.Errorf("salt-master not found in PATH")
		}
	}
	
	// Check version
	cmd := exec.Command("salt-minion", "--version")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to get salt-minion version: %w", err)
	}
	
	version := strings.TrimSpace(string(output))
	logger.Debug("Salt version verified", zap.String("version", version))
	
	// Check configuration files exist
	configFiles := []string{"/etc/salt/minion"}
	if config.Role == RoleMaster {
		configFiles = append(configFiles, "/etc/salt/master")
	}
	
	for _, configFile := range configFiles {
		if _, err := os.Stat(configFile); err != nil {
			return fmt.Errorf("configuration file not found: %s", configFile)
		}
	}
	
	return nil
}

// verifySaltServices verifies Salt services are running
func verifySaltServices(rc *eos_io.RuntimeContext, config *EnrollmentConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	services := []string{"salt-minion"}
	if config.Role == RoleMaster {
		services = append(services, "salt-master")
	}
	
	for _, service := range services {
		// Check if service is active
		cmd := exec.Command("systemctl", "is-active", service)
		output, err := cmd.Output()
		if err != nil {
			return fmt.Errorf("failed to check service status for %s: %w", service, err)
		}
		
		status := strings.TrimSpace(string(output))
		if status != "active" {
			return fmt.Errorf("service %s is not active (status: %s)", service, status)
		}
		
		// Check if service is enabled
		cmd = exec.Command("systemctl", "is-enabled", service)
		output, err = cmd.Output()
		if err != nil {
			logger.Warn("Failed to check if service is enabled", 
				zap.String("service", service),
				zap.Error(err))
			continue
		}
		
		enabled := strings.TrimSpace(string(output))
		if enabled != "enabled" {
			logger.Warn("Service is not enabled for boot", 
				zap.String("service", service),
				zap.String("status", enabled))
		}
	}
	
	return nil
}

// verifyNetworkConnectivity verifies network connectivity
func verifyNetworkConnectivity(rc *eos_io.RuntimeContext, config *EnrollmentConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Skip network tests if no master address (masterless mode)
	if config.MasterAddress == "" {
		logger.Info("No master address specified, skipping network connectivity tests")
		return nil
	}
	
	// Test Salt ports
	saltPorts := []int{SaltPublisherPort, SaltRequestPort}
	for _, port := range saltPorts {
		if err := testConnectivity(rc, config.MasterAddress, port); err != nil {
			return fmt.Errorf("failed to connect to master port %d: %w", port, err)
		}
	}
	
	// Test DNS resolution
	if err := testDNSResolution(rc, config.MasterAddress); err != nil {
		return fmt.Errorf("DNS resolution failed for master: %w", err)
	}
	
	return nil
}

// testDNSResolution tests DNS resolution for the master address
func testDNSResolution(rc *eos_io.RuntimeContext, masterAddr string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	cmd := exec.Command("nslookup", masterAddr)
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("nslookup failed: %w", err)
	}
	
	if strings.Contains(string(output), "can't find") || strings.Contains(string(output), "NXDOMAIN") {
		return fmt.Errorf("DNS resolution failed for %s", masterAddr)
	}
	
	logger.Debug("DNS resolution successful", zap.String("master", masterAddr))
	return nil
}

// verifySaltKeys verifies Salt key management
func verifySaltKeys(rc *eos_io.RuntimeContext, config *EnrollmentConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Check minion key exists
	minionKeyPath := "/etc/salt/pki/minion/minion.pem"
	if _, err := os.Stat(minionKeyPath); err != nil {
		return fmt.Errorf("minion private key not found: %s", minionKeyPath)
	}
	
	minionPubKeyPath := "/etc/salt/pki/minion/minion.pub"
	if _, err := os.Stat(minionPubKeyPath); err != nil {
		return fmt.Errorf("minion public key not found: %s", minionPubKeyPath)
	}
	
	// For master, check master keys
	if config.Role == RoleMaster {
		masterKeyPath := "/etc/salt/pki/master/master.pem"
		if _, err := os.Stat(masterKeyPath); err != nil {
			return fmt.Errorf("master private key not found: %s", masterKeyPath)
		}
		
		masterPubKeyPath := "/etc/salt/pki/master/master.pub"
		if _, err := os.Stat(masterPubKeyPath); err != nil {
			return fmt.Errorf("master public key not found: %s", masterPubKeyPath)
		}
	}
	
	// Try to get minion fingerprint
	if fingerprint, err := GetSaltKeyFingerprint(rc); err != nil {
		logger.Warn("Failed to get key fingerprint", zap.Error(err))
	} else {
		logger.Info("Salt key fingerprint", zap.String("fingerprint", fingerprint))
	}
	
	return nil
}

// verifyBasicFunctionality tests basic Salt functionality
func verifyBasicFunctionality(rc *eos_io.RuntimeContext, config *EnrollmentConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Test basic salt-call functionality
	tests := []struct {
		name string
		cmd  []string
		desc string
	}{
		{
			name: "grains",
			cmd:  []string{"salt-call", "--local", "grains.get", "os"},
			desc: "Get OS grain",
		},
		{
			name: "test_ping",
			cmd:  []string{"salt-call", "--local", "test.ping"},
			desc: "Test ping function",
		},
		{
			name: "disk_usage",
			cmd:  []string{"salt-call", "--local", "disk.usage", "/"},
			desc: "Get disk usage",
		},
	}
	
	for _, test := range tests {
		logger.Debug("Testing salt-call function", zap.String("test", test.name))
		
		cmd := exec.Command(test.cmd[0], test.cmd[1:]...)
		output, err := cmd.Output()
		if err != nil {
			return fmt.Errorf("salt-call test '%s' failed: %w", test.name, err)
		}
		
		// Check for basic success indicators
		outputStr := string(output)
		if strings.Contains(outputStr, "ERROR") || strings.Contains(outputStr, "CRITICAL") {
			return fmt.Errorf("salt-call test '%s' returned error: %s", test.name, outputStr)
		}
		
		logger.Debug("Salt-call test successful", 
			zap.String("test", test.name),
			zap.String("output", strings.TrimSpace(outputStr)))
	}
	
	// Test master connectivity if not masterless
	if config.Role == RoleMinion && config.MasterAddress != "" {
		logger.Debug("Testing master connectivity")
		
		// Test simple command to master
		cmd := exec.Command("salt-call", "test.ping")
		output, err := cmd.Output()
		if err != nil {
			logger.Warn("Failed to ping master", zap.Error(err))
			// Don't fail here as key might not be accepted yet
		} else {
			logger.Debug("Master ping successful", zap.String("output", string(output)))
		}
	}
	
	return nil
}

// VerifyNetworkRequirements verifies network requirements are met
func VerifyNetworkRequirements(rc *eos_io.RuntimeContext, config *EnrollmentConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Test DNS resolution
	if err := testDNSResolution(rc, "google.com"); err != nil {
		return fmt.Errorf("basic DNS resolution failed: %w", err)
	}
	
	// Test outbound internet connectivity
	if err := testInternetConnectivity(rc); err != nil {
		logger.Warn("Internet connectivity test failed", zap.Error(err))
		// Don't fail enrollment for this
	}
	
	// Test required ports are available
	if config.Role == RoleMaster {
		requiredPorts := []int{SaltPublisherPort, SaltRequestPort}
		for _, port := range requiredPorts {
			if err := testPortAvailable(port); err != nil {
				return fmt.Errorf("required port %d not available: %w", port, err)
			}
		}
	}
	
	return nil
}

// testInternetConnectivity tests outbound internet connectivity
func testInternetConnectivity(rc *eos_io.RuntimeContext) error {
	// Test connection to common servers
	servers := []string{
		"8.8.8.8:53",    // Google DNS
		"1.1.1.1:53",    // Cloudflare DNS
		"github.com:443", // GitHub HTTPS
	}
	
	for _, server := range servers {
		if err := testNetworkConnectivity(server); err == nil {
			return nil // At least one worked
		}
	}
	
	return fmt.Errorf("no internet connectivity detected")
}

// testPortAvailable tests if a port is available for binding
func testPortAvailable(port int) error {
	cmd := exec.Command("nc", "-z", "127.0.0.1", fmt.Sprintf("%d", port))
	if err := cmd.Run(); err == nil {
		return fmt.Errorf("port %d is already in use", port)
	}
	
	return nil // Port is available
}

// VerifyPrerequisites verifies system prerequisites
func VerifyPrerequisites(rc *eos_io.RuntimeContext, info *SystemInfo) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Check minimum resources
	if !info.HasSufficientResources() {
		return fmt.Errorf("insufficient system resources: %dGB RAM, %dGB disk, %d CPU cores", 
			info.MemoryGB, info.DiskSpaceGB, info.CPUCores)
	}
	
	// Check supported platform
	if info.Platform != "linux" {
		return fmt.Errorf("unsupported platform: %s (only linux is supported)", info.Platform)
	}
	
	// Check disk space
	if info.DiskSpaceGB < 10 {
		return fmt.Errorf("insufficient disk space: %dGB available, 10GB required", info.DiskSpaceGB)
	}
	
	// Check for required commands
	requiredCommands := []string{"systemctl", "curl", "wget"}
	for _, cmd := range requiredCommands {
		if _, err := exec.LookPath(cmd); err != nil {
			return fmt.Errorf("required command not found: %s", cmd)
		}
	}
	
	// Check network interfaces
	if len(info.NetworkIfaces) == 0 {
		return fmt.Errorf("no network interfaces found")
	}
	
	hasActiveInterface := false
	for _, iface := range info.NetworkIfaces {
		if iface.IsUp && iface.Type != "loopback" {
			hasActiveInterface = true
			break
		}
	}
	
	if !hasActiveInterface {
		return fmt.Errorf("no active network interfaces found")
	}
	
	logger.Info("Prerequisites verified successfully")
	return nil
}

// GenerateVerificationReport generates a detailed verification report
func GenerateVerificationReport(rc *eos_io.RuntimeContext, config *EnrollmentConfig, info *SystemInfo) (*EnrollmentResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	result := &EnrollmentResult{
		Success:        true,
		Role:           config.Role,
		MasterAddress:  config.MasterAddress,
		ServicesSetup:  []string{},
		ConfigsUpdated: []string{},
		BackupsCreated: []string{},
		Duration:       0, // Will be set by caller
		Errors:         []string{},
	}
	
	// Check services
	services := []string{"salt-minion"}
	if config.Role == RoleMaster {
		services = append(services, "salt-master")
	}
	
	for _, service := range services {
		if isServiceRunning(service) {
			result.ServicesSetup = append(result.ServicesSetup, service)
		} else {
			result.Errors = append(result.Errors, fmt.Sprintf("service %s not running", service))
			result.Success = false
		}
	}
	
	// Check configurations
	configs := []string{"/etc/salt/minion"}
	if config.Role == RoleMaster {
		configs = append(configs, "/etc/salt/master")
	}
	
	for _, configFile := range configs {
		if _, err := os.Stat(configFile); err == nil {
			result.ConfigsUpdated = append(result.ConfigsUpdated, configFile)
		} else {
			result.Errors = append(result.Errors, fmt.Sprintf("config file not found: %s", configFile))
			result.Success = false
		}
	}
	
	// Check for backups
	backupDir := "/var/backups/eos-enrollment"
	if _, err := os.Stat(backupDir); err == nil {
		result.BackupsCreated = append(result.BackupsCreated, backupDir)
	}
	
	logger.Info("Verification report generated", 
		zap.Bool("success", result.Success),
		zap.Int("errors", len(result.Errors)))
	
	return result, nil
}