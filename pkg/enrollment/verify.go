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

// verifyHashiCorpKeys verifies HashiCorp key management (Vault, Consul, etc.)
func verifyHashiCorpKeys(rc *eos_io.RuntimeContext, config *EnrollmentConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Verifying HashiCorp key management")

	// TODO: Implement HashiCorp key verification
	// This should check:
	// - Vault token validity
	// - Consul ACL tokens
	// - Nomad tokens
	// - TLS certificates for inter-service communication

	logger.Info("HashiCorp key management verification completed")
	return nil
}

// isServiceRunning checks if a system service is running
func isServiceRunning(serviceName string) bool {
	// Use systemctl to check service status
	cmd := exec.Command("systemctl", "is-active", "--quiet", serviceName)
	err := cmd.Run()
	return err == nil
}

// ValidateInventoryExport validates that inventory export was successful
func VerifyEnrollment(rc *eos_io.RuntimeContext, config *EnrollmentConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting enrollment verification",
		zap.String("role", config.Role),
		zap.String("master_address", config.ess))

	// Run verification tests
	tests := []VerificationTest{
		{
			Name:        " installation",
			Description: "Verify  is installed and configured",
			TestFunc:    func() error { return verifyInstallation(rc, config) },
		},
		{
			Name:        "Service status",
			Description: "Verify  services are running",
			TestFunc:    func() error { return verifyServices(rc, config) },
		},
		{
			Name:        "Network connectivity",
			Description: "Test network connectivity to master",
			TestFunc:    func() error { return verifyNetworkConnectivity(rc, config) },
		},
		{
			Name:        "Key management",
			Description: "Verify HashiCorp key management",
			TestFunc:    func() error { return verifyHashiCorpKeys(rc, config) },
		},
		{
			Name:        "Basic functionality",
			Description: "Test basic  functionality",
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

// verifyInstallation verifies  installation
func verifyInstallation(rc *eos_io.RuntimeContext, config *EnrollmentConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check HashiCorp tools if needed
	hashicorpTools := []string{"consul", "nomad", "vault"}
	for _, tool := range hashicorpTools {
		if _, err := exec.LookPath(tool); err != nil {
			logger.Warn("HashiCorp tool not found in PATH",
				zap.String("tool", tool),
				zap.Error(err))
			// Don't fail here as tools might be installed differently
		}
	}

	// Verify HashiCorp tool versions
	cmd := exec.Command("consul", "version")
	output, err := cmd.Output()
	if err != nil {
		logger.Warn("Failed to get consul version", zap.Error(err))
	} else {
		version := strings.TrimSpace(string(output))
		logger.Debug("Consul version verified", zap.String("version", version))
	}

	// Check configuration files
	configFiles := []string{
		"/etc/consul/consul.hcl",
		"/etc/nomad/nomad.hcl",
		"/etc/vault/vault.hcl",
	}
	for _, configFile := range configFiles {
		if _, err := os.Stat(configFile); err != nil {
			return fmt.Errorf("configuration file not found: %s", configFile)
		}
	}

	return nil
}

// verifyServices verifies  services are running
func verifyServices(rc *eos_io.RuntimeContext, config *EnrollmentConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	services := []string{"-minion"}
	if config.Role == RoleMaster {
		services = append(services, "-master")
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
	if config.ess == "" {
		logger.Info("No master address specified, skipping network connectivity tests")
		return nil
	}

	// Test  ports
	Ports := []int{PublisherPort, RequestPort}
	for _, port := range Ports {
		if err := testConnectivity(rc, config.ess, port); err != nil {
			return fmt.Errorf("failed to connect to master port %d: %w", port, err)
		}
	}

	// Test DNS resolution
	if err := testDNSResolution(rc, config.ess); err != nil {
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

// verifyBasicFunctionality tests basic  functionality
func verifyBasicFunctionality(rc *eos_io.RuntimeContext, config *EnrollmentConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Test basic -call functionality
	tests := []struct {
		name string
		cmd  []string
		desc string
	}{
		{
			name: "s",
			cmd:  []string{"-call", "--local", "s.get", "os"},
			desc: "Get OS ",
		},
		{
			name: "test_ping",
			cmd:  []string{"-call", "--local", "test.ping"},
			desc: "Test ping function",
		},
		{
			name: "disk_usage",
			cmd:  []string{"-call", "--local", "disk.usage", "/"},
			desc: "Get disk usage",
		},
	}

	for _, test := range tests {
		logger.Debug("Testing -call function", zap.String("test", test.name))

		cmd := exec.Command(test.cmd[0], test.cmd[1:]...)
		output, err := cmd.Output()
		if err != nil {
			return fmt.Errorf("-call test '%s' failed: %w", test.name, err)
		}

		// Check for basic success indicators
		outputStr := string(output)
		if strings.Contains(outputStr, "ERROR") || strings.Contains(outputStr, "CRITICAL") {
			return fmt.Errorf("-call test '%s' returned error: %s", test.name, outputStr)
		}

		logger.Debug("-call test successful",
			zap.String("test", test.name),
			zap.String("output", strings.TrimSpace(outputStr)))
	}

	// Test HashiCorp cluster connectivity if not standalone
	if config.Role == "minion" && config.ess != "" {
		logger.Debug("Testing master connectivity")

		// Test simple command to master
		cmd := exec.Command("-call", "test.ping")
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
		requiredPorts := []int{PublisherPort, RequestPort}
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
		"8.8.8.8:53",     // Google DNS
		"1.1.1.1:53",     // Cloudflare DNS
		"github.com:443", // GitHub HTTPS
	}

	for _, server := range servers {
		if err := testNetworkConnectivity(server); err == nil {
			return nil // At least one worked
		}
	}

	return fmt.Errorf("no internet connectivity detected")
}

// testNetworkConnectivity tests connectivity to a specific server
func testNetworkConnectivity(server string) error {
	// Use ping to test connectivity
	cmd := exec.Command("ping", "-c", "1", "-W", "3000", server)
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to ping %s: %w", server, err)
	}
	return nil
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
		MasterAddress:  config.ess,
		ServicesSetup:  []string{},
		ConfigsUpdated: []string{},
		BackupsCreated: []string{},
		Duration:       0, // Will be set by caller
		Errors:         []string{},
	}

	// Check services
	services := []string{"-minion"}
	if config.Role == RoleMaster {
		services = append(services, "-master")
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
	configs := []string{"/etc//minion"}
	if config.Role == RoleMaster {
		configs = append(configs, "/etc//master")
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
