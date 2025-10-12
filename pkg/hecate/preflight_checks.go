package hecate

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// DependencyStatus represents the status of a dependency
type DependencyStatus struct {
	Name        string
	Description string
	Required    bool
	Installed   bool
	Running     bool
	Version     string
	Issues      []string
	InstallCmd  string
}

// NetworkCheckResult represents network accessibility results
type NetworkCheckResult struct {
	PublicIP          string
	Port80Open        bool
	Port443Open       bool
	DNSWorking        bool
	BehindNAT         bool
	InternetReachable bool
	Issues            []string
}

// PreflightCheckResult contains all preflight check results
type PreflightCheckResult struct {
	Dependencies     []DependencyStatus
	NetworkCheck     NetworkCheckResult
	DiskSpace        map[string]int64 // path -> available MB
	PortAvailability map[int]bool     // port -> available
	SystemChecks     map[string]bool  // check name -> passed
	CanProceed       bool
	CriticalIssues   []string
	Warnings         []string
}

// PreflightChecks performs comprehensive preflight validation for Hecate
func PreflightChecks(rc *eos_io.RuntimeContext) (*PreflightCheckResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting comprehensive Hecate preflight checks")

	result := &PreflightCheckResult{
		Dependencies:     []DependencyStatus{},
		DiskSpace:        make(map[string]int64),
		PortAvailability: make(map[int]bool),
		SystemChecks:     make(map[string]bool),
		CanProceed:       true,
		CriticalIssues:   []string{},
		Warnings:         []string{},
	}

	// 1. Check system requirements
	checkSystemRequirements(rc, result)

	// 2. Check all dependencies
	checkDependencies(rc, result)

	// 3. Check network accessibility for Caddy
	checkNetworkAccessibility(rc, result)

	// 4. Check port availability
	checkPortAvailability(rc, result)

	// 5. Check disk space
	checkDiskSpace(rc, result)

	// 6. Analyze results and determine if we can proceed
	analyzeResults(result)

	// 7. Display summary
	displayPreflightSummary(rc, result)

	return result, nil
}

// checkSystemRequirements checks basic system requirements
func checkSystemRequirements(rc *eos_io.RuntimeContext, result *PreflightCheckResult) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Checking system requirements")

	// Check if running as root
	if os.Geteuid() != 0 {
		result.CriticalIssues = append(result.CriticalIssues, "Must run with sudo/root privileges")
		result.SystemChecks["root_privileges"] = false
	} else {
		result.SystemChecks["root_privileges"] = true
	}

	// Check required system tools
	requiredTools := []string{"systemctl", "curl", "ss", "nc", "dig", "-call"}
	for _, tool := range requiredTools {
		if _, err := execute.Run(rc.Ctx, execute.Options{
			Command: "which",
			Args:    []string{tool},
			Capture: true,
		}); err != nil {
			result.CriticalIssues = append(result.CriticalIssues, fmt.Sprintf("Required tool '%s' not found in PATH", tool))
			result.SystemChecks[tool+"_available"] = false
		} else {
			result.SystemChecks[tool+"_available"] = true
		}
	}
}

// checkDependencies checks all required and optional dependencies
func checkDependencies(rc *eos_io.RuntimeContext, result *PreflightCheckResult) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Checking dependencies")

	dependencies := []struct {
		name        string
		description string
		required    bool
		serviceName string
		installCmd  string
		checkCmd    []string
	}{
		{
			name:        "Nomad",
			description: "HashiCorp Nomad orchestrator (manages containers)",
			required:    true,
			serviceName: "nomad",
			installCmd:  "nomad",
			checkCmd:    []string{"nomad", "version"},
		},
		{
			name:        "Consul",
			description: "HashiCorp Consul (service discovery & mesh)",
			required:    true,
			serviceName: "consul",
			installCmd:  "consul",
			checkCmd:    []string{"consul", "version"},
		},
		{
			name:        "Vault",
			description: "HashiCorp Vault (secrets management)",
			required:    true,
			serviceName: "vault",
			installCmd:  "vault",
			checkCmd:    []string{"vault", "version"},
		},
		{
			name:        "",
			description: " configuration management",
			required:    true,
			installCmd:  "",
			checkCmd:    []string{"-call", "--version"},
		},
		{
			name:        "Docker",
			description: "Docker container runtime (optional - Nomad can use other drivers)",
			required:    false,
			serviceName: "docker",
			installCmd:  "docker",
			checkCmd:    []string{"docker", "version"},
		},
	}

	for _, dep := range dependencies {
		status := DependencyStatus{
			Name:        dep.name,
			Description: dep.description,
			Required:    dep.required,
			InstallCmd:  dep.installCmd,
			Issues:      []string{},
		}

		// Check if installed
		if output, err := execute.Run(rc.Ctx, execute.Options{
			Command: "which",
			Args:    []string{dep.checkCmd[0]},
			Capture: true,
		}); err == nil && output != "" {
			status.Installed = true

			// Get version
			if versionOutput, err := execute.Run(rc.Ctx, execute.Options{
				Command: dep.checkCmd[0],
				Args:    dep.checkCmd[1:],
				Capture: true,
			}); err == nil {
				status.Version = strings.TrimSpace(strings.Split(versionOutput, "\n")[0])
			}
		} else {
			status.Installed = false
			if dep.required {
				status.Issues = append(status.Issues, "Not installed")
			}
		}

		// Check if service is running (if installed)
		if status.Installed && dep.serviceName != "" {
			if output, err := execute.Run(rc.Ctx, execute.Options{
				Command: "systemctl",
				Args:    []string{"is-active", dep.serviceName},
				Capture: true,
			}); err == nil && strings.TrimSpace(output) == "active" {
				status.Running = true
			} else {
				status.Running = false
				if dep.required {
					status.Issues = append(status.Issues, "Service not running")
				}
			}
		}

		result.Dependencies = append(result.Dependencies, status)
	}
}

// checkNetworkAccessibility checks if the server can be reached from the internet
func checkNetworkAccessibility(rc *eos_io.RuntimeContext, result *PreflightCheckResult) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Checking network accessibility for Caddy/ACME")

	netCheck := &result.NetworkCheck

	// 1. Get public IP
	logger.Info("Detecting public IP address")
	publicIPServices := []string{
		"https://api.ipify.org",
		"https://icanhazip.com",
		"https://checkip.amazonaws.com",
	}

	for _, service := range publicIPServices {
		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Get(service)

		if err == nil && resp.StatusCode == 200 {
			defer func() { _ = resp.Body.Close() }()
			buf := make([]byte, 100)
			n, _ := resp.Body.Read(buf)
			netCheck.PublicIP = strings.TrimSpace(string(buf[:n]))
			break
		}
	}

	if netCheck.PublicIP == "" {
		netCheck.Issues = append(netCheck.Issues, "Could not determine public IP address")
	} else {
		logger.Info("Public IP detected", zap.String("ip", netCheck.PublicIP))
	}

	// 2. Check if we can reach the internet
	netCheck.InternetReachable = canReachInternet(rc)
	if !netCheck.InternetReachable {
		netCheck.Issues = append(netCheck.Issues, "Cannot reach the internet")
	}

	// 3. Check DNS resolution
	logger.Info("Checking DNS resolution")
	if _, err := net.LookupHost("google.com"); err == nil {
		netCheck.DNSWorking = true
	} else {
		netCheck.DNSWorking = false
		netCheck.Issues = append(netCheck.Issues, "DNS resolution not working")
	}

	// 4. Check if ports 80 and 443 are accessible from outside
	// This is a simplified check - in production you'd want a more sophisticated test
	logger.Info("Checking port accessibility")
	netCheck.Port80Open = !isPortInUse(80)
	netCheck.Port443Open = !isPortInUse(443)

	if !netCheck.Port80Open {
		netCheck.Issues = append(netCheck.Issues, "Port 80 is already in use or blocked")
	}
	if !netCheck.Port443Open {
		netCheck.Issues = append(netCheck.Issues, "Port 443 is already in use or blocked")
	}

	// 5. Detect if behind NAT
	netCheck.BehindNAT = detectNAT(rc, netCheck.PublicIP)
	if netCheck.BehindNAT {
		netCheck.Issues = append(netCheck.Issues, "Server appears to be behind NAT - port forwarding may be required")
	}
}

// checkPortAvailability checks if required ports are available
func checkPortAvailability(rc *eos_io.RuntimeContext, result *PreflightCheckResult) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Checking port availability")

	requiredPorts := map[int]string{
		80:                    "HTTP (Caddy)",
		443:                   "HTTPS (Caddy)",
		shared.PortCaddyAdmin: "Caddy Admin API",
		shared.PortAuthentik:  "Authentik",
		8263:                  "PostgreSQL", // PortPostgres
		shared.PortRedis:      "Redis",
		// Core services that should already be running
		shared.PortVault:  "Vault (should be running)",
		shared.PortConsul: "Consul (should be running)",
		shared.PortNomad:  "Nomad (should be running)",
	}

	for port, service := range requiredPorts {
		if isPortInUse(port) {
			result.PortAvailability[port] = false
			// Check if it's one of our core services that should be running
			if strings.Contains(service, "should be running") {
				logger.Debug("Port in use by expected service", zap.Int("port", port), zap.String("service", service))
			} else {
				result.Warnings = append(result.Warnings,
					fmt.Sprintf("Port %d (%s) is already in use", port, service))
			}
		} else {
			result.PortAvailability[port] = true
			// If it's a core service port that should be in use but isn't, that's a problem
			if strings.Contains(service, "should be running") {
				result.CriticalIssues = append(result.CriticalIssues,
					fmt.Sprintf("Port %d (%s) is not in use - service may not be running", port, service))
			}
		}
	}
}

// checkDiskSpace checks available disk space
func checkDiskSpace(rc *eos_io.RuntimeContext, result *PreflightCheckResult) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Checking disk space")

	paths := []string{"/opt", "/var", "/"}
	requiredMB := int64(5000) // 5GB minimum

	for _, path := range paths {
		var stat syscall.Statfs_t
		if err := syscall.Statfs(path, &stat); err != nil {
			logger.Warn("Failed to check disk space", zap.String("path", path), zap.Error(err))
			continue
		}

		availableMB := int64(stat.Bavail) * int64(stat.Bsize) / 1024 / 1024
		result.DiskSpace[path] = availableMB

		if availableMB < requiredMB {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("Low disk space on %s: %d MB available (recommended: %d MB)",
					path, availableMB, requiredMB))
		}
	}
}

// Helper functions

func canReachInternet(rc *eos_io.RuntimeContext) bool {
	// Try to connect to well-known services
	testHosts := []string{
		"google.com:443",
		"cloudflare.com:443",
		"github.com:443",
	}

	for _, host := range testHosts {
		conn, err := net.DialTimeout("tcp", host, 3*time.Second)
		if err == nil {
			conn.Close()
			return true
		}
	}
	return false
}

func isPortInUse(port int) bool {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return true
	}
	listener.Close()
	return false
}

func detectNAT(rc *eos_io.RuntimeContext, publicIP string) bool {
	// Get local IPs
	interfaces, err := net.Interfaces()
	if err != nil {
		return false
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			if ip.String() == publicIP {
				// Public IP is directly assigned to an interface
				return false
			}
		}
	}

	// Public IP not found on any interface - likely behind NAT
	return true
}

// analyzeResults determines if deployment can proceed
func analyzeResults(result *PreflightCheckResult) {
	// Check critical dependencies
	for _, dep := range result.Dependencies {
		if dep.Required && (!dep.Installed || !dep.Running) {
			result.CanProceed = false
			if !dep.Installed {
				result.CriticalIssues = append(result.CriticalIssues,
					fmt.Sprintf("%s is required but not installed", dep.Name))
			} else if !dep.Running {
				result.CriticalIssues = append(result.CriticalIssues,
					fmt.Sprintf("%s is installed but not running", dep.Name))
			}
		}
	}

	// Check network requirements for ACME
	if !result.NetworkCheck.InternetReachable {
		result.Warnings = append(result.Warnings,
			"No internet access detected - ACME/Let's Encrypt certificates will not work")
	}

	if !result.NetworkCheck.DNSWorking {
		result.CriticalIssues = append(result.CriticalIssues,
			"DNS resolution not working - required for service discovery")
		result.CanProceed = false
	}

	// Check if we have a public IP but it might be behind cloud NAT
	if result.NetworkCheck.BehindNAT && result.NetworkCheck.PublicIP != "" {
		// This is likely a cloud server with NAT (common in AWS, GCP, etc.)
		result.Warnings = append(result.Warnings,
			"Server appears to be behind NAT but has a public IP - this is common in cloud environments")
	} else if result.NetworkCheck.BehindNAT && result.NetworkCheck.PublicIP == "" {
		// This is truly a private network without public IP
		result.CriticalIssues = append(result.CriticalIssues,
			"No public IP detected - Hecate requires a public IP for HTTPS certificates")
		result.CriticalIssues = append(result.CriticalIssues,
			"Please deploy on a cloud server with public IP: AWS EC2, Hetzner Cloud, DigitalOcean, GCP, Azure, etc.")
		result.CanProceed = false
	}

	// Also check if we have a public IP at all
	if result.NetworkCheck.PublicIP == "" {
		result.CriticalIssues = append(result.CriticalIssues,
			"No public IP detected - Hecate requires a cloud deployment with public IP")
		result.CanProceed = false
	}
}

// displayPreflightSummary shows a formatted summary of preflight checks
func displayPreflightSummary(rc *eos_io.RuntimeContext, result *PreflightCheckResult) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: ╔════════════════════════════════════════════════════════════════╗")
	logger.Info("terminal prompt: ║               HECATE PREFLIGHT CHECK SUMMARY                   ║")
	logger.Info("terminal prompt: ╚════════════════════════════════════════════════════════════════╝")
	logger.Info("terminal prompt: ")

	// System Checks
	logger.Info("terminal prompt: SYSTEM CHECKS:")
	for check, passed := range result.SystemChecks {
		status := "✓"
		if !passed {
			status = "✗"
		}
		logger.Info(fmt.Sprintf("terminal prompt:   %s %s", status, check))
	}

	// Dependencies
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: DEPENDENCIES:")
	for _, dep := range result.Dependencies {
		status := "✓"
		if dep.Required && (!dep.Installed || !dep.Running) {
			status = "✗"
		} else if !dep.Installed {
			status = "○"
		} else if !dep.Running {
			status = "⚠"
		}

		line := fmt.Sprintf("  %s %-15s - %s", status, dep.Name, dep.Description)
		if dep.Installed && dep.Version != "" {
			line += fmt.Sprintf(" (%s)", dep.Version)
		}
		if !dep.Installed {
			line += " [NOT INSTALLED]"
		} else if !dep.Running {
			line += " [NOT RUNNING]"
		}
		logger.Info("terminal prompt: " + line)
	}

	// Network Accessibility
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: NETWORK ACCESSIBILITY (for Caddy/ACME):")
	netItems := []struct {
		name   string
		value  string
		status bool
	}{
		{"Public IP", result.NetworkCheck.PublicIP, result.NetworkCheck.PublicIP != ""},
		{"Internet Access", fmt.Sprintf("%v", result.NetworkCheck.InternetReachable), result.NetworkCheck.InternetReachable},
		{"DNS Working", fmt.Sprintf("%v", result.NetworkCheck.DNSWorking), result.NetworkCheck.DNSWorking},
		{"Port 80 Available", fmt.Sprintf("%v", result.NetworkCheck.Port80Open), result.NetworkCheck.Port80Open},
		{"Port 443 Available", fmt.Sprintf("%v", result.NetworkCheck.Port443Open), result.NetworkCheck.Port443Open},
		{"Behind NAT", fmt.Sprintf("%v", result.NetworkCheck.BehindNAT), !result.NetworkCheck.BehindNAT},
	}

	for _, item := range netItems {
		status := "✓"
		if !item.status {
			status = "⚠"
		}
		logger.Info(fmt.Sprintf("terminal prompt:   %s %-20s: %s", status, item.name, item.value))
	}

	// Disk Space
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: DISK SPACE:")
	for path, availMB := range result.DiskSpace {
		status := "✓"
		if availMB < 5000 {
			status = "⚠"
		}
		logger.Info(fmt.Sprintf("terminal prompt:   %s %-10s: %d MB available", status, path, availMB))
	}

	// Issues Summary
	if len(result.CriticalIssues) > 0 {
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt:  CRITICAL ISSUES (must be resolved):")
		for _, issue := range result.CriticalIssues {
			logger.Info("terminal prompt:   • " + issue)
		}
	}

	if len(result.Warnings) > 0 {
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt: WARNINGS (deployment may work with limitations):")
		for _, warning := range result.Warnings {
			logger.Info("terminal prompt:   • " + warning)
		}
	}

	// Network issues details
	if len(result.NetworkCheck.Issues) > 0 {
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt:  NETWORK NOTES:")
		for _, issue := range result.NetworkCheck.Issues {
			logger.Info("terminal prompt:   • " + issue)
		}
	}

	// Final status
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: ════════════════════════════════════════════════════════════════")
	if result.CanProceed {
		logger.Info("terminal prompt:  PREFLIGHT CHECKS PASSED - Ready to proceed with deployment")
	} else {
		logger.Info("terminal prompt:  PREFLIGHT CHECKS FAILED - Critical issues must be resolved")
	}
	logger.Info("terminal prompt: ")
}

// InteractivelyHandleDependencies handles missing dependencies with Y/N prompts
func InteractivelyHandleDependencies(rc *eos_io.RuntimeContext, result *PreflightCheckResult) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Find missing required dependencies
	var missingDeps []DependencyStatus
	for _, dep := range result.Dependencies {
		if dep.Required && !dep.Installed {
			missingDeps = append(missingDeps, dep)
		}
	}

	if len(missingDeps) == 0 {
		return nil
	}

	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: The following required dependencies are missing:")
	logger.Info("terminal prompt: ")

	for _, dep := range missingDeps {
		logger.Info(fmt.Sprintf("terminal prompt: • %s - %s", dep.Name, dep.Description))
	}

	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: Would you like to install these dependencies now?")

	for _, dep := range missingDeps {
		// Use the new consent helper for consistency
		consent, err := eos_io.PromptForDependency(rc, dep.Name, dep.Description, "Hecate")
		if err != nil {
			return fmt.Errorf("failed to get user consent: %w", err)
		}

		if consent {
			logger.Info(fmt.Sprintf("terminal prompt: Installing %s...", dep.Name))

			if err := installDependency(rc, dep); err != nil {
				logger.Error("Failed to install dependency",
					zap.String("dependency", dep.Name),
					zap.Error(err))

				// Ask if they want to continue anyway
				continueAnyway, _ := eos_io.PromptToContinueDespiteErrors(rc, 1, fmt.Sprintf("installing %s", dep.Name))
				if !continueAnyway {
					return eos_err.NewUserError("Deployment cancelled - %s is required", dep.Name)
				}
			} else {
				logger.Info(fmt.Sprintf("terminal prompt: ✓ %s installed successfully", dep.Name))
			}
		} else {
			// User chose not to install
			return eos_err.NewUserError("Deployment cancelled - %s is required but was not installed", dep.Name)
		}
	}

	return nil
}

// installDependency installs a missing dependency
func installDependency(rc *eos_io.RuntimeContext, dep DependencyStatus) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Find eos binary path
	eosPath, err := os.Executable()
	if err != nil {
		eosPath = "/usr/local/bin/eos"
	}

	// Build the installation command
	args := []string{"create", dep.InstallCmd}

	// Add appropriate flags based on the service
	switch dep.InstallCmd {
	case "vault":
		args = append(args, "--dev-mode")
	case "consul":
		// Consul doesn't have a --dev-mode flag, it will run with default settings
		// which are appropriate for a single-node deployment
	case "nomad":
		// Don't add --node-role flag, let the command use its defaults
		// The nomad command will handle the role appropriately
	case "":
		args = append(args, "--masterless")
	}

	logger.Info("Executing installation command",
		zap.String("command", eosPath),
		zap.Strings("args", args))

	// Run the installation with a longer timeout
	installCtx, cancel := context.WithTimeout(rc.Ctx, 10*time.Minute)
	defer cancel()

	output, err := execute.Run(installCtx, execute.Options{
		Command: eosPath,
		Args:    args,
		Capture: false, // Show output to user
	})

	if err != nil {
		logger.Error("Installation failed",
			zap.String("service", dep.Name),
			zap.Error(err),
			zap.String("output", output))
		return fmt.Errorf("failed to install %s: %w", dep.Name, err)
	}

	// Give the service a moment to fully initialize
	time.Sleep(5 * time.Second)

	// Verify the service is now running
	if output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"is-active", strings.ToLower(dep.Name)},
		Capture: true,
	}); err != nil || strings.TrimSpace(output) != "active" {
		return fmt.Errorf("%s installed but not running properly", dep.Name)
	}

	return nil
}
