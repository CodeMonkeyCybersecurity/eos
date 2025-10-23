// cmd/debug/bootstrap.go
package debug

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var debugBootstrapCmd = &cobra.Command{
	Use:   "bootstrap",
	Short: "Debug bootstrap process and infrastructure setup",
	Long: `Comprehensive diagnostics for the Eos bootstrap process.

This command examines the entire bootstrap state, checks for conflicts,
validates prerequisites, and identifies exactly where and why the bootstrap
process is failing.

Checks performed:
1. System information (OS, kernel, architecture)
2. Bootstrap prerequisites (systemd, wget, curl, unzip)
3. Bootstrap state markers and flags
4. Bootstrap locks (detect stale locks from crashed processes)
5. Infrastructure services (Consul, Vault, Nomad)
6. Port conflicts on infrastructure ports
7. Network configuration and connectivity
8. System resources (memory, CPU, disk)
9. Bootstrap phase status
10. Previous bootstrap attempts analysis

Example:
  eos debug bootstrap`,
	RunE: eos.WrapDebug("bootstrap", runDebugBootstrap),
}

func init() {
	debugCmd.AddCommand(debugBootstrapCmd)
}

type BootstrapDebugResult struct {
	Timestamp             time.Time
	SystemCheck           CheckResult
	PrerequisitesCheck    CheckResult
	StateCheck            CheckResult
	ServicesCheck         CheckResult
	PortsCheck            CheckResult
	LockCheck             CheckResult
	PhaseCheck            CheckResult
	NetworkCheck          CheckResult
	ResourcesCheck        CheckResult
	PreviousAttemptsCheck CheckResult
	Summary               string
}

type CheckResult struct {
	Name    string
	Status  string // "PASS", "WARN", "FAIL"
	Message string
	Details []string
	Error   error
}

func runDebugBootstrap(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting comprehensive bootstrap diagnostics")

	result := BootstrapDebugResult{
		Timestamp: time.Now(),
	}

	// Run all diagnostic checks
	result.SystemCheck = checkSystemInfo(rc)
	result.PrerequisitesCheck = checkBootstrapPrerequisites(rc)
	result.StateCheck = checkBootstrapState(rc)
	result.LockCheck = checkBootstrapLocks(rc)
	result.ServicesCheck = checkInfraServices(rc)
	result.PortsCheck = checkInfraPorts(rc)
	result.NetworkCheck = checkNetworkConfig(rc)
	result.ResourcesCheck = checkSystemResources(rc)
	result.PhaseCheck = checkBootstrapPhases(rc)
	result.PreviousAttemptsCheck = checkPreviousAttempts(rc)

	// Print results
	printBootstrapDebugResults(rc, result)

	// Generate summary and recommendations
	result.Summary = generateBootstrapSummary(result)
	logger.Info("terminal prompt: " + strings.Repeat("=", 80))
	logger.Info("terminal prompt: SUMMARY AND RECOMMENDATIONS")
	logger.Info("terminal prompt: " + strings.Repeat("=", 80))
	for _, line := range strings.Split(result.Summary, "\n") {
		if line != "" {
			logger.Info("terminal prompt: " + line)
		}
	}

	return nil
}

func checkSystemInfo(rc *eos_io.RuntimeContext) CheckResult {
	logger := otelzap.Ctx(rc.Ctx)
	result := CheckResult{Name: "System Information"}

	// OS Info
	osInfo, _ := exec.CommandContext(rc.Ctx, "lsb_release", "-d").Output()
	result.Details = append(result.Details, fmt.Sprintf("OS: %s", strings.TrimSpace(string(osInfo))))

	// Kernel
	kernel, _ := exec.CommandContext(rc.Ctx, "uname", "-r").Output()
	result.Details = append(result.Details, fmt.Sprintf("Kernel: %s", strings.TrimSpace(string(kernel))))

	// Architecture
	arch, _ := exec.CommandContext(rc.Ctx, "uname", "-m").Output()
	result.Details = append(result.Details, fmt.Sprintf("Architecture: %s", strings.TrimSpace(string(arch))))

	// Hostname
	hostname, _ := os.Hostname()
	result.Details = append(result.Details, fmt.Sprintf("Hostname: %s", hostname))

	// Uptime
	uptime, _ := exec.CommandContext(rc.Ctx, "uptime", "-p").Output()
	result.Details = append(result.Details, fmt.Sprintf("Uptime: %s", strings.TrimSpace(string(uptime))))

	result.Status = "PASS"
	result.Message = "System information collected"
	logger.Debug("System info check complete", zap.Strings("details", result.Details))
	return result
}

func checkBootstrapPrerequisites(rc *eos_io.RuntimeContext) CheckResult {
	logger := otelzap.Ctx(rc.Ctx)
	result := CheckResult{Name: "Bootstrap Prerequisites"}

	checks := []struct {
		name     string
		required bool
		check    func() (bool, string)
	}{
		{"systemd", true, func() (bool, string) {
			_, err := exec.LookPath("systemctl")
			return err == nil, "systemctl binary"
		}},
		{"wget", true, func() (bool, string) {
			_, err := exec.LookPath("wget")
			return err == nil, "wget binary"
		}},
		{"curl", true, func() (bool, string) {
			_, err := exec.LookPath("curl")
			return err == nil, "curl binary"
		}},
		{"unzip", true, func() (bool, string) {
			_, err := exec.LookPath("unzip")
			return err == nil, "unzip binary"
		}},
		{"iptables", false, func() (bool, string) {
			_, err := exec.LookPath("iptables")
			return err == nil, "iptables binary"
		}},
	}

	allRequired := true
	for _, c := range checks {
		passed, detail := c.check()
		if passed {
			result.Details = append(result.Details, fmt.Sprintf("✓ %s: found (%s)", c.name, detail))
		} else {
			if c.required {
				result.Details = append(result.Details, fmt.Sprintf("✗ %s: MISSING (required)", c.name))
				allRequired = false
			} else {
				result.Details = append(result.Details, fmt.Sprintf("⚠ %s: missing (optional)", c.name))
			}
		}
	}

	if !allRequired {
		result.Status = "FAIL"
		result.Message = "Missing required prerequisites"
	} else {
		result.Status = "PASS"
		result.Message = "All required prerequisites present"
	}

	logger.Debug("Prerequisites check complete", zap.String("status", result.Status))
	return result
}

func checkBootstrapState(rc *eos_io.RuntimeContext) CheckResult {
	logger := otelzap.Ctx(rc.Ctx)
	result := CheckResult{Name: "Bootstrap State"}

	// Check for bootstrap markers
	markers := map[string]string{
		"/var/lib/eos/.bootstrapped":      "Complete bootstrap marker",
		"/var/lib/eos/.consul_installed":  "Consul installation marker",
		"/var/lib/eos/.vault_installed":   "Vault installation marker",
		"/var/lib/eos/.nomad_installed":   "Nomad installation marker",
		"/tmp/.eos_bootstrap_in_progress": "Bootstrap in progress flag",
	}

	foundMarkers := []string{}
	for path, desc := range markers {
		if info, err := os.Stat(path); err == nil {
			foundMarkers = append(foundMarkers, desc)
			result.Details = append(result.Details,
				fmt.Sprintf("✓ Found: %s (%s, modified: %s)",
					desc, path, info.ModTime().Format("2006-01-02 15:04:05")))
		}
	}

	if len(foundMarkers) == 0 {
		result.Status = "PASS"
		result.Message = "No bootstrap state found (clean slate)"
	} else {
		result.Status = "WARN"
		result.Message = fmt.Sprintf("Found %d state marker(s) from previous bootstrap attempts", len(foundMarkers))
	}

	// Check environment variable
	if os.Getenv("EOS_BOOTSTRAP_IN_PROGRESS") != "" {
		result.Details = append(result.Details,
			fmt.Sprintf("⚠ Environment variable EOS_BOOTSTRAP_IN_PROGRESS=%s",
				os.Getenv("EOS_BOOTSTRAP_IN_PROGRESS")))
	}

	logger.Debug("Bootstrap state check complete", zap.Int("markers_found", len(foundMarkers)))
	return result
}

func checkBootstrapLocks(rc *eos_io.RuntimeContext) CheckResult {
	logger := otelzap.Ctx(rc.Ctx)
	result := CheckResult{Name: "Bootstrap Locks"}

	lockFiles := []string{
		"/var/lock/eos-bootstrap.lock",
		"/var/lock/consul-install.lock",
		"/var/lock/vault-install.lock",
	}

	activeLocks := 0
	for _, lockPath := range lockFiles {
		if info, err := os.Stat(lockPath); err == nil {
			activeLocks++
			result.Details = append(result.Details,
				fmt.Sprintf("✗ Active lock: %s (created: %s)",
					lockPath, info.ModTime().Format("2006-01-02 15:04:05")))

			// Try to read lock contents (might contain PID)
			if content, err := os.ReadFile(lockPath); err == nil {
				pidStr := strings.TrimSpace(string(content))
				if pid, err := strconv.Atoi(pidStr); err == nil {
					// Check if process is still running
					process, err := os.FindProcess(pid)
					if err == nil {
						err = process.Signal(syscall.Signal(0))
						if err == nil {
							result.Details = append(result.Details,
								fmt.Sprintf("  → Lock held by running process PID %d", pid))
						} else {
							result.Details = append(result.Details,
								fmt.Sprintf("  → Lock references dead process PID %d (STALE)", pid))
						}
					}
				}
			}
		}
	}

	if activeLocks > 0 {
		result.Status = "FAIL"
		result.Message = fmt.Sprintf("Found %d active lock(s) - may prevent bootstrap", activeLocks)
		result.Details = append(result.Details, "\nTo clear stale locks:")
		result.Details = append(result.Details, "  sudo rm -f /var/lock/eos-*.lock")
	} else {
		result.Status = "PASS"
		result.Message = "No active bootstrap locks"
	}

	logger.Debug("Lock check complete", zap.Int("active_locks", activeLocks))
	return result
}

func checkInfraServices(rc *eos_io.RuntimeContext) CheckResult {
	logger := otelzap.Ctx(rc.Ctx)
	result := CheckResult{Name: "Infrastructure Services"}

	services := []struct {
		name     string
		port     int
		expected bool
	}{
		{"consul", shared.PortConsul, true},
		{"vault", shared.PortVault, false},
		{"nomad", 4646, false},
	}

	runningCount := 0
	for _, svc := range services {
		// Check systemd service
		out, err := exec.CommandContext(rc.Ctx, "systemctl", "is-active", svc.name).CombinedOutput()
		isActive := strings.TrimSpace(string(out)) == "active"

		if isActive {
			runningCount++
			result.Details = append(result.Details, fmt.Sprintf("✓ %s: ACTIVE", svc.name))

			// Get more details
			statusOut, _ := exec.CommandContext(rc.Ctx, "systemctl", "status", svc.name, "--no-pager", "-n", "0").CombinedOutput()
			for _, line := range strings.Split(string(statusOut), "\n") {
				if strings.Contains(line, "Active:") || strings.Contains(line, "Main PID:") {
					result.Details = append(result.Details, "  "+strings.TrimSpace(line))
				}
			}
		} else if err == nil && string(out) != "" {
			// Service exists but not active
			status := strings.TrimSpace(string(out))
			result.Details = append(result.Details, fmt.Sprintf("⚠ %s: %s", svc.name, status))
		} else {
			// Service not found
			if svc.expected {
				result.Details = append(result.Details, fmt.Sprintf("✗ %s: NOT INSTALLED", svc.name))
			} else {
				result.Details = append(result.Details, fmt.Sprintf("○ %s: not installed (optional)", svc.name))
			}
		}
	}

	if runningCount == 0 {
		result.Status = "FAIL"
		result.Message = "No infrastructure services running"
	} else {
		result.Status = "PASS"
		result.Message = fmt.Sprintf("%d service(s) running", runningCount)
	}

	logger.Debug("Infrastructure services check complete", zap.Int("running_count", runningCount))
	return result
}

func checkInfraPorts(rc *eos_io.RuntimeContext) CheckResult {
	logger := otelzap.Ctx(rc.Ctx)
	result := CheckResult{Name: "Infrastructure Port Conflicts"}

	// Ports used by Eos infrastructure
	ports := map[int]string{
		shared.PortConsul: "Consul HTTP",
		8300:              "Consul Server RPC",
		8301:              "Consul Serf LAN",
		8302:              "Consul Serf WAN",
		8502:              "Consul gRPC",
		8600:              "Consul DNS",
		shared.PortVault:  "Vault",
		4646:              "Nomad HTTP",
		4647:              "Nomad RPC",
		4648:              "Nomad Serf",
	}

	conflicts := 0
	listening := 0

	for port, service := range ports {
		// Check if port is in use
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", shared.GetInternalHostname(), port), 1*time.Second)
		if err == nil {
			conn.Close()
			listening++

			// Find what's using it
			out, err := exec.CommandContext(rc.Ctx, "sh", "-c", fmt.Sprintf("lsof -i :%d -sTCP:LISTEN", port)).CombinedOutput()
			if err == nil {
				lines := strings.Split(string(out), "\n")
				if len(lines) > 1 {
					fields := strings.Fields(lines[1])
					if len(fields) >= 1 {
						processName := fields[0]
						if strings.Contains(strings.ToLower(service), strings.ToLower(processName)) {
							result.Details = append(result.Details,
								fmt.Sprintf("✓ Port %d (%s): in use by %s", port, service, processName))
						} else {
							conflicts++
							result.Details = append(result.Details,
								fmt.Sprintf("✗ Port %d (%s): CONFLICT - used by %s", port, service, processName))
						}
					}
				}
			} else {
				result.Details = append(result.Details,
					fmt.Sprintf("⚠ Port %d (%s): in use by unknown process", port, service))
			}
		}
	}

	if conflicts > 0 {
		result.Status = "FAIL"
		result.Message = fmt.Sprintf("Found %d port conflict(s)", conflicts)
	} else if listening > 0 {
		result.Status = "PASS"
		result.Message = fmt.Sprintf("%d port(s) listening, no conflicts", listening)
	} else {
		result.Status = "PASS"
		result.Message = "No ports in use (clean state)"
	}

	logger.Debug("Port check complete", zap.Int("listening", listening), zap.Int("conflicts", conflicts))
	return result
}

func checkNetworkConfig(rc *eos_io.RuntimeContext) CheckResult {
	logger := otelzap.Ctx(rc.Ctx)
	result := CheckResult{Name: "Network Configuration"}

	// Check primary interface
	ifaces, err := net.Interfaces()
	if err != nil {
		result.Status = "FAIL"
		result.Error = err
		return result
	}

	// Find interface with default gateway
	gwOut, _ := exec.CommandContext(rc.Ctx, "ip", "route", "show", "default").Output()
	defaultIface := ""
	if len(gwOut) > 0 {
		fields := strings.Fields(string(gwOut))
		for i, f := range fields {
			if f == "dev" && i+1 < len(fields) {
				defaultIface = fields[i+1]
				break
			}
		}
	}

	result.Details = append(result.Details, fmt.Sprintf("Default route interface: %s", defaultIface))

	// Check that interface
	if defaultIface != "" {
		for _, iface := range ifaces {
			if iface.Name == defaultIface {
				addrs, _ := iface.Addrs()
				result.Details = append(result.Details, fmt.Sprintf("\nInterface %s:", iface.Name))
				result.Details = append(result.Details, fmt.Sprintf("  MAC: %s", iface.HardwareAddr))
				result.Details = append(result.Details, fmt.Sprintf("  MTU: %d", iface.MTU))
				for _, addr := range addrs {
					result.Details = append(result.Details, fmt.Sprintf("  IP: %s", addr.String()))
				}
				break
			}
		}
	}

	// Check DNS resolution
	_, err = net.LookupHost("releases.hashicorp.com")
	if err != nil {
		result.Status = "WARN"
		result.Message = "DNS resolution may be impaired"
		result.Details = append(result.Details, fmt.Sprintf("\n⚠ DNS test failed: %v", err))
	} else {
		result.Status = "PASS"
		result.Message = "Network configuration looks good"
		result.Details = append(result.Details, "\n✓ DNS resolution working")
	}

	// Check internet connectivity
	client := &http.Client{Timeout: 5 * time.Second}
	_, err = client.Get("https://releases.hashicorp.com")
	if err != nil {
		result.Details = append(result.Details, fmt.Sprintf("⚠ Internet connectivity test failed: %v", err))
		if result.Status == "PASS" {
			result.Status = "WARN"
			result.Message = "Network available but internet connectivity issues"
		}
	} else {
		result.Details = append(result.Details, "✓ Internet connectivity working")
	}

	logger.Debug("Network check complete", zap.String("status", result.Status))
	return result
}

func checkSystemResources(rc *eos_io.RuntimeContext) CheckResult {
	logger := otelzap.Ctx(rc.Ctx)
	result := CheckResult{Name: "System Resources"}

	// Memory
	memInfo, err := os.ReadFile("/proc/meminfo")
	if err == nil {
		for _, line := range strings.Split(string(memInfo), "\n") {
			if strings.HasPrefix(line, "MemTotal:") {
				result.Details = append(result.Details, "Memory: "+strings.TrimSpace(strings.TrimPrefix(line, "MemTotal:")))
			}
			if strings.HasPrefix(line, "MemAvailable:") {
				result.Details = append(result.Details, "Available: "+strings.TrimSpace(strings.TrimPrefix(line, "MemAvailable:")))
			}
		}
	}

	// CPU
	cpuInfo, err := exec.CommandContext(rc.Ctx, "nproc").Output()
	if err == nil {
		result.Details = append(result.Details, fmt.Sprintf("CPU cores: %s", strings.TrimSpace(string(cpuInfo))))
	}

	// Disk space for critical paths
	paths := []string{"/", "/var", "/opt", "/tmp"}
	for _, path := range paths {
		out, err := exec.CommandContext(rc.Ctx, "df", "-h", path).Output()
		if err == nil {
			lines := strings.Split(string(out), "\n")
			if len(lines) >= 2 {
				fields := strings.Fields(lines[1])
				if len(fields) >= 5 {
					result.Details = append(result.Details,
						fmt.Sprintf("Disk %s: %s used of %s (%s full)",
							path, fields[2], fields[1], fields[4]))
				}
			}
		}
	}

	// Load average
	loadavg, err := os.ReadFile("/proc/loadavg")
	if err == nil {
		fields := strings.Fields(string(loadavg))
		if len(fields) >= 3 {
			result.Details = append(result.Details,
				fmt.Sprintf("Load average: %s %s %s", fields[0], fields[1], fields[2]))
		}
	}

	result.Status = "PASS"
	result.Message = "System resources checked"
	logger.Debug("System resources check complete")
	return result
}

func checkBootstrapPhases(rc *eos_io.RuntimeContext) CheckResult {
	logger := otelzap.Ctx(rc.Ctx)
	result := CheckResult{Name: "Bootstrap Phases"}

	phases := []struct {
		name      string
		component string
		check     func() string
	}{
		{
			"Phase 1: Consul",
			"consul",
			func() string {
				if _, err := os.Stat("/usr/bin/consul"); err == nil {
					if out, err := exec.CommandContext(rc.Ctx, "systemctl", "is-active", "consul").Output(); err == nil {
						if strings.TrimSpace(string(out)) == "active" {
							return "COMPLETE"
						}
						return "INSTALLED (not running)"
					}
					return "INSTALLED (service not configured)"
				}
				return "NOT STARTED"
			},
		},
		{
			"Phase 2: Vault",
			"vault",
			func() string {
				if _, err := os.Stat(vault.VaultBinaryPath); err == nil {
					if out, err := exec.CommandContext(rc.Ctx, "systemctl", "is-active", "vault").Output(); err == nil {
						if strings.TrimSpace(string(out)) == "active" {
							return "COMPLETE"
						}
						return "INSTALLED (not running)"
					}
					return "INSTALLED (service not configured)"
				}
				return "NOT STARTED"
			},
		},
		{
			"Phase 3: Nomad",
			"nomad",
			func() string {
				if _, err := os.Stat("/usr/bin/nomad"); err == nil {
					if out, err := exec.CommandContext(rc.Ctx, "systemctl", "is-active", "nomad").Output(); err == nil {
						if strings.TrimSpace(string(out)) == "active" {
							return "COMPLETE"
						}
						return "INSTALLED (not running)"
					}
					return "INSTALLED (service not configured)"
				}
				return "NOT STARTED (optional)"
			},
		},
	}

	for _, phase := range phases {
		status := phase.check()
		icon := "○"
		if strings.Contains(status, "COMPLETE") {
			icon = "✓"
		} else if strings.Contains(status, "INSTALLED") {
			icon = "⚠"
		} else if strings.Contains(status, "NOT STARTED") && !strings.Contains(status, "optional") {
			icon = "✗"
		}
		result.Details = append(result.Details, fmt.Sprintf("%s %s: %s", icon, phase.name, status))
	}

	result.Status = "PASS"
	result.Message = "Phase status checked"
	logger.Debug("Bootstrap phases check complete")
	return result
}

func checkPreviousAttempts(rc *eos_io.RuntimeContext) CheckResult {
	logger := otelzap.Ctx(rc.Ctx)
	result := CheckResult{Name: "Previous Bootstrap Attempts"}

	// Check bootstrap logs
	logPaths := []string{
		"/var/log/eos/bootstrap.log",
		"/var/log/eos/eos.log",
	}

	for _, logPath := range logPaths {
		if info, err := os.Stat(logPath); err == nil {
			result.Details = append(result.Details,
				fmt.Sprintf("Log file: %s (size: %d bytes, modified: %s)",
					logPath, info.Size(), info.ModTime().Format("2006-01-02 15:04:05")))

			// Get last 20 lines
			out, err := exec.CommandContext(rc.Ctx, "tail", "-n", "20", logPath).CombinedOutput()
			if err == nil {
				result.Details = append(result.Details, "\nRecent log entries:")
				result.Details = append(result.Details, string(out))
			}
		}
	}

	// Check systemd journal for bootstrap-related entries
	out, err := exec.CommandContext(rc.Ctx, "journalctl", "-u", "eos-bootstrap", "-n", "10", "--no-pager").CombinedOutput()
	if err == nil && len(out) > 0 {
		result.Details = append(result.Details, "\nRecent systemd journal entries:")
		result.Details = append(result.Details, string(out))
	}

	// Check for backup files (indicates previous attempts)
	backupPattern := "/etc/systemd/system/*.backup.*"
	matches, _ := filepath.Glob(backupPattern)
	if len(matches) > 0 {
		result.Details = append(result.Details,
			fmt.Sprintf("\nFound %d backup file(s) from previous attempts:", len(matches)))
		for _, match := range matches {
			info, _ := os.Stat(match)
			result.Details = append(result.Details,
				fmt.Sprintf("  %s (created: %s)", match, info.ModTime().Format("2006-01-02 15:04:05")))
		}
	}

	result.Status = "PASS"
	result.Message = "Previous attempt information collected"
	logger.Debug("Previous attempts check complete")
	return result
}

func printBootstrapDebugResults(rc *eos_io.RuntimeContext, result BootstrapDebugResult) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("terminal prompt: " + strings.Repeat("=", 80))
	logger.Info("terminal prompt: BOOTSTRAP DIAGNOSTICS REPORT")
	logger.Info(fmt.Sprintf("terminal prompt: Generated: %s", result.Timestamp.Format(time.RFC3339)))
	logger.Info("terminal prompt: " + strings.Repeat("=", 80))

	checks := []CheckResult{
		result.SystemCheck,
		result.PrerequisitesCheck,
		result.StateCheck,
		result.LockCheck,
		result.ServicesCheck,
		result.PortsCheck,
		result.NetworkCheck,
		result.ResourcesCheck,
		result.PhaseCheck,
		result.PreviousAttemptsCheck,
	}

	for _, check := range checks {
		printBootstrapCheckResult(rc, check)
	}
}

func printBootstrapCheckResult(rc *eos_io.RuntimeContext, check CheckResult) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("terminal prompt: " + strings.Repeat("-", 80))

	statusIcon := ""
	switch check.Status {
	case "PASS":
		statusIcon = "✓"
	case "WARN":
		statusIcon = "⚠"
	case "FAIL":
		statusIcon = "✗"
	default:
		statusIcon = "?"
	}

	logger.Info(fmt.Sprintf("terminal prompt: [%s] %s: %s", statusIcon, check.Name, check.Message))

	if check.Error != nil {
		logger.Info(fmt.Sprintf("terminal prompt:     Error: %v", check.Error))
	}

	if len(check.Details) > 0 {
		for _, detail := range check.Details {
			if detail != "" {
				logger.Info("terminal prompt:     " + detail)
			}
		}
	}
}

func generateBootstrapSummary(result BootstrapDebugResult) string {
	var summary strings.Builder

	passCount := 0
	warnCount := 0
	failCount := 0

	checks := []CheckResult{
		result.SystemCheck,
		result.PrerequisitesCheck,
		result.StateCheck,
		result.LockCheck,
		result.ServicesCheck,
		result.PortsCheck,
		result.NetworkCheck,
		result.ResourcesCheck,
		result.PhaseCheck,
		result.PreviousAttemptsCheck,
	}

	for _, check := range checks {
		switch check.Status {
		case "PASS":
			passCount++
		case "WARN":
			warnCount++
		case "FAIL":
			failCount++
		}
	}

	summary.WriteString(fmt.Sprintf("Checks: %d passed, %d warnings, %d failed\n\n",
		passCount, warnCount, failCount))

	// Critical issues
	if failCount > 0 {
		summary.WriteString("CRITICAL ISSUES:\n")
		for _, check := range checks {
			if check.Status == "FAIL" {
				summary.WriteString(fmt.Sprintf("  ✗ %s: %s\n", check.Name, check.Message))
			}
		}
		summary.WriteString("\n")
	}

	// Warnings
	if warnCount > 0 {
		summary.WriteString("WARNINGS:\n")
		for _, check := range checks {
			if check.Status == "WARN" {
				summary.WriteString(fmt.Sprintf("  ⚠ %s: %s\n", check.Name, check.Message))
			}
		}
		summary.WriteString("\n")
	}

	// Specific recommendations
	summary.WriteString("RECOMMENDATIONS:\n\n")

	if result.LockCheck.Status == "FAIL" {
		summary.WriteString("1. CLEAR STALE LOCKS:\n")
		summary.WriteString("   sudo rm -f /var/lock/eos-*.lock\n\n")
	}

	if result.ServicesCheck.Status == "FAIL" {
		summary.WriteString("2. CHECK CONSUL SERVICE:\n")
		summary.WriteString("   sudo eos debug consul\n")
		summary.WriteString("   sudo journalctl -u consul -n 50\n\n")
	}

	if result.PortsCheck.Status == "FAIL" {
		summary.WriteString("3. RESOLVE PORT CONFLICTS:\n")
		summary.WriteString("   Stop conflicting services or use --stop-conflicting flag\n\n")
	}

	if result.StateCheck.Status == "WARN" {
		summary.WriteString("4. CLEAN PREVIOUS BOOTSTRAP STATE:\n")
		summary.WriteString("   Use --clean flag to start fresh:\n")
		summary.WriteString("   sudo eos bootstrap --clean\n\n")
	}

	if result.NetworkCheck.Status == "WARN" || result.NetworkCheck.Status == "FAIL" {
		summary.WriteString("5. CHECK NETWORK CONNECTIVITY:\n")
		summary.WriteString("   Verify DNS and internet access for downloading components\n\n")
	}

	// Specific action based on phase
	summary.WriteString("NEXT STEPS:\n\n")

	if strings.Contains(result.PhaseCheck.Message, "Consul") ||
		strings.Contains(result.ServicesCheck.Message, "No infrastructure") {
		summary.WriteString("Bootstrap appears to be failing during Consul installation.\n")
		summary.WriteString("This is the most common failure point. Try:\n\n")
		summary.WriteString("1. Run detailed Consul diagnostics:\n")
		summary.WriteString("   sudo eos debug consul\n\n")
		summary.WriteString("2. Try manual Consul start to see exact error:\n")
		summary.WriteString("   sudo -u consul /usr/bin/consul agent -config-dir=/etc/consul.d\n\n")
		summary.WriteString("3. Check system logs:\n")
		summary.WriteString("   sudo journalctl -u consul -f\n\n")
		summary.WriteString("4. If persistent, try bootstrap with verbose logging:\n")
		summary.WriteString("   sudo EOS_LOG_LEVEL=debug eos bootstrap\n\n")
	} else if result.StateCheck.Status == "WARN" {
		summary.WriteString("Previous bootstrap attempts detected.\n")
		summary.WriteString("Try a clean bootstrap:\n\n")
		summary.WriteString("   sudo eos bootstrap --clean\n\n")
	} else {
		summary.WriteString("Run bootstrap with appropriate flags:\n\n")
		summary.WriteString("   sudo eos bootstrap --single-node\n\n")
		summary.WriteString("Or for development:\n\n")
		summary.WriteString("   sudo eos bootstrap quickstart\n\n")
	}

	return summary.String()
}
