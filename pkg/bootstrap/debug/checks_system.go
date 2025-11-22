// pkg/bootstrap/debug/checks_system.go
package debug

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CheckSystemInfo gathers and validates system information
func CheckSystemInfo(rc *eos_io.RuntimeContext) CheckResult {
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

// CheckSystemResources checks system resource availability (memory, CPU, disk)
func CheckSystemResources(rc *eos_io.RuntimeContext) CheckResult {
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
