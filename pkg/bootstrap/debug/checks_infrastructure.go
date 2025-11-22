// pkg/bootstrap/debug/checks_infrastructure.go
package debug

import (
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CheckInfraServices verifies the status of infrastructure services (Consul, Vault, Nomad)
func CheckInfraServices(rc *eos_io.RuntimeContext) CheckResult {
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

// CheckInfraPorts detects port conflicts on infrastructure service ports
func CheckInfraPorts(rc *eos_io.RuntimeContext) CheckResult {
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
			_ = conn.Close()
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

// CheckNetworkConfig validates network configuration and connectivity
func CheckNetworkConfig(rc *eos_io.RuntimeContext) CheckResult {
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
