// pkg/ceph/network.go
package ceph

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

// CheckNetwork checks network connectivity to monitors
func CheckNetwork(logger otelzap.LoggerWithCtx, verbose bool) DiagnosticResult {
	logger.Info("Checking network connectivity...")

	// Get monitor addresses from config
	cmd := exec.Command("grep", "mon_host", "/etc/ceph/ceph.conf")
	output, err := cmd.Output()
	if err != nil {
		logger.Warn("⚠️  Cannot find mon_host in config")
		return DiagnosticResult{
			CheckName: "Network",
			Passed:    false,
			Error:     fmt.Errorf("no monitor hosts configured"),
		}
	}

	monHostLine := strings.TrimSpace(string(output))
	logger.Info("Monitor configuration: " + monHostLine)

	// Extract IP/hostname from Ceph address format
	// Format can be: [v2:IP:3300/0,v1:IP:6789/0] or just IP
	parts := strings.Split(monHostLine, "=")
	if len(parts) < 2 {
		return DiagnosticResult{
			CheckName: "Network",
			Passed:    false,
			Error:     fmt.Errorf("cannot parse mon_host"),
		}
	}

	monHosts := strings.TrimSpace(parts[1])

	// Parse Ceph address format: [v2:192.168.6.77:3300/0,v1:192.168.6.77:6789/0]
	// Extract unique IP addresses
	uniqueIPs := make(map[string]bool)

	// Remove brackets
	monHosts = strings.Trim(monHosts, "[]")

	// Split by comma
	addrs := strings.Split(monHosts, ",")
	for _, addr := range addrs {
		addr = strings.TrimSpace(addr)
		// Format: v2:192.168.6.77:3300/0 or just 192.168.6.77
		if strings.Contains(addr, ":") {
			// Extract IP from protocol:IP:port/rank format
			colonParts := strings.Split(addr, ":")
			if len(colonParts) >= 2 {
				// colonParts[0] is protocol (v1/v2), colonParts[1] is IP
				ip := colonParts[1]
				// Handle case where IP might have more colons (IPv6)
				if len(colonParts) > 2 {
					// For IPv4, colonParts[1] is the IP
					// For formats like v2:192.168.6.77:3300, we want colonParts[1]
					ip = colonParts[1]
				}
				uniqueIPs[ip] = true
			}
		} else {
			// Plain IP address
			uniqueIPs[addr] = true
		}
	}

	if len(uniqueIPs) == 0 {
		logger.Warn("⚠️  Could not extract monitor IPs from config")
		uniqueIPs[monHosts] = true // Try the raw value as fallback
	}

	// First, check if monitor ports are listening locally
	logger.Info("")
	logger.Info("Checking if monitor ports are listening:")
	cmd = exec.Command("ss", "-tlnp")
	output, _ = cmd.Output()
	ssOutput := string(output)

	monPortsListening := false
	for _, port := range []string{"3300", "6789"} {
		if strings.Contains(ssOutput, ":"+port) {
			logger.Info(fmt.Sprintf("  ✓ Port %s is LISTENING", port))
			monPortsListening = true

			// Extract which process is listening
			if verbose {
				lines := strings.Split(ssOutput, "\n")
				for _, line := range lines {
					if strings.Contains(line, ":"+port) {
						logger.Info("    " + strings.TrimSpace(line))
					}
				}
			}
		} else {
			logger.Warn(fmt.Sprintf("  ✗ Port %s is NOT listening", port))
		}
	}

	if !monPortsListening {
		logger.Error("❌ CRITICAL: No monitor ports are listening!")
		logger.Info("  → This means ceph-mon is not running or failed to bind ports")
		logger.Info("  → Check: journalctl -u ceph-mon@* -n 50")
		return DiagnosticResult{
			CheckName: "Network",
			Passed:    false,
			Error:     fmt.Errorf("monitor ports not listening - daemon not running"),
		}
	}

	// Now check connectivity to configured IPs
	logger.Info("")
	logger.Info("Checking connectivity to configured monitor hosts:")
	for ip := range uniqueIPs {
		logger.Info(fmt.Sprintf("  Checking: %s", ip))

		// Try to ping
		cmd = exec.Command("ping", "-c", "1", "-W", "2", ip)
		if err := cmd.Run(); err != nil {
			logger.Warn(fmt.Sprintf("    ✗ Cannot ping %s", ip))
			logger.Info("      → Network connectivity issue or firewall")
		} else {
			logger.Info("    ✓ Ping successful")
		}
	}

	return DiagnosticResult{
		CheckName: "Network",
		Passed:    true,
	}
}
