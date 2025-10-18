// pkg/network/network.go
package network

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// checkIPv6Enabled checks if IPv6 is enabled on the kernel.
func CheckIPv6Enabled() bool {
	out, err := exec.Command("sysctl", "-n", "net.ipv6.conf.all.disable_ipv6").Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "0"
}

// enableIPv6 attempts to enable IPv6 (requires root privileges).
func EnableIPv6() error {
	cmd := exec.Command("sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=0")
	return cmd.Run()
}

// getTailscaleIPv6 attempts to retrieve the first Tailscale IPv6 address.
func GetTailscaleIPv6() (string, error) {
	out, err := exec.Command("tailscale", "ip", "-6").Output()
	if err != nil {
		return "", err
	}
	lines := strings.Split(string(out), "\n")
	if len(lines) > 0 {
		ip := strings.TrimSpace(lines[0])
		return ip, nil
	}
	return "", fmt.Errorf("no Tailscale IPv6 address found")
}

// CheckResult represents a network check result
type CheckResult struct {
	Name        string
	Category    string
	Passed      bool
	Warning     bool
	Error       error
	Remediation []string
	Details     string
}

// CheckPing checks if a target host is reachable via ICMP ping
func CheckPing(rc *eos_io.RuntimeContext, targetIP string, targetName string) CheckResult {
	logger := otelzap.Ctx(rc.Ctx)

	ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ping", "-c", "3", "-W", "1", targetIP)
	output, err := cmd.CombinedOutput()

	if err != nil {
		logger.Error("Ping failed", zap.Error(err), zap.String("output", string(output)))
		return CheckResult{
			Name:     "Ping Connectivity",
			Category: "Network",
			Passed:   false,
			Error:    fmt.Errorf("cannot ping %s: %w", targetIP, err),
			Remediation: []string{
				fmt.Sprintf("Verify %s (%s) is powered on and accessible", targetName, targetIP),
				"Check network connectivity: ip route get " + targetIP,
				"Verify IP address is correct",
				"Check if ICMP is blocked by firewall",
			},
			Details: string(output),
		}
	}

	logger.Debug("Ping successful", zap.String("output", string(output)))
	return CheckResult{
		Name:     "Ping Connectivity",
		Category: "Network",
		Passed:   true,
		Details:  fmt.Sprintf("Successfully pinged %s", targetIP),
	}
}

// CheckTCPConnection checks if a TCP port is accessible on a target host
func CheckTCPConnection(rc *eos_io.RuntimeContext, targetIP string, targetPort int, serviceName string) CheckResult {
	logger := otelzap.Ctx(rc.Ctx)

	target := net.JoinHostPort(targetIP, fmt.Sprint(targetPort))
	conn, err := net.DialTimeout("tcp", target, 3*time.Second)

	if err != nil {
		logger.Error("TCP connection failed", zap.Error(err), zap.String("target", target))
		return CheckResult{
			Name:     "TCP Port Connectivity",
			Category: "Network",
			Passed:   false,
			Error:    fmt.Errorf("port %d not accessible: %w", targetPort, err),
			Remediation: []string{
				fmt.Sprintf("Verify %s service is running on %s", serviceName, targetIP),
				"Check if service is listening: sudo ss -tulpn | grep " + fmt.Sprint(targetPort),
				"Check firewall rules on both machines",
				"Verify port number is correct in configuration",
			},
		}
	}
	_ = conn.Close()

	logger.Debug("TCP connection successful", zap.String("target", target))
	return CheckResult{
		Name:     "TCP Port Connectivity",
		Category: "Network",
		Passed:   true,
		Details:  fmt.Sprintf("Port %d is open and accepting connections", targetPort),
	}
}

// CheckNetworkLatency measures network latency to a target host and port
func CheckNetworkLatency(rc *eos_io.RuntimeContext, targetIP string, targetPort int, serviceName string) CheckResult {
	logger := otelzap.Ctx(rc.Ctx)

	// Measure latency with multiple TCP connections
	var latencies []time.Duration
	target := net.JoinHostPort(targetIP, fmt.Sprint(targetPort))

	for i := 0; i < 3; i++ {
		start := time.Now()
		conn, err := net.DialTimeout("tcp", target, 2*time.Second)
		latency := time.Since(start)

		if err != nil {
			logger.Warn("Latency check connection failed", zap.Int("attempt", i+1), zap.Error(err))
			continue
		}
		_ = conn.Close()
		latencies = append(latencies, latency)
	}

	if len(latencies) == 0 {
		return CheckResult{
			Name:     "Network Latency",
			Category: "Network",
			Passed:   false,
			Error:    fmt.Errorf("could not measure latency"),
			Remediation: []string{
				"Network appears unstable or port is not consistently accessible",
				"Check network congestion",
				fmt.Sprintf("Verify %s service is stable", serviceName),
			},
		}
	}

	// Calculate average latency
	var total time.Duration
	for _, l := range latencies {
		total += l
	}
	avgLatency := total / time.Duration(len(latencies))

	logger.Debug("Network latency measured",
		zap.Duration("avg_latency", avgLatency),
		zap.Int("samples", len(latencies)))

	// Warn if latency is high
	warning := avgLatency > 100*time.Millisecond
	details := fmt.Sprintf("Average latency: %v (%d samples)", avgLatency, len(latencies))

	return CheckResult{
		Name:     "Network Latency",
		Category: "Network",
		Passed:   !warning,
		Warning:  warning,
		Error:    nil,
		Details:  details,
		Remediation: func() []string {
			if warning {
				return []string{
					fmt.Sprintf("Network latency is high (%v)", avgLatency),
					"Check network congestion",
					"Verify no routing issues",
				}
			}
			return nil
		}(),
	}
}

// CheckFirewallRules checks for firewall rules that might block connectivity
func CheckFirewallRules(rc *eos_io.RuntimeContext, targetIP string, targetPort int) CheckResult {
	logger := otelzap.Ctx(rc.Ctx)

	// Check iptables/ufw for blocking rules
	ctx, cancel := context.WithTimeout(rc.Ctx, 3*time.Second)
	defer cancel()

	var details []string

	// Check ufw status
	ufwCmd := exec.CommandContext(ctx, "sudo", "ufw", "status")
	ufwOutput, err := ufwCmd.CombinedOutput()
	if err == nil && strings.Contains(string(ufwOutput), "Status: active") {
		details = append(details, "UFW firewall is active")
		// Check for specific rule
		if !strings.Contains(string(ufwOutput), fmt.Sprint(targetPort)) {
			details = append(details, fmt.Sprintf("No explicit UFW rule for port %d", targetPort))
		}
	}

	// Check iptables
	iptablesCmd := exec.CommandContext(ctx, "sudo", "iptables", "-L", "-n")
	iptablesOutput, err := iptablesCmd.CombinedOutput()
	if err == nil {
		// Look for DROP or REJECT rules
		lines := strings.Split(string(iptablesOutput), "\n")
		for _, line := range lines {
			if (strings.Contains(line, "DROP") || strings.Contains(line, "REJECT")) &&
				strings.Contains(line, targetIP) {
				details = append(details, "Found potential blocking iptables rule: "+line)
			}
		}
	}

	logger.Debug("Firewall check completed", zap.Strings("details", details))

	if len(details) == 0 {
		return CheckResult{
			Name:     "Firewall Rules",
			Category: "Network",
			Passed:   true,
			Warning:  true,
			Details:  "No obvious firewall blocking rules detected (limited check)",
		}
	}

	return CheckResult{
		Name:     "Firewall Rules",
		Category: "Network",
		Passed:   true,
		Warning:  true,
		Details:  strings.Join(details, "\n  "),
		Remediation: []string{
			"Review firewall rules manually if experiencing connectivity issues",
			"Check UFW: sudo ufw status verbose",
			"Check iptables: sudo iptables -L -n -v",
		},
	}
}
