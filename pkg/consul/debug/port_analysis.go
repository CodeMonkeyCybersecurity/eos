package debug

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

// checkDetailedPortBindings shows which addresses Consul ports are bound to
func checkDetailedPortBindings(rc *eos_io.RuntimeContext) DiagnosticResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Checking detailed port bindings")

	result := DiagnosticResult{
		CheckName: "Port Bindings Analysis",
		Success:   true,
		Details:   []string{},
	}

	// Consul ports (HashiCorp standards)
	ports := map[int]string{
		8500: "HTTP API",
		8502: "gRPC",
		8600: "DNS",
		8301: "Serf LAN",
		8302: "Serf WAN",
		8300: "RPC",
	}

	result.Details = append(result.Details, "")
	result.Details = append(result.Details, "=== Port Binding Details ===")

	// Use ss command to show detailed binding information
	cmd := execute.Options{
		Command: "ss",
		Args:    []string{"-tlnp"},
		Capture: true,
	}

	output, err := execute.Run(rc.Ctx, cmd)
	if err != nil {
		// Fallback to netstat
		cmd = execute.Options{
			Command: "netstat",
			Args:    []string{"-tlnp"},
			Capture: true,
		}
		output, _ = execute.Run(rc.Ctx, cmd)
	}

	foundPorts := 0
	notFoundPorts := []string{}

	for port, desc := range ports {
		portStr := fmt.Sprintf(":%d", port)
		found := false
		bindAddress := ""

		// Parse ss/netstat output to find binding address
		lines := strings.Split(output, "\n")
		for _, line := range lines {
			if strings.Contains(line, portStr) {
				found = true
				foundPorts++

				// Extract local address
				// Format: LISTEN 0 4096 0.0.0.0:8161 0.0.0.0:* users:(("consul",pid=...))
				fields := strings.Fields(line)
				if len(fields) >= 4 {
					bindAddress = fields[3] // This is the local address:port
				}

				result.Details = append(result.Details,
					fmt.Sprintf("✓ Port %d (%s): LISTENING on %s", port, desc, bindAddress))

				// Warn about problematic bindings
				if strings.HasPrefix(bindAddress, shared.GetInternalHostname()) || strings.HasPrefix(bindAddress, "localhost") {
					if port == 8301 || port == 8302 || port == 8300 {
						result.Details = append(result.Details,
							fmt.Sprintf("  ⚠ WARNING: %s bound to loopback - cluster communication will FAIL", desc))
						result.Success = false
					}
				}

				break
			}
		}

		if !found {
			notFoundPorts = append(notFoundPorts, fmt.Sprintf("%s (port %d)", desc, port))
			result.Details = append(result.Details,
				fmt.Sprintf("✗ Port %d (%s): NOT LISTENING", port, desc))
		}
	}

	result.Details = append(result.Details, "")

	if foundPorts == 0 {
		result.Success = false
		result.Severity = SeverityInfo // INFO: Expected if Consul not running
		result.Message = "No Consul ports are listening"
	} else if len(notFoundPorts) > 0 {
		result.Message = fmt.Sprintf("%d/%d ports listening (missing: %s)",
			foundPorts, len(ports), strings.Join(notFoundPorts, ", "))
		if strings.Contains(strings.Join(notFoundPorts, ","), "Serf") || strings.Contains(strings.Join(notFoundPorts, ","), "RPC") {
			result.Success = false
		}
	} else {
		result.Message = "All Consul ports are listening"
	}

	return result
}

// checkClusterState inspects Consul cluster membership and health
func checkClusterState(rc *eos_io.RuntimeContext) DiagnosticResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Checking Consul cluster state")

	result := DiagnosticResult{
		CheckName: "Cluster State",
		Success:   true,
		Details:   []string{},
	}

	result.Details = append(result.Details, "")
	result.Details = append(result.Details, "=== Cluster Membership ===")

	// Try to get cluster members
	cmd := execute.Options{
		Command: "consul",
		Args:    []string{"members"},
		Capture: true,
	}

	output, err := execute.Run(rc.Ctx, cmd)
	if err != nil {
		result.Success = false
		result.Severity = SeverityInfo // INFO: Expected if Consul not running
		result.Message = "Failed to retrieve cluster members"
		result.Details = append(result.Details, fmt.Sprintf("Error: %v", err))
		result.Details = append(result.Details, "Output: "+output)
		return result
	}

	// Parse members output
	lines := strings.Split(output, "\n")
	memberCount := 0
	leaderFound := false

	result.Details = append(result.Details, "")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Node") {
			continue
		}

		memberCount++
		result.Details = append(result.Details, line)

		if strings.Contains(line, "leader") {
			leaderFound = true
		}
	}

	result.Details = append(result.Details, "")
	result.Details = append(result.Details, fmt.Sprintf("Total members: %d", memberCount))

	switch memberCount {
	case 0:
		result.Success = false
		result.Severity = SeverityInfo // INFO: Expected if Consul not running
		result.Message = "No cluster members found (Consul may not be running)"
	case 1:
		result.Message = "Single-node cluster (no peers joined)"
	default:
		if leaderFound {
			result.Message = fmt.Sprintf("Multi-node cluster with %d members (leader elected)", memberCount)
		} else {
			result.Success = false
			result.Message = fmt.Sprintf("Multi-node cluster with %d members (no leader - possible split-brain)", memberCount)
		}
	}

	// Get raft peer information
	result.Details = append(result.Details, "")
	result.Details = append(result.Details, "=== Raft Peers ===")

	raftCmd := execute.Options{
		Command: "consul",
		Args:    []string{"operator", "raft", "list-peers"},
		Capture: true,
	}

	raftOutput, raftErr := execute.Run(rc.Ctx, raftCmd)
	if raftErr == nil {
		result.Details = append(result.Details, raftOutput)
	} else {
		result.Details = append(result.Details, fmt.Sprintf("Could not retrieve raft peers: %v", raftErr))
	}

	return result
}

// checkRetryJoinTargets validates retry_join targets are reachable
func checkRetryJoinTargets(rc *eos_io.RuntimeContext, retryJoinAddrs []string) DiagnosticResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Checking retry_join targets")

	result := DiagnosticResult{
		CheckName: "Retry Join Targets",
		Success:   true,
		Details:   []string{},
	}

	if len(retryJoinAddrs) == 0 {
		result.Message = "No retry_join targets configured"
		result.Details = append(result.Details, "This node will not automatically join other nodes")
		return result
	}

	result.Details = append(result.Details, "")
	result.Details = append(result.Details, "=== Retry Join Target Connectivity ===")

	unreachable := []string{}

	for _, addr := range retryJoinAddrs {
		// Try to resolve and ping the address
		pingCmd := execute.Options{
			Command: "ping",
			Args:    []string{"-c", "1", "-W", "2", extractIPOrHostname(addr)},
			Capture: true,
		}

		pingOutput, pingErr := execute.Run(rc.Ctx, pingCmd)

		if pingErr != nil {
			unreachable = append(unreachable, addr)
			result.Details = append(result.Details,
				fmt.Sprintf("✗ %s: UNREACHABLE (ping failed)", addr))
			result.Details = append(result.Details,
				fmt.Sprintf("  Error: %v", pingErr))
			result.Success = false
		} else {
			result.Details = append(result.Details,
				fmt.Sprintf("✓ %s: REACHABLE", addr))

			// Extract RTT from ping output
			rttRegex := regexp.MustCompile(`time=([0-9.]+)\s*ms`)
			if match := rttRegex.FindStringSubmatch(pingOutput); len(match) > 1 {
				result.Details = append(result.Details,
					fmt.Sprintf("  RTT: %s ms", match[1]))
			}
		}
	}

	if len(unreachable) > 0 {
		result.Message = fmt.Sprintf("%d/%d targets unreachable: %s",
			len(unreachable), len(retryJoinAddrs), strings.Join(unreachable, ", "))
	} else {
		result.Message = fmt.Sprintf("All %d retry_join targets are reachable", len(retryJoinAddrs))
	}

	return result
}

// extractIPOrHostname extracts just the IP or hostname from an address
func extractIPOrHostname(addr string) string {
	// Handle "192.168.1.1:8301" -> "192.168.1.1"
	if idx := strings.Index(addr, ":"); idx != -1 {
		return addr[:idx]
	}
	return addr
}
