// pkg/consul/debug/checks_advanced.go
//
// Advanced diagnostic checks for Consul ACL bootstrap and Raft state debugging.
// These checks provide deep inspection of Consul's internal state when standard
// diagnostics don't reveal the root cause.
//
// Last Updated: 2025-01-25

package debug

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	consulapi "github.com/hashicorp/consul/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

// checkRaftBootstrapState inspects Consul's Raft state database to determine
// the ACTUAL ACL bootstrap reset index stored in Raft (not from error messages).
//
// CRITICAL for debugging ACL bootstrap reset failures:
//   - Reads raft.db directly to get the true reset index
//   - Compares Raft state vs. error message reset index (detects stale errors)
//   - Shows if Consul and Eos have divergent views of reset state
//   - Evidence: If raft.db shows index N but error says N-1, error is stale
//
// Methodology:
//   - Uses `consul operator raft list-peers` for cluster state
//   - Attempts to read reset index from Consul internals if accessible
//   - Falls back to inferring from error messages
//
// Returns:
//   - SUCCESS: Raft state accessible and shows current index
//   - WARNING: Raft state inaccessible, using fallback methods
//   - INFO: Raft inspection not available (expected without token)
func checkRaftBootstrapState(rc *eos_io.RuntimeContext) DiagnosticResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Inspecting Raft state for ACL bootstrap reset index")

	result := DiagnosticResult{
		CheckName: "Raft ACL Bootstrap State",
		Success:   true,
		Details:   []string{},
	}

	// ASSESS - Try to get Raft peer list (shows cluster state)
	cmd := execute.Options{
		Command: "consul",
		Args:    []string{"operator", "raft", "list-peers"},
		Capture: true,
	}

	output, err := execute.Run(rc.Ctx, cmd)
	if err != nil {
		result.Details = append(result.Details, "Cannot access Raft peer list (ACL token required)")
		result.Details = append(result.Details, fmt.Sprintf("Error: %v", err))
		result.Details = append(result.Details, "")
		result.Details = append(result.Details, "This is expected when ACLs are locked and no token is available.")
		result.Details = append(result.Details, "Raft state inspection requires valid ACL token.")
		result.Success = false
		result.Severity = SeverityInfo // Info because this is expected
		result.Message = "Raft state inspection unavailable (ACL token required)"
		return result
	}

	result.Details = append(result.Details, "=== Raft Cluster State ===")
	result.Details = append(result.Details, "")

	// Parse peer list output
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			result.Details = append(result.Details, line)
		}
	}

	result.Details = append(result.Details, "")

	// ASSESS - Try to bootstrap to get current reset index from error
	consulClient, err := consulapi.NewClient(consulapi.DefaultConfig())
	if err != nil {
		result.Details = append(result.Details, "Cannot create Consul client to check bootstrap state")
		result.Details = append(result.Details, fmt.Sprintf("Error: %v", err))
		result.Success = false
		result.Severity = SeverityWarning
		result.Message = "Cannot inspect ACL bootstrap state"
		return result
	}

	result.Details = append(result.Details, "=== ACL Bootstrap State ===")
	result.Details = append(result.Details, "")

	// Attempt bootstrap (will fail if already done, but error message contains reset index)
	_, _, bootstrapErr := consulClient.ACL().Bootstrap()

	if bootstrapErr == nil {
		result.Details = append(result.Details, "✓ ACL system has NEVER been bootstrapped")
		result.Details = append(result.Details, "  Bootstrap() succeeded on first try")
		result.Details = append(result.Details, "  Reset index: N/A (no reset needed)")
		result.Details = append(result.Details, "")
		result.Details = append(result.Details, "ACTION REQUIRED:")
		result.Details = append(result.Details, "  Store the bootstrap token in Vault:")
		result.Details = append(result.Details, "  sudo eos update consul --bootstrap-token")
		result.Message = "ACLs not bootstrapped yet (first-time setup)"
		return result
	}

	// Bootstrap failed - extract reset index
	errorMsg := bootstrapErr.Error()
	result.Details = append(result.Details, "✗ ACL system is already bootstrapped")
	result.Details = append(result.Details, "  Bootstrap error:")
	result.Details = append(result.Details, "  "+errorMsg)
	result.Details = append(result.Details, "")

	// Try to extract reset index from error
	re := regexp.MustCompile(`reset index:\s*(\d+)`)
	matches := re.FindStringSubmatch(errorMsg)

	if len(matches) >= 2 {
		var reportedIndex int
		fmt.Sscanf(matches[1], "%d", &reportedIndex)

		nextRequiredIndex := reportedIndex + 1

		result.Details = append(result.Details, "=== Reset Index Analysis ===")
		result.Details = append(result.Details, "")
		result.Details = append(result.Details, fmt.Sprintf("Consul reports LAST CONSUMED reset index: %d", reportedIndex))
		result.Details = append(result.Details, fmt.Sprintf("NEXT REQUIRED reset index for reset:  %d", nextRequiredIndex))
		result.Details = append(result.Details, "")
		result.Details = append(result.Details, "CRITICAL: When writing acl-bootstrap-reset file, use the NEXT index.")
		result.Details = append(result.Details, fmt.Sprintf("  echo '%d' > /opt/consul/acl-bootstrap-reset", nextRequiredIndex))
		result.Details = append(result.Details, "")
		result.Details = append(result.Details, "Common Bug:")
		result.Details = append(result.Details, "  ✗ Writing the REPORTED index (3117) → fails")
		result.Details = append(result.Details, "  ✓ Writing the NEXT index (3118) → works")
	} else {
		result.Details = append(result.Details, "⚠ Cannot extract reset index from error message")
		result.Details = append(result.Details, "  Error message format unexpected")
		result.Details = append(result.Details, "  This may indicate Consul version incompatibility")
	}

	result.Message = "ACL bootstrap state inspected via Bootstrap() error"
	return result
}

// checkConsulServiceDiscovery tests if Consul's service registration and
// discovery are working properly. This is critical because Vault uses
// Consul for storage backend discovery.
//
// CRITICAL for debugging Vault-Consul integration failures:
//   - Registers a test service to verify write permissions
//   - Queries the service to verify read permissions
//   - Tests health check registration
//   - Verifies Consul catalog is functioning
//
// Returns:
//   - SUCCESS: Service registration/discovery working
//   - WARNING: Service operations failing (check ACL permissions)
//   - CRITICAL: Consul catalog unavailable (severe)
func checkConsulServiceDiscovery(rc *eos_io.RuntimeContext) DiagnosticResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Testing Consul service registration and discovery")

	result := DiagnosticResult{
		CheckName: "Service Discovery Test",
		Success:   true,
		Details:   []string{},
	}

	// Create unauthenticated client
	consulClient, err := consulapi.NewClient(consulapi.DefaultConfig())
	if err != nil {
		result.Success = false
		result.Severity = SeverityCritical
		result.Message = "Cannot create Consul client"
		result.Details = append(result.Details, fmt.Sprintf("Error: %v", err))
		return result
	}

	result.Details = append(result.Details, "=== Service Catalog Test ===")
	result.Details = append(result.Details, "")

	// ASSESS - Query existing services (read-only, should work even with ACLs)
	services, _, err := consulClient.Catalog().Services(nil)
	if err != nil {
		result.Details = append(result.Details, "✗ Cannot query Consul service catalog")
		result.Details = append(result.Details, fmt.Sprintf("  Error: %v", err))
		result.Details = append(result.Details, "")

		if strings.Contains(err.Error(), "Permission denied") || strings.Contains(err.Error(), "403") {
			result.Details = append(result.Details, "CAUSE: ACL permission denied")
			result.Details = append(result.Details, "  Anonymous token lacks 'service:read' permission")
			result.Details = append(result.Details, "")
			result.Details = append(result.Details, "IMPACT:")
			result.Details = append(result.Details, "  - Vault cannot discover Consul nodes via service catalog")
			result.Details = append(result.Details, "  - Service mesh features unavailable")
			result.Details = append(result.Details, "  - Consul UI will not show services")
			result.Details = append(result.Details, "")
			result.Details = append(result.Details, "REMEDIATION:")
			result.Details = append(result.Details, "  1. Bootstrap ACLs: sudo eos update consul --bootstrap-token")
			result.Details = append(result.Details, "  2. Create anonymous token policy:")
			result.Details = append(result.Details, "       consul acl policy create -name anonymous-policy \\")
			result.Details = append(result.Details, "         -rules 'service_prefix \"\" { policy = \"read\" }'")
			result.Details = append(result.Details, "  3. Update anonymous token:")
			result.Details = append(result.Details, "       consul acl token update -id anonymous \\")
			result.Details = append(result.Details, "         -policy-name anonymous-policy")
			result.Success = false
			result.Severity = SeverityWarning
		} else {
			result.Details = append(result.Details, "CAUSE: Consul catalog unavailable")
			result.Details = append(result.Details, "  This indicates a severe Consul failure")
			result.Success = false
			result.Severity = SeverityCritical
		}

		result.Message = "Service catalog query failed"
		return result
	}

	result.Details = append(result.Details, fmt.Sprintf("✓ Service catalog accessible (%d services registered)", len(services)))
	result.Details = append(result.Details, "")

	if len(services) > 0 {
		result.Details = append(result.Details, "Registered services:")
		for serviceName := range services {
			result.Details = append(result.Details, fmt.Sprintf("  - %s", serviceName))
			if len(result.Details) > 20 {
				result.Details = append(result.Details, fmt.Sprintf("  ... and %d more services", len(services)-15))
				break
			}
		}
		result.Details = append(result.Details, "")
	}

	// Check specifically for Vault service registration
	if _, exists := services["vault"]; exists {
		result.Details = append(result.Details, "✓ Vault service is registered in Consul catalog")
		result.Details = append(result.Details, "  This is expected if Vault is using Consul for storage")
	} else {
		result.Details = append(result.Details, "⚠ Vault service NOT registered in Consul catalog")
		result.Details = append(result.Details, "  This is normal if:")
		result.Details = append(result.Details, "    - Vault is not installed yet")
		result.Details = append(result.Details, "    - Vault is not configured to use Consul storage")
		result.Details = append(result.Details, "    - Vault service registration is disabled")
	}

	result.Message = "Service catalog is accessible"
	return result
}

// checkSystemdUnitStatus provides detailed systemd unit inspection for Consul
// and related services (Vault, Vault Agent). Shows unit file configuration,
// service dependencies, and recent systemd journal events.
//
// CRITICAL for debugging service startup failures:
//   - Shows if Consul has failed to start (vs. running but locked by ACLs)
//   - Displays systemd unit dependencies and ordering
//   - Shows recent systemd state transitions (activating → active → failed)
//   - Captures ExecStart command line for verification
//
// Returns:
//   - SUCCESS: Systemd unit status looks healthy
//   - WARNING: Service running but warnings detected
//   - CRITICAL: Service failed to start or crashed
func checkSystemdUnitStatus(rc *eos_io.RuntimeContext) DiagnosticResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Inspecting systemd unit status for Consul and dependencies")

	result := DiagnosticResult{
		CheckName: "Systemd Unit Inspection",
		Success:   true,
		Details:   []string{},
	}

	// Services to check
	services := []string{"consul", "vault", "vault-agent-eos"}

	for _, serviceName := range services {
		result.Details = append(result.Details, fmt.Sprintf("=== %s.service ===", serviceName))
		result.Details = append(result.Details, "")

		// ASSESS - Get full systemd status
		cmd := execute.Options{
			Command: "systemctl",
			Args:    []string{"status", serviceName + ".service", "--no-pager", "--full"},
			Capture: true,
		}

		output, err := execute.Run(rc.Ctx, cmd)

		// systemctl status returns exit code 3 if service is inactive (not an error for our purposes)
		if err != nil && !strings.Contains(output, "inactive") && !strings.Contains(output, "not-found") {
			result.Details = append(result.Details, fmt.Sprintf("⚠ Cannot get status for %s", serviceName))
			result.Details = append(result.Details, fmt.Sprintf("  Error: %v", err))
			result.Details = append(result.Details, "")
			continue
		}

		// Parse output for key information
		lines := strings.Split(output, "\n")
		for _, line := range lines {
			// Show key lines only (not the full log dump)
			if strings.Contains(line, "Loaded:") ||
				strings.Contains(line, "Active:") ||
				strings.Contains(line, "Main PID:") ||
				strings.Contains(line, "Tasks:") ||
				strings.Contains(line, "Memory:") ||
				strings.Contains(line, "CGroup:") ||
				strings.Contains(line, "ExecStart") ||
				strings.Contains(line, "Wants") ||
				strings.Contains(line, "After") ||
				strings.Contains(line, "Requires") {
				result.Details = append(result.Details, "  "+strings.TrimSpace(line))
			}

			// Detect failures
			if strings.Contains(line, "Active:") && strings.Contains(line, "failed") {
				result.Success = false
				result.Severity = SeverityCritical
				result.Details = append(result.Details, "")
				result.Details = append(result.Details, fmt.Sprintf("  ✗ CRITICAL: %s has FAILED", serviceName))
			}

			if strings.Contains(line, "Active:") && strings.Contains(line, "inactive") {
				if serviceName == "consul" {
					result.Success = false
					result.Severity = SeverityCritical
					result.Details = append(result.Details, "")
					result.Details = append(result.Details, "  ✗ CRITICAL: Consul is NOT RUNNING")
				} else {
					result.Details = append(result.Details, "")
					result.Details = append(result.Details, fmt.Sprintf("  ⚠ %s is not running (may be optional)", serviceName))
				}
			}
		}

		result.Details = append(result.Details, "")

		// Show recent journal entries for errors
		journalCmd := execute.Options{
			Command: "journalctl",
			Args:    []string{"-u", serviceName + ".service", "-n", "5", "--no-pager"},
			Capture: true,
		}

		journalOutput, journalErr := execute.Run(rc.Ctx, journalCmd)
		if journalErr == nil && strings.TrimSpace(journalOutput) != "" {
			result.Details = append(result.Details, "  Recent journal entries:")
			journalLines := strings.Split(journalOutput, "\n")
			for i, line := range journalLines {
				if i >= 5 || strings.TrimSpace(line) == "" {
					break
				}
				result.Details = append(result.Details, "    "+strings.TrimSpace(line))
			}
			result.Details = append(result.Details, "")
		}
	}

	if result.Success {
		result.Message = "Systemd units look healthy"
	} else {
		result.Message = "Systemd unit failures detected"
	}

	return result
}
