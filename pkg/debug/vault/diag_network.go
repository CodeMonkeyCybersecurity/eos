// pkg/debug/vault/diag_network.go
// Vault network diagnostic checks
//
// This module contains diagnostics for Vault network connectivity:
// - ProcessDiagnostic: Vault process detection via pgrep
// - PortDiagnostic: Port binding checks (API 8179, Cluster 8180) using lsof/netstat/ss
// - HealthCheckDiagnostic: HTTP health endpoint check (http://shared.GetInternalHostname:8179/v1/sys/health)

package vault

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/debug"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ProcessDiagnostic checks for running vault processes
func ProcessDiagnostic() *debug.Diagnostic {
	return debug.CommandCheck("Running Processes", "System", "pgrep", "-a", "vault")
}

// PortDiagnostic checks if vault is listening on configured ports using multiple methods
func PortDiagnostic() *debug.Diagnostic {
	return &debug.Diagnostic{
		Name:        fmt.Sprintf("Vault Ports (%d API, %d Cluster)", shared.PortVault, shared.PortVault+1),
		Category:    "Network",
		Description: fmt.Sprintf("Check if Vault is listening on ports %d (API) and %d (Cluster) using lsof, netstat, and ss", shared.PortVault, shared.PortVault+1),
		Collect: func(ctx context.Context) (*debug.Result, error) {
			logger := otelzap.Ctx(ctx)
			logger.Info("Checking Vault network ports",
				zap.Int("api_port", shared.PortVault),
				zap.Int("cluster_port", shared.PortVault+1))

			result := &debug.Result{
				Metadata: make(map[string]interface{}),
			}

			var outputBuilder strings.Builder
			outputBuilder.WriteString("=== Network Port Diagnostics ===\n\n")

			// Method 1: lsof (shows which process owns the port)
			outputBuilder.WriteString(fmt.Sprintf("Method 1: lsof -i :%d\n", shared.PortVault))
			lsofCmd := exec.CommandContext(ctx, "lsof", "-i", fmt.Sprintf(":%d", shared.PortVault))
			lsofOutput, lsofErr := lsofCmd.CombinedOutput()
			if lsofErr == nil && len(lsofOutput) > 0 {
				outputBuilder.WriteString(string(lsofOutput))
				outputBuilder.WriteString("\n")
			} else if lsofErr != nil && strings.Contains(lsofErr.Error(), "executable file not found") {
				outputBuilder.WriteString("  (lsof not installed)\n\n")
			} else {
				outputBuilder.WriteString(fmt.Sprintf("  No process listening on port %d\n\n", shared.PortVault))
			}

			// Method 2: netstat (traditional, widely available)
			outputBuilder.WriteString(fmt.Sprintf("Method 2: netstat -tulpn | grep %d\n", shared.PortVault))
			netstatCmd := exec.CommandContext(ctx, "sh", "-c", fmt.Sprintf("netstat -tulpn 2>/dev/null | grep ':%d'", shared.PortVault))
			netstatOutput, netstatErr := netstatCmd.CombinedOutput()
			if netstatErr == nil && len(netstatOutput) > 0 {
				outputBuilder.WriteString(string(netstatOutput))
				outputBuilder.WriteString("\n")
			} else if strings.Contains(string(netstatOutput), "command not found") {
				outputBuilder.WriteString("  (netstat not installed)\n\n")
			} else {
				outputBuilder.WriteString(fmt.Sprintf("  No process listening on port %d\n\n", shared.PortVault))
			}

			// Method 3: ss (modern replacement for netstat)
			outputBuilder.WriteString(fmt.Sprintf("Method 3: ss -tulpn | grep %d\n", shared.PortVault))
			ssCmd := exec.CommandContext(ctx, "sh", "-c", fmt.Sprintf("ss -tulpn | grep ':%d'", shared.PortVault))
			ssOutput, ssErr := ssCmd.CombinedOutput()
			if ssErr == nil && len(ssOutput) > 0 {
				outputBuilder.WriteString(string(ssOutput))
				outputBuilder.WriteString("\n")
			} else {
				outputBuilder.WriteString(fmt.Sprintf("  No process listening on port %d\n\n", shared.PortVault))
			}

			// Check cluster port (8180) with ss/netstat only
			outputBuilder.WriteString(fmt.Sprintf("Cluster Port Check: %d\n", shared.PortVault+1))
			clusterCmd := exec.CommandContext(ctx, "sh", "-c", fmt.Sprintf("ss -tlnp | grep ':%d' || netstat -tlnp 2>/dev/null | grep ':%d'", shared.PortVault+1, shared.PortVault+1))
			clusterOutput, _ := clusterCmd.CombinedOutput()

			// Determine if API port is listening based on any method
			apiListening := (lsofErr == nil && len(lsofOutput) > 0) ||
				(netstatErr == nil && len(netstatOutput) > 0) ||
				(ssErr == nil && len(ssOutput) > 0)

			clusterListening := len(clusterOutput) > 0

			result.Metadata["api_port"] = shared.PortVault
			result.Metadata["cluster_port"] = shared.PortVault + 1
			result.Metadata["api_listening"] = apiListening
			result.Metadata["cluster_listening"] = clusterListening
			result.Metadata["lsof_available"] = lsofErr == nil || !strings.Contains(string(lsofOutput), "not found")
			result.Metadata["netstat_available"] = netstatErr == nil || !strings.Contains(string(netstatOutput), "not found")
			result.Metadata["ss_available"] = ssErr == nil

			// Summary
			outputBuilder.WriteString("\n=== Summary ===\n")
			if apiListening {
				outputBuilder.WriteString(fmt.Sprintf("✓ API Port %d: LISTENING\n", shared.PortVault))
			} else {
				outputBuilder.WriteString(fmt.Sprintf("✗ API Port %d: NOT IN USE\n", shared.PortVault))
			}

			if clusterListening {
				outputBuilder.WriteString(fmt.Sprintf("✓ Cluster Port %d: LISTENING\n", shared.PortVault+1))
				outputBuilder.WriteString(string(clusterOutput))
			} else {
				outputBuilder.WriteString(fmt.Sprintf("✗ Cluster Port %d: NOT IN USE (normal for single-node)\n", shared.PortVault+1))
			}

			// Diagnostic commands for manual verification
			outputBuilder.WriteString("\n=== Manual Verification Commands ===\n")
			outputBuilder.WriteString(fmt.Sprintf("sudo lsof -i :%d\n", shared.PortVault))
			outputBuilder.WriteString(fmt.Sprintf("sudo netstat -tulpn | grep %d\n", shared.PortVault))
			outputBuilder.WriteString(fmt.Sprintf("sudo ss -tulpn | grep %d\n", shared.PortVault))
			outputBuilder.WriteString("curl -k https://localhost:8179/v1/sys/health\n")

			result.Output = outputBuilder.String()

			// Set status based on results
			if apiListening && clusterListening {
				logger.Info("Both Vault ports are listening",
					zap.Int("api_port", shared.PortVault),
					zap.Int("cluster_port", shared.PortVault+1))
				result.Status = debug.StatusOK
				result.Message = "Both API and cluster ports are listening"
			} else if apiListening {
				logger.Info("Vault API port is listening (cluster port not active)",
					zap.Int("api_port", shared.PortVault),
					zap.Bool("cluster_listening", false))
				result.Status = debug.StatusOK
				result.Message = "API port listening (cluster port not needed for single-node)"
			} else {
				logger.Error("Vault is not listening on configured port",
					zap.Int("expected_port", shared.PortVault))
				result.Status = debug.StatusError
				result.Message = fmt.Sprintf("Port %d not in use - Vault is not listening", shared.PortVault)
				result.Remediation = "Ensure vault service is running: sudo systemctl status vault\n" +
					"Check service logs: sudo journalctl -u vault -n 50\n" +
					"Verify configuration: vault validate /etc/vault.d/vault.hcl"
			}

			return result, nil
		},
	}
}

// HealthCheckDiagnostic performs HTTP health check
func HealthCheckDiagnostic() *debug.Diagnostic {
	healthURL := fmt.Sprintf("http://"+shared.GetInternalHostname()+":%d/v1/sys/health", shared.PortVault)
	return debug.NetworkCheck("HTTP Health Check", healthURL, 5*time.Second)
}
