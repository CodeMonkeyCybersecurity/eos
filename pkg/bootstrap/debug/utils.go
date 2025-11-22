// pkg/bootstrap/debug/utils.go
package debug

import (
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

// PrintBootstrapDebugResults outputs all diagnostic results to the logger
func PrintBootstrapDebugResults(rc *eos_io.RuntimeContext, result BootstrapDebugResult) {
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
		PrintBootstrapCheckResult(rc, check)
	}
}

// PrintBootstrapCheckResult outputs a single check result to the logger
func PrintBootstrapCheckResult(rc *eos_io.RuntimeContext, check CheckResult) {
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

// GenerateBootstrapSummary creates a summary and recommendations based on all check results
func GenerateBootstrapSummary(result BootstrapDebugResult) string {
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
		summary.WriteString(fmt.Sprintf("   sudo -u consul %s agent -config-dir=/etc/consul.d\n\n", consul.GetConsulBinaryPath()))
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
