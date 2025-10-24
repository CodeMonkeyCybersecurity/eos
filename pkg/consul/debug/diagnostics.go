// Package debug provides comprehensive debugging tools for Consul service issues
package debug

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Config holds the debug configuration options
type Config struct {
	AutoFix       bool
	KillProcesses bool
	TestStart     bool
	MinimalConfig bool
	LogLines      int
}

// Severity indicates how critical a diagnostic failure is
type Severity int

const (
	// SeverityInfo - Informational only, doesn't affect Consul functionality
	// Examples: optional log file missing, non-critical warnings
	// Impact: User should know, but Consul works fine
	SeverityInfo Severity = 0

	// SeverityWarning - Should be fixed but doesn't block Consul operations
	// Examples: lingering processes, suboptimal config, permission warnings
	// Impact: May cause issues later, should address soon
	SeverityWarning Severity = 1

	// SeverityCritical - Blocks Consul from starting or functioning correctly
	// Examples: binary missing, config invalid, critical files unreadable
	// Impact: Consul cannot start or will fail immediately
	SeverityCritical Severity = 2
)

// DiagnosticResult holds the results of a diagnostic check
type DiagnosticResult struct {
	CheckName  string
	Success    bool
	Message    string
	Details    []string
	FixApplied bool
	FixMessage string
	Severity   Severity // How critical is this failure (only relevant if Success = false)
}

// RunDiagnostics performs comprehensive Consul debugging following Assess → Intervene → Evaluate pattern
func RunDiagnostics(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting Consul debug diagnostics",
		zap.Bool("auto_fix", config.AutoFix),
		zap.Bool("kill_processes", config.KillProcesses),
		zap.Bool("test_start", config.TestStart))

	results := []DiagnosticResult{}

	// ASSESS - Run all diagnostic checks
	logger.Info("=== ASSESS PHASE: Running diagnostic checks ===")

	// 1. Check Consul binary
	binaryResult := checkConsulBinary(rc)
	results = append(results, binaryResult)

	// 2. Check file permissions
	permissionsResult := checkConsulPermissions(rc)
	results = append(results, permissionsResult)

	// 3. Analyze configuration
	configResult := analyzeConfiguration(rc)
	results = append(results, configResult)

	// 4. Check systemd service
	serviceResult := checkSystemdService(rc)
	results = append(results, serviceResult)

	// 5. Check for lingering processes
	processResult := checkLingeringProcesses(rc)
	results = append(results, processResult)

	// 6. Check network configuration
	networkResult := checkConsulNetwork(rc)
	results = append(results, networkResult)

	// 7. Check port connectivity (enhanced)
	portsResult := checkConsulPorts(rc)
	results = append(results, portsResult)

	// 8. Check for port conflicts
	portConflictResult := checkPortConflicts(rc)
	results = append(results, portConflictResult)

	// 9. Analyze logs
	logResult := analyzeLogs(rc, config.LogLines)
	results = append(results, logResult)

	// 10. Detailed port binding analysis
	portBindingsResult := checkDetailedPortBindings(rc)
	results = append(results, portBindingsResult)

	// 11. Check cluster state
	clusterResult := checkClusterState(rc)
	results = append(results, clusterResult)

	// 12. Check retry_join targets (if configured)
	if configResult.Success {
		// Extract retry_join from config for validation
		retryJoinAddrs := extractRetryJoinFromConfig(rc)
		if len(retryJoinAddrs) > 0 {
			retryJoinResult := checkRetryJoinTargets(rc, retryJoinAddrs)
			results = append(results, retryJoinResult)
		}
	}

	// 13. Check Vault-Consul connectivity (critical for Vault backend)
	vaultConsulResult := checkVaultConsulConnectivity(rc)
	results = append(results, vaultConsulResult)

	// INTERVENE - Apply fixes if requested
	if config.AutoFix || config.KillProcesses {
		logger.Info("=== INTERVENE PHASE: Applying fixes ===")

		if config.KillProcesses && !processResult.Success {
			killResult := killLingeringProcesses(rc)
			results = append(results, killResult)
		}

		if config.AutoFix {
			// Apply configuration fixes
			if !configResult.Success {
				fixResult := fixConfiguration(rc, configResult)
				results = append(results, fixResult)
			}
		}
	}

	// Test manual start if requested
	if config.TestStart {
		logger.Info("=== TEST PHASE: Testing manual Consul start ===")

		if config.MinimalConfig {
			minimalResult := testMinimalConfiguration(rc)
			results = append(results, minimalResult)
		} else {
			manualResult := testManualStart(rc)
			results = append(results, manualResult)
		}
	}

	// EVALUATE - Display results and recommendations
	logger.Info("=== EVALUATE PHASE: Diagnostic Summary ===")
	displayResults(rc, results)

	// Intelligent exit code based on severity
	// Critical = exit 1 (Consul cannot function)
	// Warning = exit 0 (Consul works but should be addressed)
	// Info = exit 0 (informational only)
	hasCritical := false
	warningCount := 0
	infoCount := 0

	for _, result := range results {
		if !result.Success {
			// Skip test-only checks from severity evaluation
			if result.CheckName == "Manual Start Test" || result.CheckName == "Minimal Configuration Test" {
				continue
			}

			switch result.Severity {
			case SeverityCritical:
				hasCritical = true
			case SeverityWarning:
				warningCount++
			case SeverityInfo:
				infoCount++
			}
		}
	}

	// Exit with appropriate code and message
	if hasCritical {
		logger.Error("Consul debugging found CRITICAL issues - Consul cannot function properly",
			zap.Int("warning_count", warningCount),
			zap.Int("info_count", infoCount))
		return fmt.Errorf("critical issues prevent Consul from functioning - see details above")
	}

	if warningCount > 0 {
		logger.Warn("Consul debugging found warnings - Consul works but issues should be addressed",
			zap.Int("warning_count", warningCount),
			zap.Int("info_count", infoCount))
		// Return nil (exit 0) but warn user
		fmt.Println("\n⚠️  Warnings found - Consul functional but should address issues above")
		return nil
	}

	if infoCount > 0 {
		logger.Info("Consul debugging found informational items only",
			zap.Int("info_count", infoCount))
		fmt.Printf("\nℹ️  %d informational item(s) - no action required\n", infoCount)
	}

	logger.Info("Consul debugging completed successfully - no issues found")
	return nil
}

// displayResults shows a formatted summary of all diagnostic results
// NOTE: Uses fmt.Println for user-facing output (not logger) so output is visible on terminal
func displayResults(rc *eos_io.RuntimeContext, results []DiagnosticResult) {
	logger := otelzap.Ctx(rc.Ctx)

	// Log to structured logs for forensics
	logger.Info("Displaying diagnostic results")

	// Print to stdout for user visibility
	fmt.Println("========================================")
	fmt.Println("CONSUL DEBUG DIAGNOSTIC SUMMARY")
	fmt.Println("========================================")

	for _, result := range results {
		// Use simple text symbols for maximum compatibility
		var status string
		if result.Success {
			status = "[PASS]"
		} else {
			status = "[FAIL]"
		}

		fmt.Printf("%s %s\n", status, result.CheckName)
		fmt.Printf("      %s\n", result.Message)

		if len(result.Details) > 0 {
			for _, detail := range result.Details {
				fmt.Println("      " + detail)
			}
		}

		if result.FixApplied {
			fmt.Printf("      [FIX APPLIED] %s\n", result.FixMessage)
		}

		fmt.Println("") // Blank line between checks
	}

	fmt.Println("========================================")

	// Provide recommendations
	provideRecommendations(rc, results)
}

// provideRecommendations gives actionable advice based on diagnostic results
// NOTE: Uses fmt.Println for user-facing output (not logger) so output is visible on terminal
func provideRecommendations(rc *eos_io.RuntimeContext, results []DiagnosticResult) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Providing recommendations")

	fmt.Println("RECOMMENDATIONS:")

	recommendations := []string{}

	for _, result := range results {
		if !result.Success {
			switch result.CheckName {
			case "Port Conflicts":
				recommendations = append(recommendations,
					"• Stop conflicting services or change Consul ports in configuration")
			case "Lingering Processes":
				recommendations = append(recommendations,
					"• Run 'eos debug consul --kill-processes' to clean up")
			case "Configuration Analysis":
				recommendations = append(recommendations,
					"• Run 'eos update consul --fix' to apply configuration fixes",
					"• Review and adjust /etc/consul.d/consul.hcl manually if needed")
			case "Systemd Service":
				recommendations = append(recommendations,
					"• Regenerate service file with 'sudo rm /etc/systemd/system/consul.service && sudo eos create consul'")
			case "Log Analysis":
				recommendations = append(recommendations,
					"• Check extended logs with 'sudo journalctl -xeu consul.service -n 200'")
			}
		}
	}

	if len(recommendations) == 0 {
		fmt.Println("  ✓ No issues found - Consul should be ready to start")
		fmt.Println("  → Try: sudo systemctl start consul")
	} else {
		for _, rec := range recommendations {
			fmt.Println(rec)
		}
	}
}
