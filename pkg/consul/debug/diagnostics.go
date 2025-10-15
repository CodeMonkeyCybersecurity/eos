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

// DiagnosticResult holds the results of a diagnostic check
type DiagnosticResult struct {
	CheckName  string
	Success    bool
	Message    string
	Details    []string
	FixApplied bool
	FixMessage string
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

	// Check if any critical issues remain
	hasErrors := false
	for _, result := range results {
		if !result.Success && result.CheckName != "Manual Start Test" {
			hasErrors = true
			break
		}
	}

	if hasErrors {
		logger.Warn("Consul debugging completed with issues found")
		return fmt.Errorf("consul debugging found issues that need attention")
	}

	logger.Info("Consul debugging completed successfully")
	return nil
}

// displayResults shows a formatted summary of all diagnostic results
func displayResults(rc *eos_io.RuntimeContext, results []DiagnosticResult) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("========================================")
	logger.Info("CONSUL DEBUG DIAGNOSTIC SUMMARY")
	logger.Info("========================================")

	for _, result := range results {
		// Use simple text symbols for maximum compatibility
		var status string
		if result.Success {
			status = "[PASS]"
		} else {
			status = "[FAIL]"
		}

		logger.Info(fmt.Sprintf("%s %s", status, result.CheckName))
		logger.Info(fmt.Sprintf("      %s", result.Message))

		if len(result.Details) > 0 {
			for _, detail := range result.Details {
				logger.Info("      " + detail)
			}
		}

		if result.FixApplied {
			logger.Info(fmt.Sprintf("      [FIX APPLIED] %s", result.FixMessage))
		}

		logger.Info("") // Blank line between checks
	}

	logger.Info("========================================")

	// Provide recommendations
	provideRecommendations(rc, results)
}

// provideRecommendations gives actionable advice based on diagnostic results
func provideRecommendations(rc *eos_io.RuntimeContext, results []DiagnosticResult) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("RECOMMENDATIONS:")

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
					"• Run 'eos debug consul --fix' to apply configuration fixes",
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
		logger.Info("  ✓ No issues found - Consul should be ready to start")
		logger.Info("  → Try: sudo systemctl start consul")
	} else {
		for _, rec := range recommendations {
			logger.Info(rec)
		}
	}
}
