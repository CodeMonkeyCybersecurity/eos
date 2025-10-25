// Package debug provides comprehensive debugging tools for Consul service issues
package debug

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul"
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

// ACLErrorPattern defines a specific ACL-related error pattern for log parsing
type ACLErrorPattern struct {
	Category     string   // Error category (e.g., "ACL_PERMISSION", "ACL_TOKEN_INVALID")
	Description  string   // Human-readable description
	Severity     Severity // How critical this error is
	Remediation  string   // How to fix this issue
	RelatedTerms []string // Related patterns to search for context
}

// ACLLogError represents a detected ACL error from logs
type ACLLogError struct {
	Timestamp   string   // When the error occurred
	Pattern     string   // Which pattern matched
	ErrorInfo   ACLErrorPattern
	LogLine     string   // The actual log line
	Context     []string // Surrounding log lines for context
}

// AssessmentResults holds the raw results of diagnostic assessment
// without any display or evaluation logic.
// Used by fix.go to run diagnostics without terminal output.
type AssessmentResults struct {
	Checks         []DiagnosticResult // All check results
	ConfigIssues   bool               // Whether config analysis failed
	RetryJoinAddrs []string           // Extracted retry_join addresses
}

// RunAssessment performs ONLY the diagnostic checks (ASSESS phase)
// without any display, evaluation, or fixes (INTERVENE/EVALUATE phases).
// This is used by fix.go to gather diagnostic data without user-facing output.
//
// Returns:
//   - AssessmentResults containing all check results and extracted config data
//   - error if assessment could not be performed (nil otherwise)
//
// Note: Unlike RunDiagnostics(), this function:
//   - Does NOT display results to the user
//   - Does NOT apply fixes
//   - Does NOT exit with error codes based on severity
//   - ONLY collects diagnostic data for programmatic use
func RunAssessment(rc *eos_io.RuntimeContext) (*AssessmentResults, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Running diagnostic assessment (data collection only)")

	results := []DiagnosticResult{}

	// CRITICAL: Get authenticated Consul client for checks that need it
	// This handles ACL token discovery from: flag > env > vault > consul-kv > file
	// If ACLs are disabled, returns anonymous client (no error)
	// If ACLs enabled but no token, user gets clear remediation guidance
	consulClient, consulClientErr := consul.GetAuthenticatedConsulClientForDiagnostics(rc, "")

	// ASSESS - Run all diagnostic checks (same as RunDiagnostics)

	// 0. CHECK IF CONSUL IS RUNNING (P0 - MUST BE FIRST!)
	// If this fails, ALL other checks are meaningless
	processResult := checkConsulProcessRunning(rc)
	results = append(results, processResult)

	// If Consul is not running, other checks will produce misleading results
	// (e.g., "ACLs enabled" reads config file but can't verify actual state)
	// Still run them for completeness, but user should fix process first

	// 1. Check Consul binary
	binaryResult := checkConsulBinary(rc)
	results = append(results, binaryResult)

	// 2. Check file permissions
	permissionsResult := checkConsulPermissions(rc)
	results = append(results, permissionsResult)

	// 3. Analyze configuration (now with authenticated client for validation)
	configResult := analyzeConfiguration(rc, consulClient, consulClientErr)
	results = append(results, configResult)

	// 4. Check systemd service
	serviceResult := checkSystemdService(rc)
	results = append(results, serviceResult)

	// 5. Check for lingering processes
	lingeringResult := checkLingeringProcesses(rc)
	results = append(results, lingeringResult)

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
	logResult := analyzeLogs(rc, 100) // Default log lines
	results = append(results, logResult)

	// 10. Detailed port binding analysis
	portBindingsResult := checkDetailedPortBindings(rc)
	results = append(results, portBindingsResult)

	// 11. Check cluster state (requires authenticated client if ACLs enabled)
	clusterResult := checkClusterState(rc, consulClient, consulClientErr)
	results = append(results, clusterResult)

	// 12. Check retry_join targets (if configured)
	var retryJoinAddrs []string
	if configResult.Success {
		retryJoinAddrs = extractRetryJoinFromConfig(rc)
		if len(retryJoinAddrs) > 0 {
			retryJoinResult := checkRetryJoinTargets(rc, retryJoinAddrs)
			results = append(results, retryJoinResult)
		}
	}

	// 13. Check Vault-Consul connectivity (critical for Vault backend)
	vaultConsulResult := checkVaultConsulConnectivity(rc)
	results = append(results, vaultConsulResult)

	// 14. Check ACL system status (security-critical)
	aclResult := checkACLEnabled(rc)
	results = append(results, aclResult)

	// 15. Check ACL authentication (with/without token) - NEW P0 CHECK
	// Tests if ACLs are actually enforced and if tokens work
	aclAuthResult := checkACLAuthentication(rc)
	results = append(results, aclAuthResult)

	// 16. Check agent ACL token configuration - NEW P0 CHECK
	// Verifies agent has token to authenticate internal operations
	agentTokenResult := checkAgentACLToken(rc)
	results = append(results, agentTokenResult)

	// 17. Check data directory configuration (critical for ACL bootstrap, now authenticated)
	dataDirResult := checkDataDirectoryConfiguration(rc, consulClient, consulClientErr)
	results = append(results, dataDirResult)

	// 18. Check data directory filesystem state (verify directory exists and list contents)
	dataDirFSResult := checkDataDirectoryFileSystem(rc)
	results = append(results, dataDirFSResult)

	// 19. Check Raft database location (find active raft.db across filesystem)
	raftDBResult := checkRaftDatabase(rc)
	results = append(results, raftDBResult)

	// 20. Check recent ACL bootstrap activity in logs
	aclBootstrapLogResult := checkRecentACLBootstrapActivity(rc)
	results = append(results, aclBootstrapLogResult)

	// 21. Check Raft ACL bootstrap state (advanced - shows actual reset index, now authenticated)
	raftBootstrapResult := checkRaftBootstrapState(rc, consulClient, consulClientErr)
	results = append(results, raftBootstrapResult)

	// 22. Check Consul service discovery (critical for Vault-Consul integration, now authenticated)
	serviceDiscoveryResult := checkConsulServiceDiscovery(rc, consulClient, consulClientErr)
	results = append(results, serviceDiscoveryResult)

	// 23. Check systemd unit status for Consul and dependencies
	systemdResult := checkSystemdUnitStatus(rc)
	results = append(results, systemdResult)

	logger.Debug("Diagnostic assessment completed",
		zap.Int("total_checks", len(results)),
		zap.Int("retry_join_addrs", len(retryJoinAddrs)))

	return &AssessmentResults{
		Checks:         results,
		ConfigIssues:   !configResult.Success,
		RetryJoinAddrs: retryJoinAddrs,
	}, nil
}

// RunDiagnostics performs comprehensive Consul debugging following Assess → Intervene → Evaluate pattern
func RunDiagnostics(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting Consul debug diagnostics",
		zap.Bool("auto_fix", config.AutoFix),
		zap.Bool("kill_processes", config.KillProcesses),
		zap.Bool("test_start", config.TestStart))

	// ASSESS - Run all diagnostic checks
	logger.Info("=== ASSESS PHASE: Running diagnostic checks ===")

	assessment, err := RunAssessment(rc)
	if err != nil {
		return fmt.Errorf("failed to run diagnostic assessment: %w", err)
	}

	// Start with assessment results
	results := assessment.Checks

	// INTERVENE - Apply fixes if requested
	if config.AutoFix || config.KillProcesses {
		logger.Info("=== INTERVENE PHASE: Applying fixes ===")

		// Find specific check results for conditional fixes
		processResult := FindCheckResult(assessment.Checks, "Lingering Processes")
		configResult := FindCheckResult(assessment.Checks, "Configuration Analysis")

		if config.KillProcesses && processResult != nil && !processResult.Success {
			killResult := killLingeringProcesses(rc)
			results = append(results, killResult)
		}

		if config.AutoFix {
			// Apply configuration fixes
			if configResult != nil && !configResult.Success {
				fixResult := FixConfiguration(rc, *configResult)
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
		logger.Warn("\n⚠️  Warnings found - Consul functional but should address issues above")
		return nil
	}

	if infoCount > 0 {
		logger.Info("Consul debugging found informational items only",
			zap.Int("info_count", infoCount),
			zap.String("message", fmt.Sprintf("ℹ️  %d informational item(s) - no action required", infoCount)))
	}

	logger.Info("Consul debugging completed successfully - no issues found")
	return nil
}

// displayResults shows a formatted summary of all diagnostic results
// NOTE: Uses structured logging (logger.Info/Warn/Error) which goes to BOTH terminal AND telemetry
func displayResults(rc *eos_io.RuntimeContext, results []DiagnosticResult) {
	logger := otelzap.Ctx(rc.Ctx)

	// ========================================================================
	// ROOT CAUSE ANALYSIS - Show root causes FIRST, then detailed results
	// ========================================================================

	rootCauses := AnalyzeResults(results)
	if len(rootCauses) > 0 {
		// Display root cause analysis prominently
		logger.Info("")
		for _, line := range FormatMultipleRootCauses(rootCauses) {
			logger.Info(line)
		}
	}

	// Display results via structured logging (user sees this on terminal + telemetry captures it)
	logger.Info("========================================")
	logger.Info("CONSUL DEBUG DIAGNOSTIC SUMMARY")
	logger.Info("========================================")

	for _, result := range results {
		// Use structured logging for both terminal display AND telemetry
		if result.Success {
			logger.Info("[PASS] "+result.CheckName,
				zap.String("check", result.CheckName),
				zap.String("message", result.Message),
				zap.Strings("details", result.Details),
				zap.Bool("success", true))
			logger.Info("      " + result.Message)
		} else {
			logger.Error("[FAIL] "+result.CheckName,
				zap.String("check", result.CheckName),
				zap.String("message", result.Message),
				zap.Strings("details", result.Details),
				zap.Bool("success", false))
			logger.Error("      " + result.Message)
		}

		if len(result.Details) > 0 {
			for _, detail := range result.Details {
				logger.Info("      " + detail)
			}
		}

		if result.FixApplied {
			logger.Info("      [FIX APPLIED] "+result.FixMessage,
				zap.String("fix_message", result.FixMessage),
				zap.Bool("fix_applied", true))
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
		logger.Info("  ✓ No issues found - Consul should be ready to start")
		logger.Info("  → Try: sudo systemctl start consul")
	} else {
		for _, rec := range recommendations {
			logger.Info(rec)
		}
	}
}

// FindCheckResult searches for a specific check result by name.
// Returns nil if the check was not found.
//
// Example:
//
//	configResult := FindCheckResult(assessment.Checks, "Configuration Analysis")
//	if configResult != nil && !configResult.Success {
//	    // Handle config failure
//	}
func FindCheckResult(checks []DiagnosticResult, checkName string) *DiagnosticResult {
	for i := range checks {
		if checks[i].CheckName == checkName {
			return &checks[i]
		}
	}
	return nil
}

// HasCriticalIssues checks if any diagnostic results have critical severity failures.
// Returns true if at least one check failed with SeverityCritical.
//
// Example:
//
//	if HasCriticalIssues(assessment.Checks) {
//	    return fmt.Errorf("cannot proceed - critical issues detected")
//	}
func HasCriticalIssues(checks []DiagnosticResult) bool {
	for _, check := range checks {
		if !check.Success && check.Severity == SeverityCritical {
			return true
		}
	}
	return false
}

// GetFailedChecks returns all failed diagnostic results grouped by severity.
// Useful for prioritizing fixes and reporting.
//
// Returns:
//   - critical: All failed checks with SeverityCritical
//   - warnings: All failed checks with SeverityWarning
//   - info: All failed checks with SeverityInfo
//
// Example:
//
//	critical, warnings, info := GetFailedChecks(assessment.Checks)
//	if len(critical) > 0 {
//	    logger.Error("Critical issues found", zap.Int("count", len(critical)))
//	}
func GetFailedChecks(checks []DiagnosticResult) (critical, warnings, info []DiagnosticResult) {
	for _, check := range checks {
		if !check.Success {
			switch check.Severity {
			case SeverityCritical:
				critical = append(critical, check)
			case SeverityWarning:
				warnings = append(warnings, check)
			case SeverityInfo:
				info = append(info, check)
			}
		}
	}
	return critical, warnings, info
}
