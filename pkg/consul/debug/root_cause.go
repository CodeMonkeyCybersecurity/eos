// pkg/consul/debug/root_cause.go
//
// Root Cause Analysis Engine for Consul Diagnostics
//
// Pattern-matches diagnostic results to identify root causes from symptoms.
// Instead of showing a list of 20 failures, show 1-3 root causes that explain everything.
//
// Last Updated: 2025-01-25

package debug

import (
	"fmt"
	"strings"
)

// RootCauseAnalysis represents a diagnosed root cause with symptoms and remediation
type RootCauseAnalysis struct {
	PrimaryIssue  string   // The root cause (e.g., "Consul daemon missing ACL token")
	Confidence    int      // 0-100 confidence level
	Symptoms      []string // Observable symptoms (e.g., "Coordinate update blocked")
	RelatedChecks []string // Which diagnostic checks detected this
	FixComplexity string   // "Simple", "Moderate", "Complex"
	TimeToFix     string   // Estimated time ("1 minute", "10 minutes", etc.)
	FixSteps      []string // Concrete remediation steps
}

// RootCausePattern defines a pattern for detecting root causes
type RootCausePattern struct {
	Name             string   // Pattern name (for debugging)
	Indicators       []string // Required indicators (check names, log patterns, etc.)
	RequiredMatches  int      // How many indicators must match
	ConfidenceWeight int      // Base confidence if pattern matches (0-100)
	Analysis         RootCauseAnalysis
}

// AnalyzeResults performs root cause analysis on diagnostic results.
//
// CRITICAL: This function implements the "Root Cause, Not Symptoms" philosophy.
// Instead of showing users 20 individual test failures, we pattern-match to find
// the 1-3 root causes that explain all the symptoms.
//
// Example:
//
//	Input (symptoms):
//	  [FAIL] API Connectivity
//	  [FAIL] Process Running Check
//	  [FAIL] Systemd Service
//	  [FAIL] Port 8500 Check
//
//	Output (root cause):
//	  PRIMARY ISSUE: Consul is not running
//	  └─ Explains: API connectivity, port check, systemd state
//	  Fix: systemctl start consul (Simple, 1 minute)
//
// Parameters:
//   - results: Diagnostic check results to analyze
//
// Returns:
//   - []RootCauseAnalysis: Ranked list of likely root causes (highest confidence first)
func AnalyzeResults(results []DiagnosticResult) []RootCauseAnalysis {
	// Define root cause patterns
	patterns := []RootCausePattern{
		// Pattern 1: Consul daemon missing ACL token
		{
			Name: "consul-daemon-no-acl-token",
			Indicators: []string{
				"log:Coordinate update blocked by ACLs",
				"api:403",
				"config:tokens.agent=empty",
			},
			RequiredMatches:  2,
			ConfidenceWeight: 95,
			Analysis: RootCauseAnalysis{
				PrimaryIssue: "Consul daemon has no ACL token configured",
				Symptoms: []string{
					"'Coordinate update blocked by ACLs' errors in logs",
					"API returns 403 Forbidden for authenticated requests",
					"No agent token in configuration",
				},
				FixComplexity: "Simple",
				TimeToFix:     "2 minutes",
				FixSteps: []string{
					"Get bootstrap token: export CONSUL_HTTP_TOKEN=$(eos read consul-token --export | cut -d'=' -f2 | tr -d '\"')",
					"Create agent token: consul acl token create -description='Agent token' -node-identity=\"$(hostname):dc1\"",
					"Configure daemon: consul acl set-agent-token agent <token-from-previous-step>",
					"Or use Eos: eos update consul --bootstrap-token (automatically creates agent token)",
				},
			},
		},

		// Pattern 2: Consul not running
		{
			Name: "consul-not-running",
			Indicators: []string{
				"check:Process Running:FAIL",
				"check:API Connectivity:FAIL",
				"check:Port 8500:FAIL",
				"systemd:inactive",
			},
			RequiredMatches:  2,
			ConfidenceWeight: 99,
			Analysis: RootCauseAnalysis{
				PrimaryIssue: "Consul service is not running",
				Symptoms: []string{
					"No Consul process found",
					"Cannot connect to API on port 8500",
					"Systemd shows service as inactive or failed",
				},
				FixComplexity: "Simple",
				TimeToFix:     "1 minute",
				FixSteps: []string{
					"Start Consul: systemctl start consul",
					"Check status: systemctl status consul",
					"If fails, check logs: journalctl -u consul -n 50",
					"If persistent failure: eos debug consul --fix",
				},
			},
		},

		// Pattern 3: Data directory mismatch
		{
			Name: "data-dir-mismatch",
			Indicators: []string{
				"check:Data Directory:WARN",
				"check:Raft Database:WARN",
				"config:data_dir!=actual",
			},
			RequiredMatches:  2,
			ConfidenceWeight: 85,
			Analysis: RootCauseAnalysis{
				PrimaryIssue: "Consul data directory configured path doesn't match actual location",
				Symptoms: []string{
					"Config file specifies different path than where raft.db exists",
					"ACL reset file written to wrong location",
					"Multiple raft.db files found on filesystem",
				},
				FixComplexity: "Moderate",
				TimeToFix:     "5 minutes",
				FixSteps: []string{
					"Find actual data dir: eos debug raft --show-datadir",
					"Update config: Edit /etc/consul.d/consul.hcl, set data_dir = \"<actual-path>\"",
					"Restart Consul: systemctl restart consul",
					"Verify: eos debug consul",
				},
			},
		},

		// Pattern 4: ACLs not bootstrapped yet
		{
			Name: "acls-not-bootstrapped",
			Indicators: []string{
				"acl:bootstrap:not-done",
				"check:ACL System:INFO",
				"api:no-token-required",
			},
			RequiredMatches:  1,
			ConfidenceWeight: 90,
			Analysis: RootCauseAnalysis{
				PrimaryIssue: "Consul ACL system not bootstrapped (never initialized)",
				Symptoms: []string{
					"ACL system enabled in config but no bootstrap token exists",
					"API accessible without token (ACLs not enforced)",
					"No token in Vault at secret/consul/bootstrap-token",
				},
				FixComplexity: "Simple",
				TimeToFix:     "1 minute",
				FixSteps: []string{
					"Bootstrap ACLs: eos update consul --bootstrap-token",
					"This will:",
					"  - Create bootstrap token with global-management policy",
					"  - Store token in Vault at secret/consul/bootstrap-token",
					"  - Create and configure agent token for Consul daemon",
					"Configure environment: eval $(eos read consul-token --export)",
				},
			},
		},

		// Pattern 5: Bootstrap token lost (needs reset)
		{
			Name: "bootstrap-token-lost",
			Indicators: []string{
				"acl:bootstrap:already-done",
				"vault:token-missing",
				"api:403",
			},
			RequiredMatches:  2,
			ConfidenceWeight: 92,
			Analysis: RootCauseAnalysis{
				PrimaryIssue: "Consul ACL bootstrap token lost (not in Vault)",
				Symptoms: []string{
					"ACLs are bootstrapped but token not in Vault",
					"API requires token but we don't have it",
					"Cannot create new tokens without bootstrap token",
				},
				FixComplexity: "Simple",
				TimeToFix:     "2 minutes",
				FixSteps: []string{
					"Reset ACL bootstrap: eos update consul --bootstrap-token",
					"This will:",
					"  - Detect current reset index from Consul",
					"  - Write reset file to Consul data directory",
					"  - Re-bootstrap ACL system (generates new token)",
					"  - Store new token in Vault",
					"  - Create agent token for daemon",
					"No data loss - cluster data is preserved",
				},
			},
		},

		// Pattern 6: Port conflict
		{
			Name: "port-conflict",
			Indicators: []string{
				"check:Port Binding:FAIL",
				"log:bind: address already in use",
				"check:Process Running:PASS",
			},
			RequiredMatches:  2,
			ConfidenceWeight: 88,
			Analysis: RootCauseAnalysis{
				PrimaryIssue: "Port conflict - another process using Consul's port",
				Symptoms: []string{
					"Consul process exists but port not bound",
					"Logs show 'bind: address already in use'",
					"Another service using port 8500/8600",
				},
				FixComplexity: "Moderate",
				TimeToFix:     "5 minutes",
				FixSteps: []string{
					"Find conflicting process: lsof -i :8500",
					"Option 1 - Stop conflicting service: systemctl stop <service>",
					"Option 2 - Change Consul port: eos update consul --ports 8500 -> 8161",
					"Restart Consul: systemctl restart consul",
				},
			},
		},
	}

	// Match patterns against results
	detectedCauses := []RootCauseAnalysis{}

	for _, pattern := range patterns {
		matchCount := 0
		matchedIndicators := []string{}

		for _, indicator := range pattern.Indicators {
			if indicatorMatches(indicator, results) {
				matchCount++
				matchedIndicators = append(matchedIndicators, indicator)
			}
		}

		// Check if pattern matches (enough indicators present)
		if matchCount >= pattern.RequiredMatches {
			analysis := pattern.Analysis

			// Calculate confidence based on match percentage
			matchPercentage := (matchCount * 100) / len(pattern.Indicators)
			analysis.Confidence = (pattern.ConfidenceWeight + matchPercentage) / 2

			// Add which checks detected this
			analysis.RelatedChecks = matchedIndicators

			detectedCauses = append(detectedCauses, analysis)
		}
	}

	// Sort by confidence (highest first)
	sortByConfidence(detectedCauses)

	return detectedCauses
}

// indicatorMatches checks if an indicator is present in diagnostic results
func indicatorMatches(indicator string, results []DiagnosticResult) bool {
	parts := strings.SplitN(indicator, ":", 2)
	if len(parts) != 2 {
		return false
	}

	indicatorType := parts[0]
	indicatorValue := parts[1]

	switch indicatorType {
	case "log":
		// Check if log pattern appears in any check's details
		for _, result := range results {
			for _, detail := range result.Details {
				if strings.Contains(strings.ToLower(detail), strings.ToLower(indicatorValue)) {
					return true
				}
			}
		}

	case "api":
		// Check if API error (like 403) appears
		for _, result := range results {
			if strings.Contains(result.CheckName, "API") && !result.Success {
				for _, detail := range result.Details {
					if strings.Contains(detail, indicatorValue) {
						return true
					}
				}
			}
		}

	case "check":
		// Check if a specific check failed
		// Format: "check:CheckName:FAIL" or "check:CheckName:PASS"
		checkParts := strings.SplitN(indicatorValue, ":", 2)
		if len(checkParts) != 2 {
			return false
		}
		checkName := checkParts[0]
		expectedStatus := checkParts[1] // "FAIL", "PASS", "WARN"

		for _, result := range results {
			if strings.Contains(result.CheckName, checkName) {
				switch expectedStatus {
				case "FAIL":
					return !result.Success && result.Severity == SeverityCritical
				case "WARN":
					return !result.Success && result.Severity == SeverityWarning
				case "PASS":
					return result.Success
				}
			}
		}

	case "config":
		// Check configuration-related indicators
		for _, result := range results {
			if strings.Contains(strings.ToLower(result.CheckName), "config") {
				for _, detail := range result.Details {
					if strings.Contains(strings.ToLower(detail), strings.ToLower(indicatorValue)) {
						return true
					}
				}
			}
		}

	case "systemd":
		// Check systemd state
		for _, result := range results {
			if strings.Contains(result.CheckName, "Systemd") {
				for _, detail := range result.Details {
					if strings.Contains(strings.ToLower(detail), strings.ToLower(indicatorValue)) {
						return true
					}
				}
			}
		}

	case "acl":
		// Check ACL-related states
		for _, result := range results {
			if strings.Contains(strings.ToLower(result.CheckName), "acl") {
				detailStr := strings.Join(result.Details, " ")
				if strings.Contains(strings.ToLower(detailStr), strings.ToLower(indicatorValue)) {
					return true
				}
			}
		}

	case "vault":
		// Check Vault-related states
		for _, result := range results {
			if strings.Contains(strings.ToLower(result.CheckName), "vault") {
				detailStr := strings.Join(result.Details, " ")
				if strings.Contains(strings.ToLower(detailStr), strings.ToLower(indicatorValue)) {
					return true
				}
			}
		}
	}

	return false
}

// sortByConfidence sorts root cause analyses by confidence (highest first)
func sortByConfidence(causes []RootCauseAnalysis) {
	// Simple bubble sort (fine for small lists)
	n := len(causes)
	for i := 0; i < n-1; i++ {
		for j := 0; j < n-i-1; j++ {
			if causes[j].Confidence < causes[j+1].Confidence {
				causes[j], causes[j+1] = causes[j+1], causes[j]
			}
		}
	}
}

// FormatRootCauseAnalysis formats root cause analysis for display
func FormatRootCauseAnalysis(analysis RootCauseAnalysis) []string {
	lines := []string{}

	// Header
	lines = append(lines, "╔════════════════════════════════════════════════════════════════════════════╗")
	lines = append(lines, "║ ROOT CAUSE DETECTED                                                        ║")
	lines = append(lines, "╚════════════════════════════════════════════════════════════════════════════╝")
	lines = append(lines, "")

	// Primary issue
	lines = append(lines, fmt.Sprintf("PRIMARY ISSUE: %s", analysis.PrimaryIssue))
	lines = append(lines, fmt.Sprintf("Confidence: %d%%  |  Fix Complexity: %s  |  Estimated Time: %s",
		analysis.Confidence, analysis.FixComplexity, analysis.TimeToFix))
	lines = append(lines, "")

	// Symptoms
	lines = append(lines, "SYMPTOMS:")
	for _, symptom := range analysis.Symptoms {
		lines = append(lines, fmt.Sprintf("  ├─ %s", symptom))
	}
	lines = append(lines, "")

	// Fix steps
	lines = append(lines, "REMEDIATION STEPS:")
	for i, step := range analysis.FixSteps {
		if i == len(analysis.FixSteps)-1 {
			lines = append(lines, fmt.Sprintf("  └─ %d. %s", i+1, step))
		} else {
			lines = append(lines, fmt.Sprintf("  ├─ %d. %s", i+1, step))
		}
	}
	lines = append(lines, "")

	return lines
}

// FormatMultipleRootCauses formats multiple root causes for display
func FormatMultipleRootCauses(causes []RootCauseAnalysis) []string {
	lines := []string{}

	if len(causes) == 0 {
		return lines
	}

	lines = append(lines, "")
	lines = append(lines, "╔════════════════════════════════════════════════════════════════════════════╗")
	lines = append(lines, fmt.Sprintf("║ ROOT CAUSE ANALYSIS (%d issues detected)                                   ║", len(causes)))
	lines = append(lines, "╚════════════════════════════════════════════════════════════════════════════╝")
	lines = append(lines, "")

	for i, analysis := range causes {
		lines = append(lines, fmt.Sprintf("═══ ROOT CAUSE #%d (Confidence: %d%%) ═══",
			i+1, analysis.Confidence))
		lines = append(lines, "")
		lines = append(lines, fmt.Sprintf("PRIMARY ISSUE: %s", analysis.PrimaryIssue))
		lines = append(lines, fmt.Sprintf("Fix Complexity: %s  |  Estimated Time: %s",
			analysis.FixComplexity, analysis.TimeToFix))
		lines = append(lines, "")

		lines = append(lines, "SYMPTOMS:")
		for _, symptom := range analysis.Symptoms {
			lines = append(lines, fmt.Sprintf("  • %s", symptom))
		}
		lines = append(lines, "")

		lines = append(lines, "REMEDIATION:")
		for _, step := range analysis.FixSteps {
			lines = append(lines, fmt.Sprintf("  %s", step))
		}
		lines = append(lines, "")

		if i < len(causes)-1 {
			lines = append(lines, "────────────────────────────────────────────────────────────────────────────")
			lines = append(lines, "")
		}
	}

	return lines
}
