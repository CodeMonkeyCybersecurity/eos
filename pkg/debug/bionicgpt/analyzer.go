// pkg/debug/bionicgpt/analyzer.go
// BionicGPT-specific analysis rules and insights

package bionicgpt

import (
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/debug"
)

// BionicGPTAnalysisRules returns BionicGPT-specific analysis rules
func BionicGPTAnalysisRules() []debug.AnalysisRule {
	return []debug.AnalysisRule{
		DetectNoContainersRunning,
		DetectPostgresIssues,
		DetectMissingVolumes,
		DetectPortConflict,
		DetectLogErrors,
		DetectOllamaIssues,
		DetectResourceExhaustion,
	}
}

// DetectNoContainersRunning checks if no containers are running
func DetectNoContainersRunning(report *debug.Report, analysis *debug.Analysis) {
	for _, result := range report.Results {
		if result.Name == "Container Status" && result.Status == debug.StatusError {
			if strings.Contains(result.Message, "No containers running") {
				analysis.CriticalIssues = append(analysis.CriticalIssues, debug.Issue{
					Severity:    "critical",
					Component:   "Docker Containers",
					Description: "BionicGPT containers are not running",
					Impact:      "Service is completely offline",
					Remediation: "Start containers: cd /opt/bionicgpt && sudo docker compose up -d",
				})
				analysis.Recommendations = append(analysis.Recommendations,
					"After starting containers, wait 2-3 minutes for initialization")
			}
		}
	}
}

// DetectPostgresIssues checks for PostgreSQL problems
func DetectPostgresIssues(report *debug.Report, analysis *debug.Analysis) {
	postgresRunning := false
	postgresHealthy := false

	for _, result := range report.Results {
		if result.Name == "PostgreSQL Database" && result.Status == debug.StatusOK {
			postgresRunning = true
		}
		if result.Name == "PostgreSQL Health" && result.Status == debug.StatusOK {
			postgresHealthy = true
		}
	}

	if postgresRunning && !postgresHealthy {
		analysis.MajorIssues = append(analysis.MajorIssues, debug.Issue{
			Severity:    "major",
			Component:   "PostgreSQL",
			Description: "PostgreSQL container is running but not accepting connections",
			Impact:      "Database unavailable, application cannot start",
			Remediation: "Check PostgreSQL logs: docker logs bionicgpt-postgres",
		})
		analysis.Recommendations = append(analysis.Recommendations,
			"PostgreSQL may still be initializing - wait 30-60 seconds and check again")
	} else if !postgresRunning {
		analysis.CriticalIssues = append(analysis.CriticalIssues, debug.Issue{
			Severity:    "critical",
			Component:   "PostgreSQL",
			Description: "PostgreSQL container is not running",
			Impact:      "Database unavailable, all services will fail",
			Remediation: "Start PostgreSQL: cd /opt/bionicgpt && sudo docker compose up -d postgres",
		})
	}
}

// DetectMissingVolumes checks for missing data volumes
func DetectMissingVolumes(report *debug.Report, analysis *debug.Analysis) {
	for _, result := range report.Results {
		if result.Name == "Docker Volumes" && result.Status == debug.StatusWarning {
			if missingVols, ok := result.Metadata["missing_volumes"].([]string); ok {
				if len(missingVols) > 0 {
					analysis.Warnings = append(analysis.Warnings, debug.Warning{
						Message:        fmt.Sprintf("Missing Docker volumes: %v", missingVols),
						Recommendation: "Volumes will be auto-created, but may indicate incomplete installation",
					})
					analysis.Recommendations = append(analysis.Recommendations,
						"If data loss occurred, restore from backup or reinstall")
				}
			}
		}
	}
}

// DetectPortConflict checks for port binding issues
func DetectPortConflict(report *debug.Report, analysis *debug.Analysis) {
	for _, result := range report.Results {
		if result.Name == "Port Binding" && result.Status == debug.StatusWarning {
			port := result.Metadata["port"]
			analysis.MajorIssues = append(analysis.MajorIssues, debug.Issue{
				Severity:    "major",
				Component:   "Network",
				Description: fmt.Sprintf("Port %v is not bound", port),
				Impact:      "Web interface is not accessible",
				Remediation: "Check if BionicGPT app container is running and check for port conflicts",
			})
			analysis.Recommendations = append(analysis.Recommendations,
				fmt.Sprintf("Check what's using port %v: sudo ss -tlnp | grep %v", port, port))
		}
	}
}

// DetectLogErrors checks for errors in container logs
func DetectLogErrors(report *debug.Report, analysis *debug.Analysis) {
	for _, result := range report.Results {
		if result.Name == "Log Health Check" && result.Status == debug.StatusWarning {
			if errorCount, ok := result.Metadata["error_count"].(int); ok {
				if errorCount > 0 {
					analysis.MinorIssues = append(analysis.MinorIssues, debug.Issue{
						Severity:    "minor",
						Component:   "Application Logs",
						Description: fmt.Sprintf("Found %d errors in recent logs", errorCount),
						Impact:      "May indicate ongoing issues or failed operations",
						Remediation: "Review logs: docker compose -f /opt/bionicgpt/docker-compose.yml logs --tail=100",
					})

					// Look for specific error patterns
					if strings.Contains(result.Output, "connection refused") {
						analysis.Recommendations = append(analysis.Recommendations,
							"Connection errors detected - check if all dependent services are running")
					}
					if strings.Contains(result.Output, "Azure") || strings.Contains(result.Output, "OpenAI") {
						analysis.Recommendations = append(analysis.Recommendations,
							"Azure OpenAI errors detected - verify credentials in .env file")
					}
				}
			}
		}
	}
}

// DetectOllamaIssues checks for Ollama connectivity problems
func DetectOllamaIssues(report *debug.Report, analysis *debug.Analysis) {
	for _, result := range report.Results {
		if result.Name == "Ollama Connectivity" && result.Status == debug.StatusWarning {
			analysis.Warnings = append(analysis.Warnings, debug.Warning{
				Message:        "Ollama service not running (required for local embeddings)",
				Recommendation: "Install/start Ollama: sudo eos create ollama OR sudo systemctl start ollama",
			})
			analysis.Recommendations = append(analysis.Recommendations,
				"If using Azure OpenAI for embeddings, you can ignore this warning")
		}
	}
}

// DetectResourceExhaustion checks for resource usage issues
func DetectResourceExhaustion(report *debug.Report, analysis *debug.Analysis) {
	for _, result := range report.Results {
		if result.Name == "Resource Usage" && result.Status == debug.StatusOK {
			// Parse output for high memory/CPU usage
			if strings.Contains(result.Output, "GiB") {
				lines := strings.Split(result.Output, "\n")
				for _, line := range lines {
					// Check for memory usage > 90%
					if strings.Contains(line, "bionicgpt") {
						// Simple heuristic - detailed parsing would require structured output
						if strings.Contains(line, "9.") && strings.Contains(line, "GiB") {
							analysis.Warnings = append(analysis.Warnings, debug.Warning{
								Message:        "High memory usage detected in BionicGPT containers",
								Recommendation: "Monitor resource usage and consider increasing available RAM",
							})
							break
						}
					}
				}
			}
		}
	}
}

// GenerateNextSteps generates recommended next steps based on diagnostics
func GenerateNextSteps(report *debug.Report, analysis *debug.Analysis) []string {
	steps := []string{}

	// Critical issues first
	if len(analysis.CriticalIssues) > 0 {
		steps = append(steps, "CRITICAL: Address critical issues immediately:")
		for _, issue := range analysis.CriticalIssues {
			steps = append(steps, fmt.Sprintf("  - %s: %s", issue.Component, issue.Remediation))
		}
	}

	// Major issues
	if len(analysis.MajorIssues) > 0 {
		steps = append(steps, "MAJOR: Fix these issues to restore functionality:")
		for _, issue := range analysis.MajorIssues {
			steps = append(steps, fmt.Sprintf("  - %s: %s", issue.Component, issue.Remediation))
		}
	}

	// If everything is OK
	if len(analysis.CriticalIssues) == 0 && len(analysis.MajorIssues) == 0 {
		steps = append(steps, "✓ BionicGPT appears healthy. Verify by accessing web interface:")
		steps = append(steps, fmt.Sprintf("  - Open browser: http://localhost:%d", DefaultPort))
		steps = append(steps, "  - Or remote: http://<server-ip>:"+fmt.Sprintf("%d", DefaultPort))
	}

	// General recommendations
	if len(analysis.Recommendations) > 0 {
		steps = append(steps, "")
		steps = append(steps, "Additional recommendations:")
		for _, rec := range analysis.Recommendations {
			steps = append(steps, "  - "+rec)
		}
	}

	// Common troubleshooting steps
	steps = append(steps, "")
	steps = append(steps, "Common troubleshooting commands:")
	steps = append(steps, "  - View all logs: docker compose -f /opt/bionicgpt/docker-compose.yml logs")
	steps = append(steps, "  - Restart services: cd /opt/bionicgpt && sudo docker compose restart")
	steps = append(steps, "  - Check service status: docker compose -f /opt/bionicgpt/docker-compose.yml ps")
	steps = append(steps, "  - Reinitialize: sudo eos delete bionicgpt && sudo eos create bionicgpt")

	return steps
}

// GenerateExecutiveSummary creates a concise summary of BionicGPT deployment status
// This appears at the TOP of diagnostic output for immediate root cause visibility
func GenerateExecutiveSummary(report *debug.Report, analysis *debug.Analysis) string {
	var summary strings.Builder

	// Loose End 1 fix: Add timestamp to show when diagnostic was run
	timestamp := time.Now().UTC().Format("2006-01-02 15:04:05 UTC")
	summary.WriteString(strings.Repeat("═", 80) + "\n")
	summary.WriteString(fmt.Sprintf("BIONICGPT DEPLOYMENT STATUS (%s)\n", timestamp))
	summary.WriteString(strings.Repeat("═", 80) + "\n\n")

	// Handle empty or nil report (Bug 6 fix)
	if report == nil || len(report.Results) == 0 {
		summary.WriteString("STATUS: UNKNOWN\n\n")
		summary.WriteString("No diagnostic data available.\n\n")
		summary.WriteString("This may indicate:\n")
		summary.WriteString("  • Diagnostics collection failed\n")
		summary.WriteString("  • BionicGPT not installed\n")
		summary.WriteString("  • Permission issues (try: sudo eos debug bionicgpt)\n\n")
		summary.WriteString("IMMEDIATE ACTION:\n")
		summary.WriteString("  1. Check if BionicGPT is installed: ls -la /opt/bionicgpt\n")
		summary.WriteString("  2. Check Docker is running: docker ps\n")
		summary.WriteString("  3. Re-run with sudo: sudo eos debug bionicgpt\n\n")
		return summary.String()
	}

	// Collect status information from diagnostics
	rootCauses := []string{}
	blockingIssues := []string{}
	primaryFailures := []string{}

	// Analyze diagnostic results
	for _, result := range report.Results {
		// Container dependency blocking (critical)
		if result.Name == "Container Dependency Blocked" && result.Status == debug.StatusError {
			if blockedCount, ok := result.Metadata["blocked_count"].(int); ok && blockedCount > 0 {
				if blocked, ok := result.Metadata["blocked_containers"].([]string); ok {
					for _, container := range blocked {
						blockingIssues = append(blockingIssues, fmt.Sprintf("├─ %s: Created (never started)", container))
					}
				}
			}
		}

		// LiteLLM health issues (root cause)
		if result.Name == "LiteLLM Proxy Health" && result.Status != debug.StatusOK {
			rootCauses = append(rootCauses, "LiteLLM proxy health check failing")
		}

		// PostgreSQL health issues (root cause) - Loose End 2 fix
		if result.Name == "PostgreSQL Health" && result.Status == debug.StatusError {
			rootCauses = append(rootCauses, "PostgreSQL database not responding")
		}

		// LiteLLM endpoint failures (primary failure)
		if result.Name == "LiteLLM Comprehensive Health" {
			// Bug 20 fix: Safe type assertion to prevent panic if metadata format unexpected
			if endpoint, ok := result.Metadata["health_endpoint"].(string); ok && endpoint == "failed" {
				primaryFailures = append(primaryFailures, "├─ /health endpoint: FAILED")
			}
			if endpoint, ok := result.Metadata["liveliness_endpoint"].(string); ok && endpoint == "failed" {
				primaryFailures = append(primaryFailures, "├─ /health/liveliness endpoint: FAILED")
			}
		}

		// Model connectivity (primary failure)
		if result.Name == "LiteLLM Model Connectivity" {
			if unhealthy, ok := result.Metadata["unhealthy_models"].(int); ok && unhealthy > 0 {
				if total, ok := result.Metadata["configured_models"].([]string); ok {
					healthy := len(total) - unhealthy
					// Bug 21 fix: Defensive bounds check (shouldn't happen but prevents negative counts)
					if healthy < 0 {
						healthy = 0
					}
					primaryFailures = append(primaryFailures, fmt.Sprintf("├─ Models reachable: %d/%d", healthy, len(total)))
				}
			}
		}

		// NOTE: Removed duplicate "App Container Running Check" detection (Bug 5 fix)
		// This is already covered by "Container Dependency Blocked" diagnostic above
	}

	// Calculate accessible status (Bug 1 fix - based on ALL conditions, not just one flag)
	accessible := len(rootCauses) == 0 && len(blockingIssues) == 0 && len(primaryFailures) == 0

	// Generate status line (Bug 9 fix - check warnings for DEGRADED status)
	if accessible {
		if analysis != nil && len(analysis.Warnings) > 0 {
			summary.WriteString("STATUS: DEGRADED\n\n")
			summary.WriteString(fmt.Sprintf("Services running with %d warnings. Review diagnostics below.\n", len(analysis.Warnings)))
		} else {
			summary.WriteString("STATUS: ACCESSIBLE\n\n")
			summary.WriteString("All services are running and healthy.\n")
		}
	} else {
		summary.WriteString("STATUS: NOT ACCESSIBLE\n\n")

		if len(rootCauses) > 0 {
			summary.WriteString("ROOT CAUSE:\n")
			for _, cause := range rootCauses {
				summary.WriteString(fmt.Sprintf("  • %s\n", cause))
			}
			summary.WriteString("\n")
		}

		if len(blockingIssues) > 0 {
			summary.WriteString("BLOCKING ISSUES:\n")
			for _, issue := range blockingIssues {
				summary.WriteString(fmt.Sprintf("  %s\n", issue))
			}
			summary.WriteString("\n")
		}

		if len(primaryFailures) > 0 {
			summary.WriteString("PRIMARY FAILURES:\n")
			for _, failure := range primaryFailures {
				summary.WriteString(fmt.Sprintf("  %s\n", failure))
			}
			summary.WriteString("\n")
		}

		// Immediate action - Bug 4 & 8 fix: check ALL root causes independently
		summary.WriteString("IMMEDIATE ACTION REQUIRED:\n\n")

		// Check if any root cause is LiteLLM-related or PostgreSQL-related
		hasLiteLLMIssue := false
		hasPostgresIssue := false
		for _, cause := range rootCauses {
			if strings.Contains(cause, "LiteLLM") {
				hasLiteLLMIssue = true
			}
			if strings.Contains(cause, "PostgreSQL") {
				hasPostgresIssue = true
			}
		}

		// Bug 8 fix: Use independent if blocks, not else if (so BOTH issues show)
		if hasLiteLLMIssue {
			summary.WriteString("LiteLLM Issues:\n")
			summary.WriteString("  1. Check LiteLLM logs for errors:\n")
			summary.WriteString("     docker logs bionicgpt-litellm --tail 50 | grep -i error\n\n")
			summary.WriteString("  2. Verify Azure OpenAI credentials:\n")
			summary.WriteString("     sudo cat /opt/bionicgpt/.env.litellm | grep AZURE_OPENAI_API_KEY\n")
			summary.WriteString("     To update: sudo nano /opt/bionicgpt/.env.litellm\n\n")
			summary.WriteString("  3. Test LiteLLM health manually:\n")
			// NOTE: Port 4000 is LiteLLM default (from bionicgpt.DefaultLiteLLMPort)
			// Hardcoded here to avoid circular import (analyzer → bionicgpt → analyzer)
			summary.WriteString("     docker exec bionicgpt-litellm python -c \"import urllib.request; print(urllib.request.urlopen('http://localhost:4000/health').read().decode())\"\n\n")
			summary.WriteString("  4. Check Azure Portal: Verify deployment names match config\n")
			summary.WriteString("     https://portal.azure.com -> Azure OpenAI -> Deployments\n\n")
			// Bug 15 fix: Add restart instructions
			summary.WriteString("  5. After fixing credentials, restart LiteLLM:\n")
			summary.WriteString("     cd /opt/bionicgpt && docker compose restart litellm-proxy\n\n")
		}

		if hasPostgresIssue {
			summary.WriteString("PostgreSQL Issues:\n")
			summary.WriteString("  1. Check PostgreSQL container status:\n")
			summary.WriteString("     docker ps -a --filter name=bionicgpt-postgres\n\n")
			summary.WriteString("  2. Check PostgreSQL logs:\n")
			summary.WriteString("     docker logs bionicgpt-postgres --tail 50\n\n")
			summary.WriteString("  3. Test PostgreSQL connection:\n")
			summary.WriteString("     docker exec bionicgpt-postgres pg_isready -U postgres\n\n")
			// Bug 15 fix: Add restart instructions
			summary.WriteString("  4. If database is corrupted, restart PostgreSQL:\n")
			summary.WriteString("     cd /opt/bionicgpt && docker compose restart postgres\n\n")
		}

		// Show generic steps only if no specific root cause identified
		if !hasLiteLLMIssue && !hasPostgresIssue {
			if len(blockingIssues) > 0 {
				summary.WriteString("Container Issues:\n")
				summary.WriteString("  1. Start containers:\n")
				summary.WriteString("     cd /opt/bionicgpt && sudo docker compose up -d\n\n")
				summary.WriteString("  2. Check container logs:\n")
				summary.WriteString("     docker compose logs --tail 50\n")
			} else {
				summary.WriteString("General Troubleshooting:\n")
				summary.WriteString("  1. Review detailed diagnostics below\n")
				summary.WriteString("  2. Check container logs: docker compose -f /opt/bionicgpt/docker-compose.yml logs\n")
			}
		}
	}

	summary.WriteString("\n" + strings.Repeat("═", 80) + "\n")
	summary.WriteString("DETAILED DIAGNOSTICS\n")
	summary.WriteString(strings.Repeat("═", 80) + "\n\n")

	return summary.String()
}
