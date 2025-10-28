// pkg/debug/bionicgpt/analyzer.go
// BionicGPT-specific analysis rules and insights

package bionicgpt

import (
	"fmt"
	"strings"

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

	summary.WriteString(strings.Repeat("═", 80) + "\n")
	summary.WriteString("BIONICGPT DEPLOYMENT STATUS\n")
	summary.WriteString(strings.Repeat("═", 80) + "\n\n")

	// Overall status
	accessible := true
	rootCauses := []string{}
	blockingIssues := []string{}
	primaryFailures := []string{}

	// Check if accessible
	for _, result := range report.Results {
		if result.Name == "Container Dependency Blocked" && result.Status == debug.StatusError {
			accessible = false
			if blockedCount, ok := result.Metadata["blocked_count"].(int); ok && blockedCount > 0 {
				if blocked, ok := result.Metadata["blocked_containers"].([]string); ok {
					for _, container := range blocked {
						blockingIssues = append(blockingIssues, fmt.Sprintf("├─ %s: Created (never started)", container))
					}
				}
			}
		}

		if result.Name == "LiteLLM Proxy Health" && result.Status != debug.StatusOK {
			rootCauses = append(rootCauses, "LiteLLM proxy health check failing")
		}

		if result.Name == "LiteLLM Comprehensive Health" {
			if result.Metadata["health_endpoint"] == "failed" {
				primaryFailures = append(primaryFailures, "├─ /health endpoint: FAILED")
			}
			if result.Metadata["liveliness_endpoint"] == "failed" {
				primaryFailures = append(primaryFailures, "├─ /health/liveliness endpoint: FAILED")
			}
		}

		if result.Name == "LiteLLM Model Connectivity" {
			if unhealthy, ok := result.Metadata["unhealthy_models"].(int); ok && unhealthy > 0 {
				if total, ok := result.Metadata["configured_models"].([]string); ok {
					healthy := len(total) - unhealthy
					primaryFailures = append(primaryFailures, fmt.Sprintf("├─ Models reachable: %d/%d", healthy, len(total)))
				}
			}
		}

		if result.Name == "App Container Running Check" && result.Status == debug.StatusError {
			blockingIssues = append(blockingIssues, "├─ bionicgpt-app: Not running")
		}
	}

	// Status line
	if accessible && len(rootCauses) == 0 && len(blockingIssues) == 0 {
		summary.WriteString("STATUS: ✅ ACCESSIBLE\n\n")
		summary.WriteString("All services are running and healthy.\n")
	} else {
		summary.WriteString("STATUS: ❌ NOT ACCESSIBLE\n\n")

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

		// Immediate action
		summary.WriteString("IMMEDIATE ACTION REQUIRED:\n")
		if len(rootCauses) > 0 && strings.Contains(rootCauses[0], "LiteLLM") {
			summary.WriteString("  1. Check LiteLLM logs for errors:\n")
			summary.WriteString("     docker logs bionicgpt-litellm --tail 50 | grep -i error\n\n")
			summary.WriteString("  2. Verify Azure OpenAI credentials:\n")
			summary.WriteString("     sudo cat /opt/bionicgpt/.env.litellm | grep AZURE_OPENAI_API_KEY\n\n")
			summary.WriteString("  3. Test LiteLLM health manually:\n")
			summary.WriteString("     docker exec bionicgpt-litellm python -c \"import urllib.request; print(urllib.request.urlopen('http://localhost:4000/health').read().decode())\"\n\n")
			summary.WriteString("  4. Check Azure Portal: Verify deployment names match config\n")
			summary.WriteString("     https://portal.azure.com → Azure OpenAI → Deployments\n")
		} else if len(blockingIssues) > 0 {
			summary.WriteString("  1. Start containers:\n")
			summary.WriteString("     cd /opt/bionicgpt && sudo docker compose up -d\n\n")
			summary.WriteString("  2. Check container logs:\n")
			summary.WriteString("     docker compose logs --tail 50\n")
		} else {
			summary.WriteString("  1. Review detailed diagnostics below\n")
			summary.WriteString("  2. Check container logs: docker compose -f /opt/bionicgpt/docker-compose.yml logs\n")
		}
	}

	summary.WriteString("\n" + strings.Repeat("═", 80) + "\n")
	summary.WriteString("DETAILED DIAGNOSTICS\n")
	summary.WriteString(strings.Repeat("═", 80) + "\n\n")

	return summary.String()
}
