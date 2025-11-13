// pkg/debug/analyzer.go
// Analyzes diagnostic results and provides actionable insights

package debug

import (
	"fmt"
	"strings"
)

// HealthStatus represents overall system health
type HealthStatus string

const (
	HealthHealthy  HealthStatus = "HEALTHY"
	HealthDegraded HealthStatus = "DEGRADED"
	HealthFailed   HealthStatus = "FAILED"
	HealthUnknown  HealthStatus = "UNKNOWN"
)

// Issue represents a detected problem
type Issue struct {
	Severity    string // critical, major, minor
	Component   string
	Description string
	Impact      string
	Remediation string
}

// Warning represents a non-critical concern
type Warning struct {
	Message        string
	Recommendation string
}

// Analysis provides interpretation of diagnostic results
type Analysis struct {
	OverallHealth   HealthStatus
	CriticalIssues  []Issue
	MajorIssues     []Issue
	MinorIssues     []Issue
	Warnings        []Warning
	Recommendations []string
	Summary         string
}

// Analyzer analyzes diagnostic reports and provides insights
type Analyzer struct {
	serviceName string
	customRules []AnalysisRule
}

// AnalysisRule is a function that examines results and may add issues/warnings
type AnalysisRule func(*Report, *Analysis)

// NewAnalyzer creates a new analyzer
func NewAnalyzer(serviceName string) *Analyzer {
	return &Analyzer{
		serviceName: serviceName,
		customRules: make([]AnalysisRule, 0),
	}
}

// AddRule adds a custom analysis rule
func (a *Analyzer) AddRule(rule AnalysisRule) {
	a.customRules = append(a.customRules, rule)
}

// Analyze performs analysis on a diagnostic report
func (a *Analyzer) Analyze(report *Report) *Analysis {
	analysis := &Analysis{
		OverallHealth:   HealthUnknown,
		CriticalIssues:  make([]Issue, 0),
		MajorIssues:     make([]Issue, 0),
		MinorIssues:     make([]Issue, 0),
		Warnings:        make([]Warning, 0),
		Recommendations: make([]string, 0),
	}

	// Run built-in analysis
	a.analyzeResults(report, analysis)

	// Run custom rules
	for _, rule := range a.customRules {
		rule(report, analysis)
	}

	// Determine overall health
	analysis.OverallHealth = a.determineHealth(analysis, report)

	// Generate summary
	analysis.Summary = a.generateSummary(analysis)

	return analysis
}

// analyzeResults performs basic analysis on results
func (a *Analyzer) analyzeResults(report *Report, analysis *Analysis) {
	for _, result := range report.Results {
		switch result.Status {
		case StatusError:
			// Create issue from error
			severity := "major"
			if strings.Contains(strings.ToLower(result.Category), "service") ||
				strings.Contains(strings.ToLower(result.Category), "critical") {
				severity = "critical"
			}

			issue := Issue{
				Severity:    severity,
				Component:   result.Category,
				Description: fmt.Sprintf("%s: %s", result.Name, result.Message),
				Remediation: result.Remediation,
			}

			if severity == "critical" {
				analysis.CriticalIssues = append(analysis.CriticalIssues, issue)
			} else {
				analysis.MajorIssues = append(analysis.MajorIssues, issue)
			}

		case StatusWarning:
			analysis.Warnings = append(analysis.Warnings, Warning{
				Message:        fmt.Sprintf("%s: %s", result.Name, result.Message),
				Recommendation: result.Remediation,
			})
		}
	}
}

// determineHealth determines overall health status
func (a *Analyzer) determineHealth(analysis *Analysis, report *Report) HealthStatus {
	if len(analysis.CriticalIssues) > 0 {
		return HealthFailed
	}

	if len(analysis.MajorIssues) > 0 || len(analysis.Warnings) > 2 {
		return HealthDegraded
	}

	// Check if we have successful service checks
	// BUG FIX: Accept multiple category names for service health checks
	// - "Systemd" for Vault server service
	// - "Vault Agent" for Agent service diagnostics
	// - "Vault" for general Vault checks
	hasRunningService := false
	serviceCategories := []string{"Systemd", "Vault Agent", "Vault", "Service"}

	for _, result := range report.Results {
		for _, category := range serviceCategories {
			if result.Category == category && result.Status == StatusOK {
				hasRunningService = true
				break
			}
		}
		if hasRunningService {
			break
		}
	}

	if hasRunningService {
		return HealthHealthy
	}

	// Only return DEGRADED if we have no healthy services at all
	// This prevents false DEGRADED status when all checks pass
	return HealthDegraded
}

// generateSummary creates a human-readable summary
func (a *Analyzer) generateSummary(analysis *Analysis) string {
	var parts []string

	switch analysis.OverallHealth {
	case HealthHealthy:
		parts = append(parts, fmt.Sprintf("%s is healthy and running normally", a.serviceName))
	case HealthDegraded:
		parts = append(parts, fmt.Sprintf("%s is running but has issues", a.serviceName))
	case HealthFailed:
		parts = append(parts, fmt.Sprintf("%s has critical failures", a.serviceName))
	}

	totalIssues := len(analysis.CriticalIssues) + len(analysis.MajorIssues) + len(analysis.MinorIssues)
	if totalIssues > 0 {
		parts = append(parts, fmt.Sprintf("%d issues found", totalIssues))
	}

	if len(analysis.Warnings) > 0 {
		parts = append(parts, fmt.Sprintf("%d warnings", len(analysis.Warnings)))
	}

	return strings.Join(parts, " - ")
}

// FormatAnalysis formats the analysis for display
func FormatAnalysis(analysis *Analysis) string {
	var b strings.Builder

	b.WriteString("\n" + strings.Repeat("=", 80) + "\n")
	b.WriteString("DIAGNOSTIC ANALYSIS\n")
	b.WriteString(strings.Repeat("=", 80) + "\n\n")

	// Overall health
	healthIcon := "✓"
	switch analysis.OverallHealth {
	case HealthDegraded:
		healthIcon = "⚠"
	case HealthFailed:
		healthIcon = "✗"
	}

	b.WriteString(fmt.Sprintf("OVERALL HEALTH: %s %s\n\n", healthIcon, analysis.OverallHealth))
	b.WriteString(fmt.Sprintf("SUMMARY: %s\n\n", analysis.Summary))

	// Critical issues
	if len(analysis.CriticalIssues) > 0 {
		b.WriteString("CRITICAL ISSUES (Immediate attention required):\n")
		for i, issue := range analysis.CriticalIssues {
			b.WriteString(fmt.Sprintf("%d. %s\n", i+1, issue.Description))
			if issue.Impact != "" {
				b.WriteString(fmt.Sprintf("   Impact: %s\n", issue.Impact))
			}
			if issue.Remediation != "" {
				b.WriteString(fmt.Sprintf("   Fix: %s\n", issue.Remediation))
			}
			b.WriteString("\n")
		}
	}

	// Major issues
	if len(analysis.MajorIssues) > 0 {
		b.WriteString("MAJOR ISSUES:\n")
		for i, issue := range analysis.MajorIssues {
			b.WriteString(fmt.Sprintf("%d. %s\n", i+1, issue.Description))
			if issue.Remediation != "" {
				b.WriteString(fmt.Sprintf("   Fix: %s\n", issue.Remediation))
			}
			b.WriteString("\n")
		}
	}

	// Warnings
	if len(analysis.Warnings) > 0 {
		b.WriteString("WARNINGS:\n")
		for i, warning := range analysis.Warnings {
			b.WriteString(fmt.Sprintf("%d. %s\n", i+1, warning.Message))
			if warning.Recommendation != "" {
				b.WriteString(fmt.Sprintf("   Recommendation: %s\n", warning.Recommendation))
			}
		}
		b.WriteString("\n")
	}

	// Recommendations
	if len(analysis.Recommendations) > 0 {
		b.WriteString("RECOMMENDATIONS:\n")
		for i, rec := range analysis.Recommendations {
			b.WriteString(fmt.Sprintf("%d. %s\n", i+1, rec))
		}
		b.WriteString("\n")
	}

	return b.String()
}

// QuickSummary generates a brief health summary
type QuickSummary struct {
	Items     []QuickSummaryItem
	NextSteps []string
}

// QuickSummaryItem represents a single status item
type QuickSummaryItem struct {
	Label  string
	Status bool
	Detail string
	Icon   string
}

// GenerateQuickSummary creates a quick summary from analysis
func GenerateQuickSummary(report *Report, analysis *Analysis) *QuickSummary {
	summary := &QuickSummary{
		Items:     make([]QuickSummaryItem, 0),
		NextSteps: make([]string, 0),
	}

	// Analyze results to build summary items
	for _, result := range report.Results {
		if shouldIncludeInQuickSummary(result) {
			item := QuickSummaryItem{
				Label:  result.Name,
				Status: result.Status == StatusOK,
				Detail: extractDetail(result),
			}

			if item.Status {
				item.Icon = "✓"
			} else {
				item.Icon = "✗"
			}

			summary.Items = append(summary.Items, item)
		}
	}

	// Generate next steps from recommendations
	if len(analysis.Recommendations) > 0 {
		summary.NextSteps = analysis.Recommendations
	} else {
		// Default next steps based on health
		switch analysis.OverallHealth {
		case HealthFailed:
			summary.NextSteps = append(summary.NextSteps, "Address critical issues listed above")
		case HealthHealthy:
			summary.NextSteps = append(summary.NextSteps, fmt.Sprintf("%s is healthy - no action required", report.ServiceName))
		}
	}

	return summary
}

// FormatQuickSummary formats the quick summary
func FormatQuickSummary(summary *QuickSummary, serviceName string) string {
	var b strings.Builder

	b.WriteString(strings.Repeat("=", 80) + "\n")
	b.WriteString(fmt.Sprintf("QUICK HEALTH SUMMARY - %s\n", strings.ToUpper(serviceName)))
	b.WriteString(strings.Repeat("=", 80) + "\n\n")

	for _, item := range summary.Items {
		detail := ""
		if item.Detail != "" {
			detail = " (" + item.Detail + ")"
		}
		b.WriteString(fmt.Sprintf("%-25s %s%s\n", item.Label+":", item.Icon, detail))
	}

	if len(summary.NextSteps) > 0 {
		b.WriteString("\nNEXT STEPS:\n")
		for i, step := range summary.NextSteps {
			b.WriteString(fmt.Sprintf("  %d. %s\n", i+1, step))
		}
	}

	b.WriteString("\n")
	return b.String()
}

// Helper functions
func shouldIncludeInQuickSummary(result *Result) bool {
	// Include service, network, and critical checks
	importantCategories := []string{"Systemd", "Network", "Installation"}
	for _, cat := range importantCategories {
		if result.Category == cat {
			return true
		}
	}
	return false
}

func extractDetail(result *Result) string {
	if detail, ok := result.Metadata["detail"].(string); ok {
		return detail
	}
	return ""
}
