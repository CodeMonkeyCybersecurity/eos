package remotedebug

import (
	"fmt"
	"strings"
	"time"
)

// ReportPrinter handles formatting and printing of diagnostic reports
type ReportPrinter struct{}

// NewReportPrinter creates a new report printer
func NewReportPrinter() *ReportPrinter {
	return &ReportPrinter{}
}

// PrintDiagnosticReport prints a human-readable diagnostic report
func (rp *ReportPrinter) PrintDiagnosticReport(report *SystemReport) {
	fmt.Printf("\n%s System Diagnostic Report %s\n", strings.Repeat("=", 20), strings.Repeat("=", 20))
	fmt.Printf("Host: %s\n", report.Hostname)
	fmt.Printf("Time: %s\n", report.Timestamp.Format(time.RFC3339))
	
	// Print summary first
	if report.Summary != "" {
		fmt.Printf("\n%s\n", report.Summary)
	}
	
	// Print issues by severity
	if len(report.Issues) > 0 {
		rp.printIssuesBySeverity(report.Issues)
	} else {
		fmt.Println("\n✅ No issues detected!")
	}
	
	// Print warnings
	if len(report.Warnings) > 0 {
		fmt.Printf("\n⚠️  WARNINGS (%d)\n", len(report.Warnings))
		for _, warning := range report.Warnings {
			fmt.Printf("\n  Category: %s\n", warning.Category)
			fmt.Printf("  %s\n", warning.Description)
			if warning.Suggestion != "" {
				fmt.Printf("  💡 %s\n", warning.Suggestion)
			}
		}
	}
	
	// Print system metrics
	rp.printSystemMetrics(report)
	
	fmt.Printf("\n%s\n", strings.Repeat("=", 60))
}

// PrintFixReport prints a human-readable fix report
func (rp *ReportPrinter) PrintFixReport(report *FixReport) {
	fmt.Printf("\n%s Fix Report %s\n", strings.Repeat("=", 25), strings.Repeat("=", 25))
	fmt.Printf("Started: %s\n", report.StartTime.Format(time.RFC3339))
	fmt.Printf("Duration: %s\n", report.Duration.Round(time.Second))
	fmt.Printf("Result: %s\n", report.Message)
	
	if len(report.Actions) > 0 {
		fmt.Printf("\n=== Actions Taken ===\n")
		for i, action := range report.Actions {
			fmt.Printf("\n%d. %s\n", i+1, action.Name)
			fmt.Printf("   Duration: %s\n", action.Duration.Round(time.Second))
			fmt.Printf("   Status: ")
			if action.Success {
				fmt.Println("✓ Success")
			} else {
				fmt.Println("✗ Failed")
			}
			
			if action.Message != "" {
				fmt.Printf("   Details: %s\n", action.Message)
			}
			
			if action.SpaceFreed > 0 {
				fmt.Printf("   Space freed: %.2f GB\n", float64(action.SpaceFreed)/(1024*1024*1024))
			}
		}
	}
	
	// Summary
	successCount := 0
	totalSpaceFreed := int64(0)
	for _, action := range report.Actions {
		if action.Success {
			successCount++
			totalSpaceFreed += action.SpaceFreed
		}
	}
	
	fmt.Printf("\n=== Summary ===\n")
	fmt.Printf("Actions completed: %d/%d\n", successCount, len(report.Actions))
	if totalSpaceFreed > 0 {
		fmt.Printf("Total space freed: %.2f GB\n", float64(totalSpaceFreed)/(1024*1024*1024))
	}
}

// printIssuesBySeverity groups and prints issues by severity
func (rp *ReportPrinter) printIssuesBySeverity(issues []Issue) {
	// Group by severity
	severityGroups := map[string][]Issue{
		SeverityCritical: {},
		SeverityHigh:     {},
		SeverityMedium:   {},
		SeverityLow:      {},
	}
	
	for _, issue := range issues {
		if group, exists := severityGroups[issue.Severity]; exists {
			severityGroups[issue.Severity] = append(group, issue)
		}
	}
	
	// Print each severity group
	if len(severityGroups[SeverityCritical]) > 0 {
		fmt.Printf("\n🔴 CRITICAL ISSUES (%d)\n", len(severityGroups[SeverityCritical]))
		for _, issue := range severityGroups[SeverityCritical] {
			rp.printIssue(issue)
		}
	}
	
	if len(severityGroups[SeverityHigh]) > 0 {
		fmt.Printf("\n🟠 HIGH PRIORITY ISSUES (%d)\n", len(severityGroups[SeverityHigh]))
		for _, issue := range severityGroups[SeverityHigh] {
			rp.printIssue(issue)
		}
	}
	
	if len(severityGroups[SeverityMedium]) > 0 {
		fmt.Printf("\n🟡 MEDIUM PRIORITY ISSUES (%d)\n", len(severityGroups[SeverityMedium]))
		for _, issue := range severityGroups[SeverityMedium] {
			rp.printIssue(issue)
		}
	}
	
	if len(severityGroups[SeverityLow]) > 0 {
		fmt.Printf("\n🟢 LOW PRIORITY ISSUES (%d)\n", len(severityGroups[SeverityLow]))
		for _, issue := range severityGroups[SeverityLow] {
			rp.printIssue(issue)
		}
	}
}

// printIssue prints a single issue
func (rp *ReportPrinter) printIssue(issue Issue) {
	fmt.Printf("\n  Category: %s\n", issue.Category)
	fmt.Printf("  Description: %s\n", issue.Description)
	if issue.Evidence != "" {
		fmt.Printf("  Evidence: %s\n", issue.Evidence)
	}
	if issue.Impact != "" {
		fmt.Printf("  Impact: %s\n", issue.Impact)
	}
	if issue.Remediation != "" {
		fmt.Printf("  Remediation: %s\n", issue.Remediation)
	}
}

// printSystemMetrics prints key system metrics
func (rp *ReportPrinter) printSystemMetrics(report *SystemReport) {
	fmt.Println("\n=== System Metrics ===")
	
	// Disk usage
	if len(report.DiskUsage) > 0 {
		fmt.Println("\nDisk Usage:")
		for _, disk := range report.DiskUsage {
			status := "✓"
			if disk.UsePercent >= 90 {
				status = "✗"
			} else if disk.UsePercent >= 80 {
				status = "⚠️"
			}
			
			fmt.Printf("  %s %s: %.1f%% used (%.2f GB free)\n",
				status, disk.Mount, disk.UsePercent,
				float64(disk.Available)/(1024*1024*1024))
		}
	}
	
	// Memory usage
	if report.MemoryUsage.Total > 0 {
		fmt.Printf("\nMemory Usage:\n")
		fmt.Printf("  Total: %.2f GB\n", float64(report.MemoryUsage.Total)/(1024*1024*1024))
		fmt.Printf("  Used: %.2f GB (%.1f%%)\n", 
			float64(report.MemoryUsage.Used)/(1024*1024*1024),
			report.MemoryUsage.UsePercent)
		fmt.Printf("  Available: %.2f GB\n", float64(report.MemoryUsage.Available)/(1024*1024*1024))
		
		if report.MemoryUsage.SwapTotal > 0 {
			fmt.Printf("  Swap: %.2f GB used of %.2f GB (%.1f%%)\n",
				float64(report.MemoryUsage.SwapUsed)/(1024*1024*1024),
				float64(report.MemoryUsage.SwapTotal)/(1024*1024*1024),
				report.MemoryUsage.SwapPercent)
		}
	}
	
	// Service health
	if len(report.ServiceHealth) > 0 {
		activeCount := 0
		for _, active := range report.ServiceHealth {
			if active {
				activeCount++
			}
		}
		
		fmt.Printf("\nService Health:\n")
		fmt.Printf("  Active: %d/%d\n", activeCount, len(report.ServiceHealth))
		
		// Show inactive services
		inactiveServices := []string{}
		for service, active := range report.ServiceHealth {
			if !active {
				inactiveServices = append(inactiveServices, service)
			}
		}
		
		if len(inactiveServices) > 0 {
			fmt.Printf("  Inactive: %s\n", strings.Join(inactiveServices, ", "))
		}
	}
	
	// Large files
	if len(report.LargeFiles) > 0 {
		fmt.Printf("\nLarge Files (top 5):\n")
		for i, file := range report.LargeFiles {
			if i >= 5 {
				break
			}
			fmt.Printf("  %.2f GB: %s\n", float64(file.Size)/(1024*1024*1024), file.Path)
		}
	}
	
	// Log sizes
	if report.JournalSize > 0 || len(report.LogSizes) > 0 {
		fmt.Printf("\nLog Storage:\n")
		if report.JournalSize > 0 {
			fmt.Printf("  Journal: %.2f GB\n", float64(report.JournalSize)/(1024*1024*1024))
		}
		
		totalLogSize := int64(0)
		for _, size := range report.LogSizes {
			totalLogSize += size
		}
		if totalLogSize > 0 {
			fmt.Printf("  Log files: %.2f GB\n", float64(totalLogSize)/(1024*1024*1024))
		}
	}
}