package remotedebug

import (
	"fmt"
	"strings"
)

// Analyzer analyzes system diagnostics and identifies issues
type Analyzer struct {
	report *SystemReport
}

// NewAnalyzer creates a new analyzer
func NewAnalyzer(report *SystemReport) *Analyzer {
	return &Analyzer{
		report: report,
	}
}

// AnalyzeIssues identifies issues in the system
func (a *Analyzer) AnalyzeIssues() []Issue {
	var issues []Issue

	// Analyze disk space
	issues = append(issues, a.analyzeDiskSpace()...)

	// Analyze memory usage
	issues = append(issues, a.analyzeMemory()...)

	// Analyze processes
	issues = append(issues, a.analyzeProcesses()...)

	// Analyze services
	issues = append(issues, a.analyzeServices()...)

	// Analyze logs
	issues = append(issues, a.analyzeLogs()...)

	return issues
}

// AnalyzeWarnings identifies potential problems
func (a *Analyzer) AnalyzeWarnings() []Warning {
	var warnings []Warning

	// Check disk usage warnings (70-80% threshold)
	for _, disk := range a.report.DiskUsage {
		if disk.UsePercent >= 70 && disk.UsePercent < 80 {
			warnings = append(warnings, Warning{
				Category:    CategoryDisk,
				Description: fmt.Sprintf("Disk %s is %.1f%% full", disk.Mount, disk.UsePercent),
				Suggestion:  "Monitor disk usage and consider cleanup",
			})
		}

		// Inode warnings
		if disk.InodesPercent >= 70 && disk.InodesPercent < 90 {
			warnings = append(warnings, Warning{
				Category:    CategoryDisk,
				Description: fmt.Sprintf("Disk %s has %.1f%% inodes used", disk.Mount, disk.InodesPercent),
				Suggestion:  "Check for many small files or empty directories",
			})
		}
	}

	// Memory warnings
	if a.report.MemoryUsage.UsePercent >= 70 && a.report.MemoryUsage.UsePercent < 85 {
		warnings = append(warnings, Warning{
			Category:    CategoryMemory,
			Description: fmt.Sprintf("Memory usage is %.1f%%", a.report.MemoryUsage.UsePercent),
			Suggestion:  "Monitor memory usage and identify memory-intensive processes",
		})
	}

	// Swap warnings
	if a.report.MemoryUsage.SwapPercent > 50 {
		warnings = append(warnings, Warning{
			Category:    CategoryMemory,
			Description: fmt.Sprintf("Swap usage is %.1f%%", a.report.MemoryUsage.SwapPercent),
			Suggestion:  "High swap usage may indicate memory pressure",
		})
	}

	return warnings
}

// GenerateSummary creates an executive summary
func (a *Analyzer) GenerateSummary() string {
	var summary strings.Builder

	// Count issues by severity
	criticalCount := 0
	highCount := 0
	mediumCount := 0
	lowCount := 0

	for _, issue := range a.report.Issues {
		switch issue.Severity {
		case SeverityCritical:
			criticalCount++
		case SeverityHigh:
			highCount++
		case SeverityMedium:
			mediumCount++
		case SeverityLow:
			lowCount++
		}
	}

	summary.WriteString(fmt.Sprintf("System Health Summary for %s:\n", a.report.Hostname))

	if criticalCount == 0 && highCount == 0 && mediumCount == 0 && lowCount == 0 {
		summary.WriteString(" No significant issues detected. System appears healthy.\n")
	} else {
		if criticalCount > 0 {
			summary.WriteString(fmt.Sprintf("🔴 Critical Issues: %d\n", criticalCount))
		}
		if highCount > 0 {
			summary.WriteString(fmt.Sprintf("🟠 High Priority Issues: %d\n", highCount))
		}
		if mediumCount > 0 {
			summary.WriteString(fmt.Sprintf("🟡 Medium Priority Issues: %d\n", mediumCount))
		}
		if lowCount > 0 {
			summary.WriteString(fmt.Sprintf("🟢 Low Priority Issues: %d\n", lowCount))
		}
	}

	if len(a.report.Warnings) > 0 {
		summary.WriteString(fmt.Sprintf("Warnings: %d\n", len(a.report.Warnings)))
	}

	// Add key metrics
	summary.WriteString("\nKey Metrics:\n")

	// Find root disk
	for _, disk := range a.report.DiskUsage {
		if disk.Mount == "/" {
			summary.WriteString(fmt.Sprintf("- Root Disk Usage: %.1f%%\n", disk.UsePercent))
			break
		}
	}

	summary.WriteString(fmt.Sprintf("- Memory Usage: %.1f%%\n", a.report.MemoryUsage.UsePercent))
	summary.WriteString(fmt.Sprintf("- Active Services: %d/%d\n", a.countActiveServices(), len(a.report.ServiceHealth)))

	return summary.String()
}

// analyzeDiskSpace checks for disk space issues
func (a *Analyzer) analyzeDiskSpace() []Issue {
	var issues []Issue

	for _, disk := range a.report.DiskUsage {
		// Critical: >95% full
		if disk.UsePercent >= 95 {
			issues = append(issues, Issue{
				Severity:    SeverityCritical,
				Category:    CategoryDisk,
				Description: fmt.Sprintf("Disk %s is critically full: %.1f%%", disk.Mount, disk.UsePercent),
				Evidence:    fmt.Sprintf("Used: %d bytes of %d total", disk.Used, disk.Total),
				Impact:      "System may fail to write files, services may crash",
				Remediation: "Immediate cleanup required. Run emergency disk cleanup or add storage",
			})
		} else if disk.UsePercent >= 90 {
			// High: 90-95% full
			issues = append(issues, Issue{
				Severity:    SeverityHigh,
				Category:    CategoryDisk,
				Description: fmt.Sprintf("Disk %s is nearly full: %.1f%%", disk.Mount, disk.UsePercent),
				Evidence:    fmt.Sprintf("Only %d bytes available", disk.Available),
				Impact:      "Services may start failing, performance degradation",
				Remediation: "Clean up disk space urgently",
			})
		} else if disk.UsePercent >= 80 {
			// Medium: 80-90% full
			issues = append(issues, Issue{
				Severity:    SeverityMedium,
				Category:    CategoryDisk,
				Description: fmt.Sprintf("Disk %s usage is high: %.1f%%", disk.Mount, disk.UsePercent),
				Evidence:    fmt.Sprintf("%d bytes available", disk.Available),
				Impact:      "May affect system performance",
				Remediation: "Plan disk cleanup or expansion",
			})
		}

		// Check inode usage
		if disk.InodesPercent >= 90 {
			issues = append(issues, Issue{
				Severity:    SeverityHigh,
				Category:    CategoryDisk,
				Description: fmt.Sprintf("Disk %s has high inode usage: %.1f%%", disk.Mount, disk.InodesPercent),
				Evidence:    fmt.Sprintf("Used %d of %d inodes", disk.InodesUsed, disk.Inodes),
				Impact:      "Cannot create new files even with space available",
				Remediation: "Remove unnecessary files or directories",
			})
		}
	}

	// Check for large files
	if len(a.report.LargeFiles) > 0 {
		totalSize := int64(0)
		for _, file := range a.report.LargeFiles {
			totalSize += file.Size
		}

		if totalSize > 10*1024*1024*1024 { // 10GB
			issues = append(issues, Issue{
				Severity:    SeverityMedium,
				Category:    CategoryDisk,
				Description: fmt.Sprintf("Found %d large files consuming %.2f GB", len(a.report.LargeFiles), float64(totalSize)/(1024*1024*1024)),
				Evidence:    fmt.Sprintf("Largest file: %s", a.report.LargeFiles[0].Path),
				Impact:      "Large files consuming significant disk space",
				Remediation: "Review and clean up large files if not needed",
			})
		}
	}

	// Check for deleted but open files
	if len(a.report.DeletedButOpenFiles) > 0 {
		totalSize := int64(0)
		for _, file := range a.report.DeletedButOpenFiles {
			totalSize += file.Size
		}

		if totalSize > 1024*1024*1024 { // 1GB
			issues = append(issues, Issue{
				Severity:    SeverityHigh,
				Category:    CategoryDisk,
				Description: fmt.Sprintf("Deleted files still consuming %.2f GB", float64(totalSize)/(1024*1024*1024)),
				Evidence:    fmt.Sprintf("%d deleted files held open by processes", len(a.report.DeletedButOpenFiles)),
				Impact:      "Disk space not freed despite file deletion",
				Remediation: "Restart services holding deleted files open",
			})
		}
	}

	return issues
}

// analyzeMemory checks for memory-related issues
func (a *Analyzer) analyzeMemory() []Issue {
	var issues []Issue

	// Check memory usage
	if a.report.MemoryUsage.UsePercent >= 95 {
		issues = append(issues, Issue{
			Severity:    SeverityCritical,
			Category:    CategoryMemory,
			Description: fmt.Sprintf("Critical memory pressure: %.1f%% used", a.report.MemoryUsage.UsePercent),
			Evidence:    fmt.Sprintf("Available: %d bytes of %d total", a.report.MemoryUsage.Available, a.report.MemoryUsage.Total),
			Impact:      "System may invoke OOM killer, services may crash",
			Remediation: "Identify and stop memory-intensive processes immediately",
		})
	} else if a.report.MemoryUsage.UsePercent >= 85 {
		issues = append(issues, Issue{
			Severity:    SeverityHigh,
			Category:    CategoryMemory,
			Description: fmt.Sprintf("High memory usage: %.1f%%", a.report.MemoryUsage.UsePercent),
			Evidence:    fmt.Sprintf("Only %d bytes available", a.report.MemoryUsage.Available),
			Impact:      "System performance degraded, risk of OOM",
			Remediation: "Review memory usage and optimize applications",
		})
	}

	// Check swap usage
	if a.report.MemoryUsage.SwapTotal > 0 && a.report.MemoryUsage.SwapPercent > 80 {
		issues = append(issues, Issue{
			Severity:    SeverityHigh,
			Category:    CategoryMemory,
			Description: fmt.Sprintf("High swap usage: %.1f%%", a.report.MemoryUsage.SwapPercent),
			Evidence:    fmt.Sprintf("Swap used: %d of %d bytes", a.report.MemoryUsage.SwapUsed, a.report.MemoryUsage.SwapTotal),
			Impact:      "Severe performance degradation due to swapping",
			Remediation: "Add more RAM or reduce memory usage",
		})
	}

	return issues
}

// analyzeProcesses checks for process-related issues
func (a *Analyzer) analyzeProcesses() []Issue {
	var issues []Issue

	// Check for high CPU usage
	for _, proc := range a.report.ProcessInfo {
		if proc.CPUPercent > 90 {
			issues = append(issues, Issue{
				Severity:    SeverityMedium,
				Category:    "process",
				Description: fmt.Sprintf("Process consuming high CPU: %s", proc.Command),
				Evidence:    fmt.Sprintf("PID %s using %.1f%% CPU", proc.PID, proc.CPUPercent),
				Impact:      "High CPU usage affecting system performance",
				Remediation: "Investigate process behavior and optimize if possible",
			})
		}

		if proc.MemPercent > 50 {
			issues = append(issues, Issue{
				Severity:    SeverityMedium,
				Category:    "process",
				Description: fmt.Sprintf("Process consuming high memory: %s", proc.Command),
				Evidence:    fmt.Sprintf("PID %s using %.1f%% memory", proc.PID, proc.MemPercent),
				Impact:      "High memory usage may lead to system instability",
				Remediation: "Review process memory usage and configuration",
			})
		}
	}

	return issues
}

// analyzeServices checks for service health issues
func (a *Analyzer) analyzeServices() []Issue {
	var issues []Issue

	// Check critical services
	criticalServices := []string{"ssh", "sshd", "systemd-logind"}

	for service, active := range a.report.ServiceHealth {
		if !active {
			severity := SeverityMedium

			// Critical services get higher severity
			for _, critical := range criticalServices {
				if service == critical {
					severity = SeverityHigh
					break
				}
			}

			issues = append(issues, Issue{
				Severity:    severity,
				Category:    "service",
				Description: fmt.Sprintf("Service %s is not active", service),
				Evidence:    "systemctl is-active returned inactive",
				Impact:      "Service functionality unavailable",
				Remediation: fmt.Sprintf("Investigate and start service: systemctl start %s", service),
			})
		}
	}

	return issues
}

// analyzeLogs checks for log-related issues
func (a *Analyzer) analyzeLogs() []Issue {
	var issues []Issue

	// Check journal size
	if a.report.JournalSize > 5*1024*1024*1024 { // 5GB
		issues = append(issues, Issue{
			Severity:    SeverityMedium,
			Category:    "logs",
			Description: fmt.Sprintf("Large systemd journal: %.2f GB", float64(a.report.JournalSize)/(1024*1024*1024)),
			Evidence:    fmt.Sprintf("%d bytes used by journal", a.report.JournalSize),
			Impact:      "Consuming significant disk space",
			Remediation: "Run: journalctl --vacuum-time=7d",
		})
	}

	// Check for large log files
	totalLogSize := int64(0)
	largestLog := ""
	largestSize := int64(0)

	for path, size := range a.report.LogSizes {
		totalLogSize += size
		if size > largestSize {
			largestSize = size
			largestLog = path
		}
	}

	if totalLogSize > 10*1024*1024*1024 { // 10GB
		issues = append(issues, Issue{
			Severity:    SeverityMedium,
			Category:    "logs",
			Description: fmt.Sprintf("Log files consuming %.2f GB", float64(totalLogSize)/(1024*1024*1024)),
			Evidence:    fmt.Sprintf("Largest log: %s (%.2f GB)", largestLog, float64(largestSize)/(1024*1024*1024)),
			Impact:      "Excessive disk space used by logs",
			Remediation: "Implement log rotation or clean old logs",
		})
	}

	return issues
}

// countActiveServices counts the number of active services
func (a *Analyzer) countActiveServices() int {
	count := 0
	for _, active := range a.report.ServiceHealth {
		if active {
			count++
		}
	}
	return count
}
