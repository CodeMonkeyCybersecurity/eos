package remotedebug

import (
	"fmt"
	"strings"
	"time"
)

// AutomatedFixer attempts to fix detected issues
type AutomatedFixer struct {
	client   *SSHClient
	sudoPass string
	dryRun   bool
}

// NewAutomatedFixer creates a new automated fixer
func NewAutomatedFixer(client *SSHClient, sudoPass string, dryRun bool) *AutomatedFixer {
	return &AutomatedFixer{
		client:   client,
		sudoPass: sudoPass,
		dryRun:   dryRun,
	}
}

// FixIssues attempts to fix issues based on the diagnostic report
func (af *AutomatedFixer) FixIssues(report *SystemReport) (*FixReport, error) {
	fixReport := &FixReport{
		StartTime: time.Now(),
		Actions:   []FixAction{},
		Success:   true,
	}

	// Group issues by category and severity
	criticalDiskIssues := af.filterIssues(report.Issues, CategoryDisk, SeverityCritical)
	highDiskIssues := af.filterIssues(report.Issues, CategoryDisk, SeverityHigh)
	memoryIssues := af.filterIssues(report.Issues, CategoryMemory, "")
	serviceIssues := af.filterIssues(report.Issues, "service", "")
	logIssues := af.filterIssues(report.Issues, "logs", "")

	// Fix critical disk issues first
	if len(criticalDiskIssues) > 0 {
		action := af.fixCriticalDiskSpace(report)
		fixReport.Actions = append(fixReport.Actions, action)
		if !action.Success && !af.dryRun {
			fixReport.Success = false
		}
	}

	// Fix high priority disk issues
	if len(highDiskIssues) > 0 {
		action := af.fixHighDiskUsage(report)
		fixReport.Actions = append(fixReport.Actions, action)
	}

	// Fix memory issues
	if len(memoryIssues) > 0 {
		action := af.fixMemoryIssues(report)
		fixReport.Actions = append(fixReport.Actions, action)
	}

	// Fix service issues
	for _, issue := range serviceIssues {
		action := af.fixServiceIssue(issue)
		fixReport.Actions = append(fixReport.Actions, action)
	}

	// Fix log issues
	if len(logIssues) > 0 {
		action := af.fixLogIssues(report)
		fixReport.Actions = append(fixReport.Actions, action)
	}

	fixReport.Duration = time.Since(fixReport.StartTime)

	// Generate summary message
	successCount := 0
	for _, action := range fixReport.Actions {
		if action.Success {
			successCount++
		}
	}

	if successCount == len(fixReport.Actions) {
		fixReport.Message = fmt.Sprintf("Successfully completed all %d fix actions", len(fixReport.Actions))
	} else {
		fixReport.Message = fmt.Sprintf("Completed %d of %d fix actions", successCount, len(fixReport.Actions))
		if !af.dryRun {
			fixReport.Success = false
		}
	}

	return fixReport, nil
}

// fixCriticalDiskSpace performs emergency disk cleanup
func (af *AutomatedFixer) fixCriticalDiskSpace(report *SystemReport) FixAction {
	action := FixAction{
		Name:      "Emergency disk cleanup",
		StartTime: time.Now(),
	}

	if af.dryRun {
		action.Success = true
		action.Message = "DRY RUN - Would perform emergency disk cleanup"
		action.Duration = time.Since(action.StartTime)
		return action
	}

	// Series of cleanup operations in order of safety and impact
	cleanupOps := []struct {
		name    string
		command string
		impact  int64 // Estimated space freed in bytes
	}{
		{
			"Package cache cleanup",
			"apt-get clean 2>/dev/null || yum clean all 2>/dev/null || dnf clean all 2>/dev/null",
			500 * 1024 * 1024, // 500MB estimate
		},
		{
			"Old journal cleanup",
			"journalctl --vacuum-time=1d",
			1024 * 1024 * 1024, // 1GB estimate
		},
		{
			"Temporary files cleanup",
			"find /tmp -type f -atime +1 -delete 2>/dev/null && find /var/tmp -type f -atime +7 -delete 2>/dev/null",
			200 * 1024 * 1024, // 200MB estimate
		},
		{
			"Compressed log cleanup",
			"find /var/log -name '*.gz' -o -name '*.bz2' -o -name '*.xz' | xargs rm -f 2>/dev/null",
			500 * 1024 * 1024, // 500MB estimate
		},
		{
			"Old log cleanup",
			"find /var/log -name '*.1' -o -name '*.2' -o -name '*.3' -o -name '*.old' | xargs rm -f 2>/dev/null",
			300 * 1024 * 1024, // 300MB estimate
		},
		{
			"Truncate large active logs",
			"find /var/log -type f -name '*.log' -size +100M -exec truncate -s 0 {} \\; 2>/dev/null",
			1024 * 1024 * 1024, // 1GB estimate
		},
	}

	totalFreed := int64(0)
	var results []string

	for _, op := range cleanupOps {
		_, err := af.client.ExecuteCommand(op.command, true)
		if err == nil {
			totalFreed += op.impact
			results = append(results, fmt.Sprintf("✓ %s", op.name))
		} else {
			results = append(results, fmt.Sprintf("✗ %s: %v", op.name, err))
		}
	}

	// Kill processes holding deleted files if significant space
	if len(report.DeletedButOpenFiles) > 0 {
		deletedSize := int64(0)
		for _, file := range report.DeletedButOpenFiles {
			deletedSize += file.Size
		}

		if deletedSize > 500*1024*1024 { // 500MB
			// Get unique PIDs
			pids := make(map[string]bool)
			for _, file := range report.DeletedButOpenFiles {
				if file.PID != "" {
					pids[file.PID] = true
				}
			}

			// Try to restart services instead of killing
			restartCmd := "systemctl restart rsyslog systemd-journald 2>/dev/null"
			if _, err := af.client.ExecuteCommand(restartCmd, true); err == nil {
				totalFreed += deletedSize
				results = append(results, fmt.Sprintf("✓ Restarted services holding deleted files (freed ~%.2f GB)",
					float64(deletedSize)/(1024*1024*1024)))
			}
		}
	}

	action.Success = true
	action.SpaceFreed = totalFreed
	action.Message = fmt.Sprintf("Freed approximately %.2f GB\nOperations:\n%s",
		float64(totalFreed)/(1024*1024*1024), strings.Join(results, "\n"))
	action.Duration = time.Since(action.StartTime)

	return action
}

// fixHighDiskUsage performs standard disk cleanup
func (af *AutomatedFixer) fixHighDiskUsage(report *SystemReport) FixAction {
	action := FixAction{
		Name:      "Standard disk cleanup",
		StartTime: time.Now(),
	}

	if af.dryRun {
		action.Success = true
		action.Message = "DRY RUN - Would perform standard disk cleanup"
		action.Duration = time.Since(action.StartTime)
		return action
	}

	cleanupOps := []struct {
		name    string
		command string
	}{
		{"Package cache", "apt-get clean 2>/dev/null || yum clean all 2>/dev/null"},
		{"Old kernels", "apt-get autoremove -y 2>/dev/null || package-cleanup --oldkernels --count=2 -y 2>/dev/null"},
		{"Journal logs (keep 3 days)", "journalctl --vacuum-time=3d"},
		{"Old compressed logs", "find /var/log -name '*.gz' -mtime +7 -delete 2>/dev/null"},
		{"Thumbnail cache", "find ~/.cache/thumbnails -type f -atime +7 -delete 2>/dev/null"},
	}

	var results []string
	successCount := 0

	for _, op := range cleanupOps {
		_, err := af.client.ExecuteCommand(op.command, true)
		if err == nil {
			results = append(results, fmt.Sprintf("✓ %s", op.name))
			successCount++
		} else {
			results = append(results, fmt.Sprintf("✗ %s: %v", op.name, err))
		}
	}

	action.Success = successCount > 0
	action.Message = fmt.Sprintf("Completed %d of %d cleanup operations\n%s",
		successCount, len(cleanupOps), strings.Join(results, "\n"))
	action.Duration = time.Since(action.StartTime)

	return action
}

// fixMemoryIssues attempts to free up memory
func (af *AutomatedFixer) fixMemoryIssues(report *SystemReport) FixAction {
	action := FixAction{
		Name:      "Memory optimization",
		StartTime: time.Now(),
	}

	if af.dryRun {
		action.Success = true
		action.Message = "DRY RUN - Would perform memory optimization"
		action.Duration = time.Since(action.StartTime)
		return action
	}

	var results []string

	// Clear caches
	cacheCmd := "sync && echo 3 > /proc/sys/vm/drop_caches"
	if _, err := af.client.ExecuteCommand(cacheCmd, true); err == nil {
		results = append(results, "✓ Cleared system caches")
	}

	// Restart memory-heavy services if safe
	heavyServices := []string{"mysql", "mariadb", "postgresql", "mongodb", "elasticsearch"}
	for _, service := range heavyServices {
		// Check if service exists and is running
		checkCmd := fmt.Sprintf("systemctl is-active %s 2>/dev/null", service)
		if output, err := af.client.ExecuteCommand(checkCmd, false); err == nil && strings.TrimSpace(output) == "active" {
			// Check if it's using significant memory
			for _, proc := range report.ProcessInfo {
				if strings.Contains(strings.ToLower(proc.Command), service) && proc.MemPercent > 20 {
					restartCmd := fmt.Sprintf("systemctl restart %s", service)
					if _, err := af.client.ExecuteCommand(restartCmd, true); err == nil {
						results = append(results, fmt.Sprintf("✓ Restarted %s (was using %.1f%% memory)", service, proc.MemPercent))
					}
					break
				}
			}
		}
	}

	// Kill zombie processes
	zombieCmd := "ps aux | grep '<defunct>' | grep -v grep | awk '{print $2}' | xargs -r kill -9 2>/dev/null"
	if _, err := af.client.ExecuteCommand(zombieCmd, true); err == nil {
		results = append(results, "✓ Cleaned up zombie processes")
	}

	action.Success = len(results) > 0
	if len(results) == 0 {
		action.Message = "No memory optimization actions were applicable"
	} else {
		action.Message = fmt.Sprintf("Memory optimization completed:\n%s", strings.Join(results, "\n"))
	}
	action.Duration = time.Since(action.StartTime)

	return action
}

// fixServiceIssue attempts to fix a service that's not running
func (af *AutomatedFixer) fixServiceIssue(issue Issue) FixAction {
	// Extract service name from issue description
	serviceName := ""
	if strings.Contains(issue.Description, "Service ") && strings.Contains(issue.Description, " is not active") {
		parts := strings.Split(issue.Description, " ")
		for i, part := range parts {
			if part == "Service" && i+1 < len(parts) {
				serviceName = parts[i+1]
				break
			}
		}
	}

	action := FixAction{
		Name:      fmt.Sprintf("Fix service: %s", serviceName),
		StartTime: time.Now(),
	}

	if serviceName == "" {
		action.Success = false
		action.Message = "Could not extract service name from issue"
		action.Duration = time.Since(action.StartTime)
		return action
	}

	if af.dryRun {
		action.Success = true
		action.Message = fmt.Sprintf("DRY RUN - Would attempt to start service %s", serviceName)
		action.Duration = time.Since(action.StartTime)
		return action
	}

	// Try to start the service
	startCmd := fmt.Sprintf("systemctl start %s", serviceName)
	_, err := af.client.ExecuteCommand(startCmd, true)

	if err != nil {
		// Check if it failed due to a condition
		statusCmd := fmt.Sprintf("systemctl status %s", serviceName)
		statusOutput, _ := af.client.ExecuteCommand(statusCmd, true)

		action.Success = false
		action.Message = fmt.Sprintf("Failed to start %s: %v\nStatus: %s", serviceName, err, statusOutput)
	} else {
		// Verify it's now running
		checkCmd := fmt.Sprintf("systemctl is-active %s", serviceName)
		if activeOutput, err := af.client.ExecuteCommand(checkCmd, false); err == nil && strings.TrimSpace(activeOutput) == "active" {
			action.Success = true
			action.Message = fmt.Sprintf("Successfully started %s", serviceName)
		} else {
			action.Success = false
			action.Message = fmt.Sprintf("Started %s but verification failed", serviceName)
		}
	}

	action.Duration = time.Since(action.StartTime)
	return action
}

// fixLogIssues cleans up excessive logs
func (af *AutomatedFixer) fixLogIssues(report *SystemReport) FixAction {
	action := FixAction{
		Name:      "Log cleanup and rotation",
		StartTime: time.Now(),
	}

	if af.dryRun {
		action.Success = true
		action.Message = "DRY RUN - Would perform log cleanup and rotation"
		action.Duration = time.Since(action.StartTime)
		return action
	}

	var results []string
	totalFreed := int64(0)

	// Vacuum journal if large
	if report.JournalSize > 1*1024*1024*1024 { // 1GB
		vacuumCmd := "journalctl --vacuum-size=500M"
		if _, err := af.client.ExecuteCommand(vacuumCmd, true); err == nil {
			freed := report.JournalSize - 500*1024*1024
			if freed > 0 {
				totalFreed += freed
				results = append(results, fmt.Sprintf("✓ Vacuumed journal (freed ~%.2f GB)", float64(freed)/(1024*1024*1024)))
			}
		}
	}

	// Rotate and compress large logs
	rotateCmd := "logrotate -f /etc/logrotate.conf 2>/dev/null"
	if _, err := af.client.ExecuteCommand(rotateCmd, true); err == nil {
		results = append(results, "✓ Forced log rotation")
	}

	// Clean old rotated logs
	cleanCmd := "find /var/log -name '*.gz' -o -name '*.1' -o -name '*.old' -mtime +30 | xargs -r rm -f"
	if _, err := af.client.ExecuteCommand(cleanCmd, true); err == nil {
		results = append(results, "✓ Cleaned old rotated logs (>30 days)")
	}

	// Truncate specific large logs
	for logPath, size := range report.LogSizes {
		if size > 1*1024*1024*1024 { // 1GB
			truncateCmd := fmt.Sprintf("cp /dev/null %s", logPath)
			if _, err := af.client.ExecuteCommand(truncateCmd, true); err == nil {
				totalFreed += size
				results = append(results, fmt.Sprintf("✓ Truncated %s (freed %.2f GB)", logPath, float64(size)/(1024*1024*1024)))
			}
		}
	}

	action.Success = len(results) > 0
	action.SpaceFreed = totalFreed
	if len(results) == 0 {
		action.Message = "No log cleanup actions were necessary"
	} else {
		action.Message = fmt.Sprintf("Log cleanup completed (freed ~%.2f GB):\n%s",
			float64(totalFreed)/(1024*1024*1024), strings.Join(results, "\n"))
	}
	action.Duration = time.Since(action.StartTime)

	return action
}

// filterIssues filters issues by category and/or severity
func (af *AutomatedFixer) filterIssues(issues []Issue, category, severity string) []Issue {
	var filtered []Issue

	for _, issue := range issues {
		if category != "" && issue.Category != category {
			continue
		}
		if severity != "" && issue.Severity != severity {
			continue
		}
		filtered = append(filtered, issue)
	}

	return filtered
}
