package remotedebug

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DiagnosticCollector gathers system information following Assess → Intervene → Evaluate pattern
type DiagnosticCollector struct {
	client   *SSHClient
	sudoPass string
}

// NewDiagnosticCollector creates a new diagnostic collector
func NewDiagnosticCollector(client *SSHClient, sudoPass string) *DiagnosticCollector {
	return &DiagnosticCollector{
		client:   client,
		sudoPass: sudoPass,
	}
}

// CollectDiagnostics gathers system diagnostics based on options
func (dc *DiagnosticCollector) CollectDiagnostics(opts DiagnosticOptions) (*SystemReport, error) {
	report := &SystemReport{
		Timestamp: time.Now(),
	}

	// ASSESS - Check if we can gather diagnostics
	if err := dc.assessCapabilities(); err != nil {
		return nil, fmt.Errorf("assessment failed: %w", err)
	}

	// Get hostname first
	hostname, err := dc.client.GetHostInfo()
	if err == nil {
		report.Hostname = strings.TrimSpace(hostname)
	}

	// INTERVENE - Collect diagnostics based on check type
	switch opts.CheckType {
	case "disk":
		if err := dc.collectDiskDiagnostics(report); err != nil {
			return nil, fmt.Errorf("disk diagnostics failed: %w", err)
		}

	case "memory":
		if err := dc.collectMemoryDiagnostics(report); err != nil {
			return nil, fmt.Errorf("memory diagnostics failed: %w", err)
		}

	case "network":
		if err := dc.collectNetworkDiagnostics(report); err != nil {
			return nil, fmt.Errorf("network diagnostics failed: %w", err)
		}

	case "auth":
		if err := dc.collectAuthDiagnostics(report); err != nil {
			return nil, fmt.Errorf("auth diagnostics failed: %w", err)
		}

	case "all":
		// Collect all diagnostics in parallel for efficiency
		if err := dc.collectAllDiagnostics(report); err != nil {
			return nil, fmt.Errorf("comprehensive diagnostics failed: %w", err)
		}

	default:
		return nil, fmt.Errorf("unknown check type: %s", opts.CheckType)
	}

	// EVALUATE - Verify diagnostic collection was successful
	if err := dc.evaluateCollection(report); err != nil {
		return nil, fmt.Errorf("evaluation failed: %w", err)
	}

	return report, nil
}

// assessCapabilities checks if we can perform diagnostics
func (dc *DiagnosticCollector) assessCapabilities() error {
	// Check basic command availability
	requiredCmds := []string{"df", "free", "ps", "ss"}

	for _, cmd := range requiredCmds {
		checkCmd := fmt.Sprintf("which %s", cmd)
		if _, err := dc.client.ExecuteCommand(checkCmd, false); err != nil {
			return fmt.Errorf("required command '%s' not found", cmd)
		}
	}

	// Check if we can use sudo if needed
	if dc.sudoPass != "" {
		if _, err := dc.client.ExecuteCommand("id", true); err != nil {
			return fmt.Errorf("sudo access verification failed")
		}
	}

	return nil
}

// collectAllDiagnostics collects all diagnostic information in parallel
func (dc *DiagnosticCollector) collectAllDiagnostics(report *SystemReport) error {
	var wg sync.WaitGroup
	errChan := make(chan error, 5)

	// Disk diagnostics
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := dc.collectDiskDiagnostics(report); err != nil {
			errChan <- fmt.Errorf("disk: %w", err)
		}
	}()

	// Memory diagnostics
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := dc.collectMemoryDiagnostics(report); err != nil {
			errChan <- fmt.Errorf("memory: %w", err)
		}
	}()

	// Service health
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := dc.collectServiceHealth(report); err != nil {
			errChan <- fmt.Errorf("services: %w", err)
		}
	}()

	// Log sizes
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := dc.collectLogInfo(report); err != nil {
			errChan <- fmt.Errorf("logs: %w", err)
		}
	}()

	// Process information
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := dc.collectProcessInfo(report); err != nil {
			errChan <- fmt.Errorf("processes: %w", err)
		}
	}()

	wg.Wait()
	close(errChan)

	// Check for errors
	var errors []string
	for err := range errChan {
		errors = append(errors, err.Error())
	}

	if len(errors) > 0 {
		return fmt.Errorf("multiple diagnostic failures: %s", strings.Join(errors, "; "))
	}

	return nil
}

// collectDiskDiagnostics gathers disk-related information
func (dc *DiagnosticCollector) collectDiskDiagnostics(report *SystemReport) error {
	// Get disk usage
	diskUsage, err := dc.getDiskUsage()
	if err != nil {
		return fmt.Errorf("failed to get disk usage: %w", err)
	}
	report.DiskUsage = diskUsage

	// Find large files
	largeFiles, err := dc.findLargeFiles()
	if err == nil {
		report.LargeFiles = largeFiles
	}

	// Find large directories
	largeDirs, err := dc.findLargeDirectories()
	if err == nil {
		report.LargeDirectories = largeDirs
	}

	// Check for deleted but open files
	deletedFiles, err := dc.findDeletedButOpenFiles()
	if err == nil {
		report.DeletedButOpenFiles = deletedFiles
	}

	return nil
}

// getDiskUsage retrieves disk usage information
func (dc *DiagnosticCollector) getDiskUsage() ([]DiskInfo, error) {
	// Get basic disk usage and inode usage
	dfCmd := "df -B1 && echo '---SEPARATOR---' && df -i"
	output, err := dc.client.ExecuteCommand(dfCmd, false)
	if err != nil {
		return nil, err
	}

	parts := strings.Split(output, "---SEPARATOR---")
	if len(parts) != 2 {
		return nil, fmt.Errorf("unexpected df output format")
	}

	return dc.parseDiskUsage(parts[0], parts[1]), nil
}

// parseDiskUsage parses df output
func (dc *DiagnosticCollector) parseDiskUsage(dfOutput, dfiOutput string) []DiskInfo {
	var disks []DiskInfo

	// Parse regular df output
	lines := strings.Split(dfOutput, "\n")
	dfMap := make(map[string]DiskInfo)

	for i, line := range lines {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}

		total, _ := strconv.ParseInt(fields[1], 10, 64)
		used, _ := strconv.ParseInt(fields[2], 10, 64)
		available, _ := strconv.ParseInt(fields[3], 10, 64)
		usePercent, _ := strconv.ParseFloat(strings.TrimSuffix(fields[4], "%"), 64)

		disk := DiskInfo{
			Mount:      fields[5],
			Total:      total,
			Used:       used,
			Available:  available,
			UsePercent: usePercent,
		}

		dfMap[disk.Mount] = disk
	}

	// Parse inode information
	lines = strings.Split(dfiOutput, "\n")
	for i, line := range lines {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}

		mount := fields[5]
		if disk, exists := dfMap[mount]; exists {
			disk.Inodes, _ = strconv.ParseInt(fields[1], 10, 64)
			disk.InodesUsed, _ = strconv.ParseInt(fields[2], 10, 64)
			if fields[4] != "-" {
				disk.InodesPercent, _ = strconv.ParseFloat(strings.TrimSuffix(fields[4], "%"), 64)
			}
			dfMap[mount] = disk
		}
	}

	// Convert map to slice
	for _, disk := range dfMap {
		disks = append(disks, disk)
	}

	return disks
}

// findLargeFiles locates files over 100MB
func (dc *DiagnosticCollector) findLargeFiles() ([]FileInfo, error) {
	cmd := `find / -type f -size +100M 2>/dev/null | head -50 | xargs -I {} sh -c 'ls -la "{}" | awk "{print \$5, \"{}\""}'`

	output, err := dc.client.ExecuteCommand(cmd, true)
	if err != nil {
		// Try without sudo
		output, err = dc.client.ExecuteCommand(cmd, false)
		if err != nil {
			return nil, err
		}
	}

	return dc.parseFileList(output), nil
}

// parseFileList parses file listing output
func (dc *DiagnosticCollector) parseFileList(output string) []FileInfo {
	var files []FileInfo

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			size, _ := strconv.ParseInt(fields[0], 10, 64)
			path := strings.Join(fields[1:], " ")

			files = append(files, FileInfo{
				Path: path,
				Size: size,
			})
		}
	}

	return files
}

// findLargeDirectories finds directories consuming the most space
func (dc *DiagnosticCollector) findLargeDirectories() (map[string]int64, error) {
	cmd := "du -b / 2>/dev/null | sort -rn | head -20"

	output, err := dc.client.ExecuteCommand(cmd, true)
	if err != nil {
		// Try specific directories without sudo
		cmd = "du -b /var /tmp /home 2>/dev/null | sort -rn | head -20"
		output, err = dc.client.ExecuteCommand(cmd, false)
		if err != nil {
			return nil, err
		}
	}

	dirs := make(map[string]int64)
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			size, _ := strconv.ParseInt(fields[0], 10, 64)
			path := strings.Join(fields[1:], " ")
			dirs[path] = size
		}
	}

	return dirs, nil
}

// findDeletedButOpenFiles finds files that are deleted but still held open
func (dc *DiagnosticCollector) findDeletedButOpenFiles() ([]FileInfo, error) {
	cmd := `lsof 2>/dev/null | grep deleted | awk '{print $7, $1, $2}' | sort -rn | head -20`

	output, err := dc.client.ExecuteCommand(cmd, true)
	if err != nil {
		return nil, err
	}

	var files []FileInfo
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			size, _ := strconv.ParseInt(fields[0], 10, 64)
			files = append(files, FileInfo{
				Path:    fmt.Sprintf("(deleted) held by %s", fields[1]),
				Size:    size,
				Process: fields[1],
				PID:     fields[2],
			})
		}
	}

	return files, nil
}

// collectMemoryDiagnostics gathers memory-related information
func (dc *DiagnosticCollector) collectMemoryDiagnostics(report *SystemReport) error {
	// Get memory info
	cmd := "free -b"
	output, err := dc.client.ExecuteCommand(cmd, false)
	if err != nil {
		return fmt.Errorf("failed to get memory info: %w", err)
	}

	// Parse memory info
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "Mem:") {
			fields := strings.Fields(line)
			if len(fields) >= 7 {
				total, _ := strconv.ParseInt(fields[1], 10, 64)
				used, _ := strconv.ParseInt(fields[2], 10, 64)
				available, _ := strconv.ParseInt(fields[6], 10, 64)

				report.MemoryUsage = MemoryInfo{
					Total:      total,
					Used:       used,
					Available:  available,
					UsePercent: float64(used) / float64(total) * 100,
				}
			}
		} else if strings.HasPrefix(line, "Swap:") {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				total, _ := strconv.ParseInt(fields[1], 10, 64)
				used, _ := strconv.ParseInt(fields[2], 10, 64)

				report.MemoryUsage.SwapTotal = total
				report.MemoryUsage.SwapUsed = used
				if total > 0 {
					report.MemoryUsage.SwapPercent = float64(used) / float64(total) * 100
				}
			}
		}
	}

	return nil
}

// collectServiceHealth checks critical services
func (dc *DiagnosticCollector) collectServiceHealth(report *SystemReport) error {
	services := []string{
		"ssh", "sshd",
		"systemd-logind",
		"systemd-resolved",
		"networking", "NetworkManager",
		"cron", "crond",
	}

	health := make(map[string]bool)

	for _, service := range services {
		cmd := fmt.Sprintf("systemctl is-active %s 2>/dev/null", service)
		output, err := dc.client.ExecuteCommand(cmd, false)
		health[service] = err == nil && strings.TrimSpace(output) == "active"
	}

	report.ServiceHealth = health
	return nil
}

// collectLogInfo gathers log file sizes
func (dc *DiagnosticCollector) collectLogInfo(report *SystemReport) error {
	// Get journal size
	journalCmd := "journalctl --disk-usage 2>/dev/null | grep -oP 'Archived and active journals take up \\K[0-9.]+[A-Z]'"
	journalOutput, err := dc.client.ExecuteCommand(journalCmd, true)
	if err == nil && journalOutput != "" {
		report.JournalSize = parseSize(strings.TrimSpace(journalOutput))
	}

	// Get log file sizes
	logCmd := `find /var/log -type f -name "*.log" -exec ls -la {} \; 2>/dev/null | awk '{sum+=$5; files[$9]=$5} END {for (f in files) print files[f], f}' | sort -rn | head -20`
	logOutput, err := dc.client.ExecuteCommand(logCmd, true)
	if err == nil {
		logSizes := make(map[string]int64)
		lines := strings.Split(logOutput, "\n")
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				size, _ := strconv.ParseInt(fields[0], 10, 64)
				path := strings.Join(fields[1:], " ")
				logSizes[path] = size
			}
		}
		report.LogSizes = logSizes
	}

	return nil
}

// collectProcessInfo gathers process information
func (dc *DiagnosticCollector) collectProcessInfo(report *SystemReport) error {
	// Get top processes by CPU and memory
	cmd := `ps aux --sort=-%cpu | head -10`
	output, err := dc.client.ExecuteCommand(cmd, false)
	if err != nil {
		return err
	}

	var processes []ProcessInfo
	lines := strings.Split(output, "\n")
	for i, line := range lines {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 11 {
			cpuPercent, _ := strconv.ParseFloat(fields[2], 64)
			memPercent, _ := strconv.ParseFloat(fields[3], 64)

			process := ProcessInfo{
				PID:        fields[1],
				User:       fields[0],
				CPUPercent: cpuPercent,
				MemPercent: memPercent,
				Command:    strings.Join(fields[10:], " "),
			}

			processes = append(processes, process)
		}
	}

	report.ProcessInfo = processes
	return nil
}

// collectNetworkDiagnostics gathers network information
func (dc *DiagnosticCollector) collectNetworkDiagnostics(report *SystemReport) error {
	// This is a placeholder - implement network diagnostics as needed
	return nil
}

// collectAuthDiagnostics gathers authentication information
func (dc *DiagnosticCollector) collectAuthDiagnostics(report *SystemReport) error {
	// This is a placeholder - implement auth diagnostics as needed
	return nil
}

// evaluateCollection verifies the diagnostic collection was successful
func (dc *DiagnosticCollector) evaluateCollection(report *SystemReport) error {
	// Verify we collected essential information
	if report.Hostname == "" {
		return fmt.Errorf("failed to retrieve hostname")
	}

	if len(report.DiskUsage) == 0 && report.MemoryUsage.Total == 0 {
		return fmt.Errorf("no system metrics collected")
	}

	return nil
}

// parseSize converts size strings like "1.5G" to bytes
func parseSize(sizeStr string) int64 {
	sizeStr = strings.TrimSpace(sizeStr)
	if sizeStr == "" {
		return 0
	}

	multipliers := map[string]int64{
		"B": 1,
		"K": 1024,
		"M": 1024 * 1024,
		"G": 1024 * 1024 * 1024,
		"T": 1024 * 1024 * 1024 * 1024,
	}

	for suffix, multiplier := range multipliers {
		if strings.HasSuffix(sizeStr, suffix) {
			numStr := strings.TrimSuffix(sizeStr, suffix)
			num, err := strconv.ParseFloat(numStr, 64)
			if err == nil {
				return int64(num * float64(multiplier))
			}
		}
	}

	// Try parsing as raw number
	num, _ := strconv.ParseInt(sizeStr, 10, 64)
	return num
}
