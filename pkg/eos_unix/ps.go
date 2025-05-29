// pkg/eos_unix/ps.go

package eos_unix

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

const hertz = 100.0 // Typically, this is 100 ticks per second; adjust for your system if necessary

// ProcessInfo holds details about a process
type ProcessInfo struct {
	PID        string
	Comm       string
	State      string
	Name       string
	User       string
	CPUPercent string
	MemPercent string
	RunTime    string
}

// GetProcessesDetails retrieves process information
func GetProcessDetails(ctx context.Context) ([]ProcessInfo, error) {

	otelzap.Ctx(ctx).Info("Reading processes from /proc directory")

	procDir := "/proc"
	files, err := os.ReadDir(procDir)
	if err != nil {
		otelzap.Ctx(ctx).Error("Failed to read /proc directory", zap.Error(err))
		return nil, fmt.Errorf("failed to read /proc directory: %w", err)
	}

	var processes []ProcessInfo
	uptime := GetSystemUptime(ctx)

	for _, file := range files {
		if file.IsDir() {
			pid := file.Name()
			if _, err := strconv.Atoi(pid); err == nil {
				process, err := ExtractProcessDetails(ctx, pid, uptime)
				if err != nil {
					otelzap.Ctx(ctx).Debug("Skipping process", zap.String("pid", pid), zap.Error(err))
					continue
				}
				processes = append(processes, process)

			}
		}
	}

	otelzap.Ctx(ctx).Info("Completed reading processes", zap.Int("processCount", len(processes)))
	return processes, nil
}

// ExtractProcessDetails extracts details about a specific process
func ExtractProcessDetails(ctx context.Context, pid string, uptime float64) (ProcessInfo, error) {

	otelzap.Ctx(ctx).Info("Extracting process details", zap.String("pid", pid))

	procDir := fmt.Sprintf("/proc/%s", pid)

	// Read /proc/[PID]/stat
	statPath := fmt.Sprintf("%s/stat", procDir)
	statContent, err := os.ReadFile(statPath)
	if err != nil {
		otelzap.Ctx(ctx).Warn("Unable to read stat file for process", zap.String("pid", pid), zap.Error(err))
		return ProcessInfo{}, err
	}

	fields := strings.Fields(string(statContent))
	comm := strings.Trim(fields[1], "()") // Command name without parentheses
	state := fields[2]                    // State
	startTime, _ := strconv.ParseFloat(fields[21], 64)

	// Calculate runtime
	runTime := fmt.Sprintf("%.2f seconds", uptime-(startTime/hertz))

	// Get process name
	processName := comm

	// Read /proc/[PID]/status to get user info
	statusPath := fmt.Sprintf("%s/status", procDir)
	statusContent, err := os.ReadFile(statusPath)
	userName := "unknown"
	if err == nil {
		for _, line := range strings.Split(string(statusContent), "\n") {
			if strings.HasPrefix(line, "Uid:") {
				uid := strings.Fields(line)[1]
				if user, err := user.LookupId(uid); err == nil {
					userName = user.Username
				}
				break
			}
		}
	} else {
		otelzap.Ctx(ctx).Warn("Unable to read status file", zap.String("pid", pid), zap.Error(err))
	}

	// Get CPU and memory usage
	cpuPercent, _ := GetCPUPercent(ctx, pid)
	memPercent, _ := GetMemoryPercent(ctx, pid)

	otelzap.Ctx(ctx).Info("Successfully extracted process details", zap.String("pid", pid), zap.String("user", userName))
	return ProcessInfo{
		PID:        pid,
		Comm:       comm,
		State:      state,
		Name:       processName,
		User:       userName,
		CPUPercent: cpuPercent,
		MemPercent: memPercent,
		RunTime:    runTime,
	}, nil
}

func GetCPUPercent(ctx context.Context, pid string) (string, error) {

	statPath := fmt.Sprintf("/proc/%s/stat", pid)
	data, err := os.ReadFile(statPath)
	if err != nil {
		otelzap.Ctx(ctx).Warn("Unable to read stat file for CPU usage", zap.String("pid", pid), zap.Error(err))
		return "Err", nil // Return "Err" if process is not accessible
	}

	fields := strings.Fields(string(data))
	utime, _ := strconv.ParseFloat(fields[13], 64) // Field 13
	stime, _ := strconv.ParseFloat(fields[14], 64) // Field 14

	// Get system uptime and total CPU time
	uptimeData, err := os.ReadFile("/proc/uptime")
	if err != nil {
		otelzap.Ctx(ctx).Warn("Unable to read uptime file for CPU calculation; using fallback", zap.Error(err))
		return "0.0", nil
	}
	uptimeFields := strings.Fields(string(uptimeData))
	uptime, _ := strconv.ParseFloat(uptimeFields[0], 64)

	totalCPU := uptime * hertz // Total CPU time
	processCPU := (utime + stime) / totalCPU * 100.0
	cpuPercent := fmt.Sprintf("%.2f", processCPU)

	otelzap.Ctx(ctx).Info("Calculated CPU usage", zap.String("pid", pid), zap.String("cpuPercent", cpuPercent))
	return cpuPercent, nil
}

func GetMemoryPercent(ctx context.Context, pid string) (string, error) {

	statusPath := fmt.Sprintf("/proc/%s/status", pid)
	data, err := os.ReadFile(statusPath)
	if err != nil {
		otelzap.Ctx(ctx).Warn("Unable to read status file for memory usage", zap.String("pid", pid), zap.Error(err))
		return "Err", nil // Return 0.0 if process is not accessible
	}

	var memUsage float64
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			memUsage, _ = strconv.ParseFloat(fields[1], 64) // VmRSS in kB
			break
		}
	}

	memInfo, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		otelzap.Ctx(ctx).Warn("Unable to read /proc/meminfo for memory calculation", zap.Error(err))
		return "Err", nil
	}

	totalMem := 0.0
	memLines := strings.Split(string(memInfo), "\n")
	for _, line := range memLines {
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			totalMem, _ = strconv.ParseFloat(fields[1], 64) // MemTotal in kB
			break
		}
	}

	// Add the block to handle zero or undefined total memory
	if totalMem <= 0 {
		otelzap.Ctx(ctx).Warn("Total memory is zero or undefined; returning 0% for memory usage", zap.String("pid", pid))
		return "0.0", nil
	}

	memPercent := "0.0"
	if totalMem > 0 {
		memPercent = fmt.Sprintf("%.2f", (memUsage/totalMem)*100.0)
	}

	otelzap.Ctx(ctx).Info("Calculated memory usage", zap.String("pid", pid), zap.String("memPercent", memPercent))
	return memPercent, nil
}

// GetSystemUptime retrieves the system uptime
func GetSystemUptime(ctx context.Context) float64 {

	uptimeFile := "/proc/uptime"
	content, err := os.ReadFile(uptimeFile)
	if err != nil {
		otelzap.Ctx(ctx).Warn("Unable to read uptime file", zap.Error(err))
		return 0.0
	}
	uptime, _ := strconv.ParseFloat(strings.Fields(string(content))[0], 64)
	return uptime
}

/* PrintProcessTable prints the process information in a table format */
func PrintProcessTable(ctx context.Context, process []ProcessInfo) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', tabwriter.Debug)

	// Write table header
	if _, err := fmt.Fprintln(w, "PID\tComm\tState\tName\tUser\tCPU%\tMemory%\tRunning Time"); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing header: %v\n", err)
		return
	}
	if _, err := fmt.Fprintln(w, "----\t----\t----\t----\t----\t----\t----\t----"); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing header divider: %v\n", err)
		return
	}

	// Write each process's data in a formatted row.
	for _, proc := range process {
		if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			proc.PID, proc.Comm, proc.State, proc.Name, proc.User, proc.CPUPercent, proc.MemPercent, proc.RunTime); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing process info: %v\n", err)
			return
		}
	}

	// Flush the writer and check for errors.
	if err := w.Flush(); err != nil {
		fmt.Fprintf(os.Stderr, "Error flushing tabwriter: %v\n", err)
	}
}
