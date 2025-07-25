// pkg/watchdog/resource_watchdog_enhanced.go

package watchdog

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"runtime/pprof"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"
	"go.uber.org/zap"
)

// ResourceWatchdog monitors system resources and takes action when limits are exceeded
type ResourceWatchdog struct {
	ctx            context.Context
	logger         *zap.Logger
	config         ResourceConfig
	mu             sync.Mutex
	processTracker map[int32]*ProcessInfo
	actionTaken    bool
	startTime      time.Time
	
	// Enhanced tracing
	traceLogger    *TraceLogger
	lastStatus     ResourceStatus
	warningCount   int
	criticalCount  int
}

// TraceLogger handles multi-destination logging with progressive detail
type TraceLogger struct {
	baseDir        string
	sessionID      string
	terminalWriter io.Writer
	fileWriters    map[string]*bufio.Writer
	mu             sync.Mutex
}

// ResourceConfig configures resource monitoring thresholds and actions
type ResourceConfig struct {
	// CPU thresholds (percentage)
	CPUWarningThreshold  float64 // Default: 70%
	CPUCriticalThreshold float64 // Default: 90%

	// Memory thresholds (percentage)
	MemWarningThreshold  float64 // Default: 70%
	MemCriticalThreshold float64 // Default: 85%

	// Process count thresholds
	MaxEosProcesses   int // Default: 10
	MaxTotalProcesses int // Default: 50

	// Monitoring intervals
	CheckInterval     time.Duration // Default: 1 second
	SustainedDuration time.Duration // Default: 3 seconds

	// Tracing configuration
	TraceBaseDir         string // Default: /var/log/eos/watchdog
	EnableTerminalOutput bool   // Default: true
	VerboseLogging       bool   // Default: false
	CaptureSystemInfo    bool   // Default: true

	// Actions
	EnableTracing     bool // Default: true
	EnableKillProcess bool // Default: true
	TracePath         string // Deprecated: use TraceBaseDir
}

// ProcessInfo contains information about a running process
type ProcessInfo struct {
	PID         int32
	Name        string
	CPUPercent  float64
	MemoryMB    float64
	CreateTime  time.Time
	CommandLine string
}

// ResourceStatus contains the current state of system resources
type ResourceStatus struct {
	CPUPercent      float64
	MemoryPercent   float64
	MemoryUsedMB    float64
	MemoryTotalMB   float64
	EosProcessCount int
	TotalProcesses  int
	TopProcesses    []ProcessInfo
	IsWarning       bool
	IsCritical      bool
	Reason          string
	CheckTime       time.Time
}

// DefaultResourceConfig returns sensible defaults
func DefaultResourceConfig() ResourceConfig {
	baseDir := "/var/log/eos/watchdog"
	if home := os.Getenv("HOME"); home != "" && os.Getuid() != 0 {
		// Use user's home directory if not running as root
		baseDir = filepath.Join(home, ".eos", "watchdog")
	}
	
	return ResourceConfig{
		CPUWarningThreshold:  70.0,
		CPUCriticalThreshold: 90.0,
		MemWarningThreshold:  70.0,
		MemCriticalThreshold: 85.0,
		MaxEosProcesses:      10,
		MaxTotalProcesses:    50,
		CheckInterval:        1 * time.Second,
		SustainedDuration:    3 * time.Second,
		TraceBaseDir:         baseDir,
		EnableTerminalOutput: true,
		VerboseLogging:       os.Getenv("EOS_VERBOSE") == "1",
		CaptureSystemInfo:    true,
		EnableTracing:        true,
		EnableKillProcess:    true,
		TracePath:            "/tmp/eos-trace", // Deprecated
	}
}

// NewResourceWatchdog creates a new resource watchdog
func NewResourceWatchdog(ctx context.Context, logger *zap.Logger, config ResourceConfig) *ResourceWatchdog {
	sessionID := fmt.Sprintf("eos-watchdog-%s", time.Now().Format("20060102-150405"))
	
	// Create trace logger that writes to both file and terminal
	var traceLogger *TraceLogger
	if config.EnableTracing {
		traceLogger = &TraceLogger{
			baseDir:        config.TraceBaseDir,
			sessionID:      sessionID,
			terminalWriter: os.Stdout,
			fileWriters:    make(map[string]*bufio.Writer),
		}
		
		// Initialize trace directory structure
		if err := traceLogger.Initialize(); err != nil {
			logger.Error("Failed to initialize trace logger", zap.Error(err))
		}
	}
	
	return &ResourceWatchdog{
		ctx:            ctx,
		logger:         logger,
		config:         config,
		processTracker: make(map[int32]*ProcessInfo),
		startTime:      time.Now(),
		traceLogger:    traceLogger,
	}
}

// Initialize creates the directory structure for traces
func (tl *TraceLogger) Initialize() error {
	tl.mu.Lock()
	defer tl.mu.Unlock()
	
	// Create session directory
	sessionDir := filepath.Join(tl.baseDir, tl.sessionID)
	if err := os.MkdirAll(sessionDir, 0755); err != nil {
		return fmt.Errorf("failed to create session directory: %w", err)
	}
	
	// Create subdirectories for different trace types
	traceDirs := []string{"system", "processes", "profiles", "logs"}
	for _, dir := range traceDirs {
		if err := os.MkdirAll(filepath.Join(sessionDir, dir), 0755); err != nil {
			return fmt.Errorf("failed to create %s directory: %w", dir, err)
		}
	}
	
	// Create main log file
	mainLogPath := filepath.Join(sessionDir, "watchdog.log")
	mainLogFile, err := os.Create(mainLogPath)
	if err != nil {
		return fmt.Errorf("failed to create main log file: %w", err)
	}
	
	tl.fileWriters["main"] = bufio.NewWriter(mainLogFile)
	
	// Write session header
	tl.writeToAll("=== EOS Resource Watchdog Session Started ===\n")
	tl.writeToAll(fmt.Sprintf("Session ID: %s\n", tl.sessionID))
	tl.writeToAll(fmt.Sprintf("Start Time: %s\n", time.Now().Format(time.RFC3339)))
	tl.writeToAll(fmt.Sprintf("Log Directory: %s\n\n", sessionDir))
	
	return nil
}

// writeToAll writes to both terminal and file
func (tl *TraceLogger) writeToAll(format string, args ...interface{}) {
	if tl == nil {
		return
	}
	
	tl.mu.Lock()
	defer tl.mu.Unlock()
	
	message := fmt.Sprintf(format, args...)
	timestamp := time.Now().Format("15:04:05.000")
	
	// Format for terminal (with color codes for different levels)
	terminalMsg := fmt.Sprintf("[%s] %s", timestamp, message)
	if strings.Contains(message, "CRITICAL") {
		terminalMsg = fmt.Sprintf("\033[31m%s\033[0m", terminalMsg) // Red
	} else if strings.Contains(message, "WARNING") {
		terminalMsg = fmt.Sprintf("\033[33m%s\033[0m", terminalMsg) // Yellow
	}
	
	// Write to terminal
	if tl.terminalWriter != nil {
		fmt.Fprint(tl.terminalWriter, terminalMsg)
	}
	
	// Write to main log file
	if writer, ok := tl.fileWriters["main"]; ok {
		writer.WriteString(fmt.Sprintf("[%s] %s", timestamp, message))
		writer.Flush()
	}
}

// Start begins monitoring resources
func (rw *ResourceWatchdog) Start() {
	if rw.traceLogger != nil {
		rw.traceLogger.writeToAll("Starting resource monitoring with thresholds:\n")
		rw.traceLogger.writeToAll("  CPU Warning: %.1f%%, Critical: %.1f%%\n", 
			rw.config.CPUWarningThreshold, rw.config.CPUCriticalThreshold)
		rw.traceLogger.writeToAll("  Memory Warning: %.1f%%, Critical: %.1f%%\n",
			rw.config.MemWarningThreshold, rw.config.MemCriticalThreshold)
		rw.traceLogger.writeToAll("  Max EOS Processes: %d\n\n", rw.config.MaxEosProcesses)
	}
	
	go rw.monitorLoop()
}

func (rw *ResourceWatchdog) monitorLoop() {
	ticker := time.NewTicker(rw.config.CheckInterval)
	defer ticker.Stop()

	var sustainedCriticalCount int

	for {
		select {
		case <-rw.ctx.Done():
			if rw.traceLogger != nil {
				rw.traceLogger.writeToAll("Monitoring stopped: context cancelled\n")
			}
			return
		case <-ticker.C:
			status := rw.checkResources()

			// Track sustained critical conditions
			if status.IsCritical {
				sustainedCriticalCount++
				rw.criticalCount++
				
				// Log critical status
				if rw.traceLogger != nil {
					rw.handleCriticalStatus(status)
				}
				
				// Check if we need to take action
				sustainedSeconds := sustainedCriticalCount * int(rw.config.CheckInterval.Seconds())
				if sustainedSeconds >= int(rw.config.SustainedDuration.Seconds()) {
					rw.handleCriticalCondition(status)
					sustainedCriticalCount = 0
				}
			} else {
				sustainedCriticalCount = 0
				
				// Handle warning or normal status
				if status.IsWarning {
					rw.warningCount++
					rw.criticalCount = 0
					if rw.traceLogger != nil {
						rw.handleWarningStatus(status)
					}
				} else if rw.config.VerboseLogging && rw.traceLogger != nil {
					// Log normal status periodically in verbose mode
					if time.Since(rw.startTime).Seconds() > 0 && 
					   int(time.Since(rw.startTime).Seconds())%10 == 0 {
						rw.handleNormalStatus(status)
					}
				}
			}

			// Always log warnings
			if status.IsWarning {
				rw.logWarning(status)
			}
			
			rw.lastStatus = status
		}
	}
}

// handleNormalStatus logs basic information during normal operation
func (rw *ResourceWatchdog) handleNormalStatus(status ResourceStatus) {
	if rw.traceLogger == nil {
		return
	}
	
	// Only log to file in normal status to avoid terminal spam
	sessionDir := filepath.Join(rw.traceLogger.baseDir, rw.traceLogger.sessionID)
	normalLog := filepath.Join(sessionDir, "logs", "normal.log")
	
	f, err := os.OpenFile(normalLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		defer f.Close()
		fmt.Fprintf(f, "[%s] CPU: %.1f%%, Mem: %.1f%%, EOS Procs: %d\n",
			time.Now().Format("15:04:05"),
			status.CPUPercent,
			status.MemoryPercent,
			status.EosProcessCount)
	}
}

// handleWarningStatus provides detailed logging at warning level
func (rw *ResourceWatchdog) handleWarningStatus(status ResourceStatus) {
	if rw.traceLogger == nil {
		return
	}
	
	rw.traceLogger.writeToAll("WARNING: Resource usage elevated - %s\n", status.Reason)
	rw.traceLogger.writeToAll("  CPU: %.1f%% | Memory: %.1f%% | EOS Processes: %d\n",
		status.CPUPercent, status.MemoryPercent, status.EosProcessCount)
	
	// Capture warning-level traces
	sessionDir := filepath.Join(rw.traceLogger.baseDir, rw.traceLogger.sessionID)
	warningDir := filepath.Join(sessionDir, fmt.Sprintf("warning-%03d", rw.warningCount))
	os.MkdirAll(warningDir, 0755)
	
	// Write process list
	rw.writeProcessList(warningDir, status)
	
	// Write system info if this is the first warning
	if rw.warningCount == 1 && rw.config.CaptureSystemInfo {
		rw.captureSystemInfo(sessionDir)
	}
	
	// Log top consumers to terminal
	rw.traceLogger.writeToAll("\nTop EOS Processes:\n")
	for i, proc := range status.TopProcesses[:min(3, len(status.TopProcesses))] {
		rw.traceLogger.writeToAll("  %d. PID %d: CPU %.1f%%, Mem %.1fMB - %s\n",
			i+1, proc.PID, proc.CPUPercent, proc.MemoryMB, proc.Name)
	}
	rw.traceLogger.writeToAll("\n")
}

// handleCriticalStatus logs critical status (called on each check during critical state)
func (rw *ResourceWatchdog) handleCriticalStatus(status ResourceStatus) {
	if rw.traceLogger == nil {
		return
	}
	
	// Calculate how many more checks until action
	currentCount := rw.criticalCount
	neededCount := int(rw.config.SustainedDuration / rw.config.CheckInterval)
	
	rw.traceLogger.writeToAll("CRITICAL: Resource usage critical - %s (count: %d/%d)\n",
		status.Reason, currentCount, neededCount)
}

func (rw *ResourceWatchdog) handleCriticalCondition(status ResourceStatus) {
	rw.mu.Lock()
	defer rw.mu.Unlock()

	if rw.actionTaken {
		return // Don't take action twice
	}

	rw.logger.Error("CRITICAL: Resource limits exceeded",
		zap.String("reason", status.Reason),
		zap.Float64("cpu_percent", status.CPUPercent),
		zap.Float64("memory_percent", status.MemoryPercent),
		zap.Int("eos_processes", status.EosProcessCount))

	// Enhanced tracing for critical conditions
	if rw.traceLogger != nil {
		rw.traceLogger.writeToAll("\n!!! CRITICAL RESOURCE EXHAUSTION DETECTED !!!\n")
		rw.traceLogger.writeToAll("Taking emergency action to prevent system failure\n\n")
		
		// Create critical trace directory
		sessionDir := filepath.Join(rw.traceLogger.baseDir, rw.traceLogger.sessionID)
		criticalDir := filepath.Join(sessionDir, "critical")
		os.MkdirAll(criticalDir, 0755)
		
		// Capture everything we can
		rw.captureCriticalDiagnostics(criticalDir, status)
		
		rw.traceLogger.writeToAll("\n=== Critical diagnostics captured to: %s ===\n", criticalDir)
	} else if rw.config.EnableTracing {
		// Legacy trace capture for backward compatibility
		rw.captureTrace(status)
	}

	// Step 2: Kill excessive processes if enabled
	if rw.config.EnableKillProcess && status.EosProcessCount > rw.config.MaxEosProcesses {
		rw.killExcessiveProcesses(status.TopProcesses)
	}

	rw.actionTaken = true
}

// captureCriticalDiagnostics captures comprehensive system state
func (rw *ResourceWatchdog) captureCriticalDiagnostics(dir string, status ResourceStatus) {
	if rw.traceLogger == nil {
		return
	}
	
	rw.traceLogger.writeToAll("Capturing critical diagnostics...\n")
	
	// 1. Detailed process information
	rw.traceLogger.writeToAll("  - Process details...")
	rw.captureDetailedProcessInfo(dir, status)
	rw.traceLogger.writeToAll(" ✓\n")
	
	// 2. System command outputs
	rw.traceLogger.writeToAll("  - System commands...")
	rw.captureSystemCommands(dir)
	rw.traceLogger.writeToAll(" ✓\n")
	
	// 3. Go runtime profiles
	rw.traceLogger.writeToAll("  - Runtime profiles...")
	rw.captureRuntimeProfiles(dir)
	rw.traceLogger.writeToAll(" ✓\n")
	
	// 4. Network connections
	rw.traceLogger.writeToAll("  - Network state...")
	rw.captureNetworkState(dir)
	rw.traceLogger.writeToAll(" ✓\n")
	
	// 5. Disk usage
	rw.traceLogger.writeToAll("  - Disk usage...")
	rw.captureDiskUsage(dir)
	rw.traceLogger.writeToAll(" ✓\n")
}

// captureDetailedProcessInfo writes comprehensive process information
func (rw *ResourceWatchdog) captureDetailedProcessInfo(dir string, status ResourceStatus) {
	processFile := filepath.Join(dir, "processes-detailed.txt")
	f, err := os.Create(processFile)
	if err != nil {
		return
	}
	defer f.Close()
	
	fmt.Fprintf(f, "=== Process Information at Critical State ===\n")
	fmt.Fprintf(f, "Time: %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(f, "Total Processes: %d\n", status.TotalProcesses)
	fmt.Fprintf(f, "EOS Processes: %d\n\n", status.EosProcessCount)
	
	// For each EOS process, get detailed information
	for _, proc := range status.TopProcesses {
		fmt.Fprintf(f, "--- Process PID %d ---\n", proc.PID)
		fmt.Fprintf(f, "Name: %s\n", proc.Name)
		fmt.Fprintf(f, "Command: %s\n", proc.CommandLine)
		fmt.Fprintf(f, "CPU: %.2f%%\n", proc.CPUPercent)
		fmt.Fprintf(f, "Memory: %.2f MB (RSS)\n", proc.MemoryMB)
		fmt.Fprintf(f, "Created: %s (%.0f seconds ago)\n", 
			proc.CreateTime.Format(time.RFC3339),
			time.Since(proc.CreateTime).Seconds())
		
		// Try to get parent process info
		if p, err := process.NewProcess(proc.PID); err == nil {
			if ppid, err := p.Ppid(); err == nil {
				if parent, err := process.NewProcess(ppid); err == nil {
					if pname, err := parent.Name(); err == nil {
						fmt.Fprintf(f, "Parent: PID %d (%s)\n", ppid, pname)
					}
				}
			}
			
			// Get open files if possible
			if files, err := p.OpenFiles(); err == nil && len(files) > 0 {
				fmt.Fprintf(f, "Open Files (%d):\n", len(files))
				for i, file := range files[:min(10, len(files))] {
					fmt.Fprintf(f, "  %d. %s\n", i+1, file.Path)
				}
			}
			
			// Get connections
			if conns, err := p.Connections(); err == nil && len(conns) > 0 {
				fmt.Fprintf(f, "Connections (%d):\n", len(conns))
				for i, conn := range conns[:min(5, len(conns))] {
					fmt.Fprintf(f, "  %d. %s:%d -> %s:%d\n", i+1,
						conn.Laddr.IP, conn.Laddr.Port,
						conn.Raddr.IP, conn.Raddr.Port)
				}
			}
		}
		fmt.Fprintf(f, "\n")
	}
}

// captureSystemCommands runs diagnostic commands
func (rw *ResourceWatchdog) captureSystemCommands(dir string) {
	commands := []struct {
		name string
		cmd  []string
	}{
		{"ps-tree", []string{"ps", "auxf"}},
		{"ps-eos", []string{"bash", "-c", "ps aux | grep eos"}},
		{"lsof-eos", []string{"lsof", "-p", fmt.Sprintf("%d", os.Getpid())}},
		{"netstat", []string{"netstat", "-tlpn"}},
		{"systemctl-eos", []string{"bash", "-c", "systemctl status eos* 2>/dev/null || true"}},
		{"journalctl", []string{"journalctl", "-u", "eos*", "--since", "10 minutes ago", "--no-pager"}},
	}
	
	for _, cmd := range commands {
		outputFile := filepath.Join(dir, fmt.Sprintf("%s.txt", cmd.name))
		output, _ := exec.Command(cmd.cmd[0], cmd.cmd[1:]...).Output()
		os.WriteFile(outputFile, output, 0644)
	}
}

// captureRuntimeProfiles captures Go runtime diagnostics
func (rw *ResourceWatchdog) captureRuntimeProfiles(dir string) {
	// CPU profile (2 seconds)
	cpuFile, err := os.Create(filepath.Join(dir, "cpu.prof"))
	if err == nil {
		if err := pprof.StartCPUProfile(cpuFile); err == nil {
			time.Sleep(2 * time.Second)
			pprof.StopCPUProfile()
		}
		cpuFile.Close()
	}
	
	// Memory profile
	memFile, err := os.Create(filepath.Join(dir, "mem.prof"))
	if err == nil {
		runtime.GC()
		pprof.WriteHeapProfile(memFile)
		memFile.Close()
	}
	
	// Goroutine profile
	goroutineFile, err := os.Create(filepath.Join(dir, "goroutines.txt"))
	if err == nil {
		pprof.Lookup("goroutine").WriteTo(goroutineFile, 2)
		goroutineFile.Close()
	}
	
	// Stack trace
	stackFile, err := os.Create(filepath.Join(dir, "stack.txt"))
	if err == nil {
		stackFile.Write(debug.Stack())
		stackFile.Close()
	}
}

// captureNetworkState records network connections
func (rw *ResourceWatchdog) captureNetworkState(dir string) {
	netFile := filepath.Join(dir, "network.txt")
	f, err := os.Create(netFile)
	if err != nil {
		return
	}
	defer f.Close()
	
	fmt.Fprintf(f, "=== Network State ===\n")
	fmt.Fprintf(f, "Time: %s\n\n", time.Now().Format(time.RFC3339))
	
	// Get all connections
	connections, err := net.Connections("all")
	if err == nil {
		// Group by state
		byState := make(map[string]int)
		for _, conn := range connections {
			byState[conn.Status]++
		}
		
		fmt.Fprintf(f, "Connection Summary:\n")
		for state, count := range byState {
			fmt.Fprintf(f, "  %s: %d\n", state, count)
		}
		fmt.Fprintf(f, "\n")
		
		// List EOS-related connections
		fmt.Fprintf(f, "EOS Process Connections:\n")
		for _, proc := range rw.lastStatus.TopProcesses {
			if p, err := process.NewProcess(proc.PID); err == nil {
				if conns, err := p.Connections(); err == nil {
					fmt.Fprintf(f, "\nPID %d (%s):\n", proc.PID, proc.Name)
					for _, conn := range conns {
						fmt.Fprintf(f, "  %s %s:%d -> %s:%d\n",
							conn.Type, conn.Laddr.IP, conn.Laddr.Port,
							conn.Raddr.IP, conn.Raddr.Port)
					}
				}
			}
		}
	}
}

// captureDiskUsage records disk usage information
func (rw *ResourceWatchdog) captureDiskUsage(dir string) {
	diskFile := filepath.Join(dir, "disk-usage.txt")
	f, err := os.Create(diskFile)
	if err != nil {
		return
	}
	defer f.Close()
	
	fmt.Fprintf(f, "=== Disk Usage ===\n")
	fmt.Fprintf(f, "Time: %s\n\n", time.Now().Format(time.RFC3339))
	
	// Get disk partitions
	partitions, err := disk.Partitions(false)
	if err == nil {
		for _, partition := range partitions {
			usage, err := disk.Usage(partition.Mountpoint)
			if err == nil {
				fmt.Fprintf(f, "Mount: %s\n", partition.Mountpoint)
				fmt.Fprintf(f, "  Device: %s\n", partition.Device)
				fmt.Fprintf(f, "  Filesystem: %s\n", partition.Fstype)
				fmt.Fprintf(f, "  Total: %.2f GB\n", float64(usage.Total)/1024/1024/1024)
				fmt.Fprintf(f, "  Used: %.2f GB (%.1f%%)\n", 
					float64(usage.Used)/1024/1024/1024, usage.UsedPercent)
				fmt.Fprintf(f, "  Free: %.2f GB\n\n", float64(usage.Free)/1024/1024/1024)
			}
		}
	}
}

// Helper functions for process management
func (rw *ResourceWatchdog) writeProcessList(dir string, status ResourceStatus) {
	processFile := filepath.Join(dir, "processes.txt")
	f, err := os.Create(processFile)
	if err != nil {
		return
	}
	defer f.Close()
	
	fmt.Fprintf(f, "=== Process Snapshot ===\n")
	fmt.Fprintf(f, "Time: %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(f, "CPU: %.1f%%, Memory: %.1f%%\n", status.CPUPercent, status.MemoryPercent)
	fmt.Fprintf(f, "Total Processes: %d, EOS Processes: %d\n\n", 
		status.TotalProcesses, status.EosProcessCount)
	
	for i, proc := range status.TopProcesses {
		fmt.Fprintf(f, "%d. PID %d: %s\n", i+1, proc.PID, proc.Name)
		fmt.Fprintf(f, "   CPU: %.1f%%, Memory: %.1fMB\n", proc.CPUPercent, proc.MemoryMB)
		fmt.Fprintf(f, "   Command: %s\n\n", proc.CommandLine)
	}
}

// captureSystemInfo captures basic system information once
func (rw *ResourceWatchdog) captureSystemInfo(sessionDir string) {
	sysInfoFile := filepath.Join(sessionDir, "system", "info.txt")
	f, err := os.Create(sysInfoFile)
	if err != nil {
		return
	}
	defer f.Close()
	
	fmt.Fprintf(f, "=== System Information ===\n")
	fmt.Fprintf(f, "Capture Time: %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(f, "Hostname: %s\n", func() string {
		if h, err := os.Hostname(); err == nil {
			return h
		}
		return "unknown"
	}())
	fmt.Fprintf(f, "OS: %s %s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Fprintf(f, "Go Version: %s\n", runtime.Version())
	fmt.Fprintf(f, "NumCPU: %d\n", runtime.NumCPU())
	fmt.Fprintf(f, "GOMAXPROCS: %d\n", runtime.GOMAXPROCS(0))
	
	// Memory info
	if memInfo, err := mem.VirtualMemory(); err == nil {
		fmt.Fprintf(f, "\nMemory:\n")
		fmt.Fprintf(f, "  Total: %.2f GB\n", float64(memInfo.Total)/1024/1024/1024)
		fmt.Fprintf(f, "  Available: %.2f GB\n", float64(memInfo.Available)/1024/1024/1024)
		fmt.Fprintf(f, "  Used: %.2f GB (%.1f%%)\n", 
			float64(memInfo.Used)/1024/1024/1024, memInfo.UsedPercent)
	}
}

// Legacy captureTrace method for backward compatibility
func (rw *ResourceWatchdog) captureTrace(status ResourceStatus) {
	timestamp := time.Now().Format("20060102-150405")
	traceDir := fmt.Sprintf("%s/%s", rw.config.TracePath, timestamp)

	if err := os.MkdirAll(traceDir, 0755); err != nil {
		rw.logger.Error("Failed to create trace directory", zap.Error(err))
		return
	}

	// Capture CPU profile
	cpuFile, err := os.Create(fmt.Sprintf("%s/cpu.prof", traceDir))
	if err == nil {
		if err := pprof.StartCPUProfile(cpuFile); err == nil {
			time.Sleep(2 * time.Second)
			pprof.StopCPUProfile()
		}
		cpuFile.Close()
	}

	// Capture memory profile
	memFile, err := os.Create(fmt.Sprintf("%s/mem.prof", traceDir))
	if err == nil {
		runtime.GC()
		if err := pprof.WriteHeapProfile(memFile); err != nil {
			rw.logger.Error("Failed to write heap profile", zap.Error(err))
		}
		memFile.Close()
	}

	// Capture goroutine dump
	goroutineFile, err := os.Create(fmt.Sprintf("%s/goroutines.txt", traceDir))
	if err == nil {
		if err := pprof.Lookup("goroutine").WriteTo(goroutineFile, 2); err != nil {
			rw.logger.Error("Failed to write goroutine profile", zap.Error(err))
		}
		goroutineFile.Close()
	}

	// Capture process tree
	processFile, err := os.Create(fmt.Sprintf("%s/processes.txt", traceDir))
	if err == nil {
		for _, p := range status.TopProcesses {
			fmt.Fprintf(processFile, "PID: %d, Name: %s, CPU: %.2f%%, Mem: %.2fMB, Created: %s, Cmd: %s\n",
				p.PID, p.Name, p.CPUPercent, p.MemoryMB, p.CreateTime.Format(time.RFC3339), p.CommandLine)
		}
		processFile.Close()
	}

	// Capture stack trace
	stackFile, err := os.Create(fmt.Sprintf("%s/stack.txt", traceDir))
	if err == nil {
		stackFile.Write(debug.Stack())
		stackFile.Close()
	}

	rw.logger.Info("Diagnostic trace captured", zap.String("path", traceDir))
}

func (rw *ResourceWatchdog) logWarning(status ResourceStatus) {
	rw.logger.Warn("Resource usage warning",
		zap.String("reason", status.Reason),
		zap.Float64("cpu_percent", status.CPUPercent),
		zap.Float64("memory_percent", status.MemoryPercent),
		zap.Int("eos_processes", status.EosProcessCount))
}

func (rw *ResourceWatchdog) killExcessiveProcesses(processes []ProcessInfo) {
	// Sort by creation time (kill newest first)
	// This preserves the original bootstrap process
	sort.Slice(processes, func(i, j int) bool {
		return processes[i].CreateTime.After(processes[j].CreateTime)
	})

	toKill := len(processes) - rw.config.MaxEosProcesses
	if toKill <= 0 {
		return
	}

	rw.logger.Warn("Killing excessive eos processes",
		zap.Int("to_kill", toKill),
		zap.Int("total", len(processes)))

	for i := 0; i < toKill && i < len(processes); i++ {
		p := processes[i]
		if proc, err := process.NewProcess(p.PID); err == nil {
			rw.logger.Info("Terminating process",
				zap.Int32("pid", p.PID),
				zap.String("cmd", p.CommandLine))

			// Try graceful termination first
			if err := proc.Terminate(); err != nil {
				rw.logger.Error("Failed to terminate process", zap.Error(err))
			}
			time.Sleep(2 * time.Second)

			// Force kill if still running
			if running, _ := proc.IsRunning(); running {
				if err := proc.Kill(); err != nil {
					rw.logger.Error("Failed to kill process", zap.Error(err))
				}
			}
		}
	}
}

func (rw *ResourceWatchdog) checkResources() ResourceStatus {
	status := ResourceStatus{
		CheckTime: time.Now(),
	}

	// Check CPU usage
	cpuPercent, err := cpu.Percent(100*time.Millisecond, false)
	if err == nil && len(cpuPercent) > 0 {
		status.CPUPercent = cpuPercent[0]
	}

	// Check memory usage
	memInfo, err := mem.VirtualMemory()
	if err == nil {
		status.MemoryPercent = memInfo.UsedPercent
		status.MemoryUsedMB = float64(memInfo.Used) / 1024 / 1024
		status.MemoryTotalMB = float64(memInfo.Total) / 1024 / 1024
	}

	// Count processes and gather info
	processes, _ := process.Processes()
	var eosProcesses []ProcessInfo

	for _, p := range processes {
		name, _ := p.Name()
		cmdline, _ := p.Cmdline()
		
		if strings.Contains(name, "eos") || strings.Contains(cmdline, "eos") {
			cpuP, _ := p.CPUPercent()
			memInfo, _ := p.MemoryInfo()
			createTime, _ := p.CreateTime()

			info := ProcessInfo{
				PID:         p.Pid,
				Name:        name,
				CPUPercent:  cpuP,
				MemoryMB:    float64(memInfo.RSS) / 1024 / 1024,
				CreateTime:  time.Unix(createTime/1000, 0),
				CommandLine: cmdline,
			}

			eosProcesses = append(eosProcesses, info)
		}
	}

	status.EosProcessCount = len(eosProcesses)
	status.TotalProcesses = len(processes)
	status.TopProcesses = eosProcesses

	// Determine status level
	if status.CPUPercent > rw.config.CPUCriticalThreshold ||
		status.MemoryPercent > rw.config.MemCriticalThreshold ||
		status.EosProcessCount > rw.config.MaxEosProcesses {
		status.IsCritical = true
		status.Reason = rw.buildReasonString(status)
	} else if status.CPUPercent > rw.config.CPUWarningThreshold ||
		status.MemoryPercent > rw.config.MemWarningThreshold {
		status.IsWarning = true
		status.Reason = rw.buildReasonString(status)
	}

	return status
}

func (rw *ResourceWatchdog) buildReasonString(status ResourceStatus) string {
	var reasons []string

	if status.CPUPercent > rw.config.CPUCriticalThreshold {
		reasons = append(reasons, fmt.Sprintf("CPU critical: %.1f%%", status.CPUPercent))
	} else if status.CPUPercent > rw.config.CPUWarningThreshold {
		reasons = append(reasons, fmt.Sprintf("CPU warning: %.1f%%", status.CPUPercent))
	}

	if status.MemoryPercent > rw.config.MemCriticalThreshold {
		reasons = append(reasons, fmt.Sprintf("Memory critical: %.1f%%", status.MemoryPercent))
	} else if status.MemoryPercent > rw.config.MemWarningThreshold {
		reasons = append(reasons, fmt.Sprintf("Memory warning: %.1f%%", status.MemoryPercent))
	}

	if status.EosProcessCount > rw.config.MaxEosProcesses {
		reasons = append(reasons, fmt.Sprintf("Too many eos processes: %d", status.EosProcessCount))
	}

	return strings.Join(reasons, ", ")
}

// CapturePanic captures panic information for debugging
func (rw *ResourceWatchdog) CapturePanic(panicInfo interface{}) {
	if rw.traceLogger == nil {
		return
	}
	
	rw.traceLogger.writeToAll("\n!!! PANIC DETECTED IN MONITORED PROCESS !!!\n")
	rw.traceLogger.writeToAll("Panic: %v\n", panicInfo)
	
	// Create panic directory
	sessionDir := filepath.Join(rw.traceLogger.baseDir, rw.traceLogger.sessionID)
	panicDir := filepath.Join(sessionDir, "panic")
	os.MkdirAll(panicDir, 0755)
	
	// Write panic info
	panicFile := filepath.Join(panicDir, "panic.txt")
	f, err := os.Create(panicFile)
	if err == nil {
		fmt.Fprintf(f, "Panic Time: %s\n", time.Now().Format(time.RFC3339))
		fmt.Fprintf(f, "Panic Info: %v\n\n", panicInfo)
		fmt.Fprintf(f, "Stack Trace:\n%s\n", debug.Stack())
		f.Close()
	}
	
	// Capture current resource state
	status := rw.checkResources()
	rw.captureCriticalDiagnostics(panicDir, status)
}

// Helper function
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}