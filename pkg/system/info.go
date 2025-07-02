package system

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/telemetry"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// SystemInfo represents collected system information
type SystemInfo struct {
	Timestamp        time.Time
	Processes        string
	Users            []string
	TempFiles        string
	InstalledPackages string
	SnapPackages     string
	DiskUsage        string
	BlockDevices     string
	BashHistory      string
	CrontabSystem    string
	CrontabUser      string
	DmesgOutput      string
	NetworkInfo      string
}

// CollectSystemInfo gathers comprehensive system information for diagnostics
func CollectSystemInfo(rc *eos_io.RuntimeContext) (*SystemInfo, error) {
	ctx, span := telemetry.Start(rc.Ctx, "system.CollectSystemInfo")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Starting comprehensive system information collection")

	info := &SystemInfo{
		Timestamp: time.Now(),
	}

	// Collect each piece of information
	if err := collectProcesses(rc, info); err != nil {
		logger.Warn("Failed to collect process information", zap.Error(err))
	}

	if err := collectUsers(rc, info); err != nil {
		logger.Warn("Failed to collect user information", zap.Error(err))
	}

	if err := collectTempFiles(rc, info); err != nil {
		logger.Warn("Failed to collect temp files information", zap.Error(err))
	}

	if err := collectInstalledPackages(rc, info); err != nil {
		logger.Warn("Failed to collect installed packages", zap.Error(err))
	}

	if err := collectSnapPackages(rc, info); err != nil {
		logger.Warn("Failed to collect snap packages", zap.Error(err))
	}

	if err := collectDiskUsage(rc, info); err != nil {
		logger.Warn("Failed to collect disk usage", zap.Error(err))
	}

	if err := collectBlockDevices(rc, info); err != nil {
		logger.Warn("Failed to collect block devices", zap.Error(err))
	}

	if err := collectBashHistory(rc, info); err != nil {
		logger.Warn("Failed to collect bash history", zap.Error(err))
	}

	if err := collectCrontab(rc, info); err != nil {
		logger.Warn("Failed to collect crontab information", zap.Error(err))
	}

	if err := collectDmesg(rc, info); err != nil {
		logger.Warn("Failed to collect dmesg output", zap.Error(err))
	}

	if err := collectNetworkInfo(rc, info); err != nil {
		logger.Warn("Failed to collect network information", zap.Error(err))
	}

	logger.Info("System information collection completed")
	return info, nil
}

// collectProcesses gathers running process information
func collectProcesses(rc *eos_io.RuntimeContext, info *SystemInfo) error {
	ctx, span := telemetry.Start(rc.Ctx, "system.collectProcesses")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Collecting process information")

	cmd := exec.CommandContext(ctx, "ps", "aux")
	output, err := cmd.Output()
	if err != nil {
		logger.Error("Failed to run ps aux", zap.Error(err))
		return fmt.Errorf("failed to collect process information: %w", err)
	}

	info.Processes = string(output)
	logger.Info("Process information collected successfully")
	return nil
}

// collectUsers gathers current user information
func collectUsers(rc *eos_io.RuntimeContext, info *SystemInfo) error {
	ctx, span := telemetry.Start(rc.Ctx, "system.collectUsers")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Collecting user information")

	cmd := exec.CommandContext(ctx, "users")
	output, err := cmd.Output()
	if err != nil {
		logger.Error("Failed to run users command", zap.Error(err))
		return fmt.Errorf("failed to collect user information: %w", err)
	}

	users := strings.Fields(strings.TrimSpace(string(output)))
	info.Users = users
	logger.Info("User information collected", zap.Strings("users", users))
	return nil
}

// collectTempFiles gathers information about temporary files
func collectTempFiles(rc *eos_io.RuntimeContext, info *SystemInfo) error {
	ctx, span := telemetry.Start(rc.Ctx, "system.collectTempFiles")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Collecting temp files information")

	cmd := exec.CommandContext(ctx, "ls", "-lah", "/tmp")
	output, err := cmd.Output()
	if err != nil {
		logger.Error("Failed to list /tmp directory", zap.Error(err))
		return fmt.Errorf("failed to collect temp files information: %w", err)
	}

	info.TempFiles = string(output)
	logger.Info("Temp files information collected successfully")
	return nil
}

// collectInstalledPackages gathers APT package information
func collectInstalledPackages(rc *eos_io.RuntimeContext, info *SystemInfo) error {
	ctx, span := telemetry.Start(rc.Ctx, "system.collectInstalledPackages")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Collecting installed packages information")

	cmd := exec.CommandContext(ctx, "apt", "list", "--installed")
	output, err := cmd.Output()
	if err != nil {
		logger.Error("Failed to list installed packages", zap.Error(err))
		return fmt.Errorf("failed to collect installed packages: %w", err)
	}

	info.InstalledPackages = string(output)
	logger.Info("Installed packages information collected successfully")
	return nil
}

// collectSnapPackages gathers Snap package information
func collectSnapPackages(rc *eos_io.RuntimeContext, info *SystemInfo) error {
	ctx, span := telemetry.Start(rc.Ctx, "system.collectSnapPackages")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Collecting snap packages information")

	cmd := exec.CommandContext(ctx, "snap", "list")
	output, err := cmd.Output()
	if err != nil {
		logger.Error("Failed to list snap packages", zap.Error(err))
		return fmt.Errorf("failed to collect snap packages: %w", err)
	}

	info.SnapPackages = string(output)
	logger.Info("Snap packages information collected successfully")
	return nil
}

// collectDiskUsage gathers disk usage information
func collectDiskUsage(rc *eos_io.RuntimeContext, info *SystemInfo) error {
	ctx, span := telemetry.Start(rc.Ctx, "system.collectDiskUsage")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Collecting disk usage information")

	cmd := exec.CommandContext(ctx, "df", "-h")
	output, err := cmd.Output()
	if err != nil {
		logger.Error("Failed to get disk usage", zap.Error(err))
		return fmt.Errorf("failed to collect disk usage: %w", err)
	}

	info.DiskUsage = string(output)
	logger.Info("Disk usage information collected successfully")
	return nil
}

// collectBlockDevices gathers block device information
func collectBlockDevices(rc *eos_io.RuntimeContext, info *SystemInfo) error {
	ctx, span := telemetry.Start(rc.Ctx, "system.collectBlockDevices")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Collecting block devices information")

	cmd := exec.CommandContext(ctx, "lsblk")
	output, err := cmd.Output()
	if err != nil {
		logger.Error("Failed to list block devices", zap.Error(err))
		return fmt.Errorf("failed to collect block devices: %w", err)
	}

	info.BlockDevices = string(output)
	logger.Info("Block devices information collected successfully")
	return nil
}

// collectBashHistory gathers bash history (safely)
func collectBashHistory(rc *eos_io.RuntimeContext, info *SystemInfo) error {
	ctx, span := telemetry.Start(rc.Ctx, "system.collectBashHistory")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Collecting bash history")

	// Get current user's home directory
	homeDir, err := os.UserHomeDir()
	if err != nil {
		logger.Error("Failed to get user home directory", zap.Error(err))
		return fmt.Errorf("failed to get home directory: %w", err)
	}

	historyFile := fmt.Sprintf("%s/.bash_history", homeDir)
	
	// Check if history file exists and is readable
	if _, err := os.Stat(historyFile); os.IsNotExist(err) {
		logger.Info("Bash history file does not exist")
		info.BashHistory = "No bash history file found"
		return nil
	}

	content, err := os.ReadFile(historyFile)
	if err != nil {
		logger.Error("Failed to read bash history", zap.Error(err))
		return fmt.Errorf("failed to read bash history: %w", err)
	}

	// Limit to last 50 lines for safety
	lines := strings.Split(string(content), "\n")
	if len(lines) > 50 {
		lines = lines[len(lines)-50:]
	}

	info.BashHistory = strings.Join(lines, "\n")
	logger.Info("Bash history collected successfully")
	return nil
}

// collectCrontab gathers crontab information
func collectCrontab(rc *eos_io.RuntimeContext, info *SystemInfo) error {
	ctx, span := telemetry.Start(rc.Ctx, "system.collectCrontab")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Collecting crontab information")

	// System crontab
	if content, err := os.ReadFile("/etc/crontab"); err == nil {
		info.CrontabSystem = string(content)
		logger.Info("System crontab collected successfully")
	} else {
		logger.Warn("Failed to read system crontab", zap.Error(err))
		info.CrontabSystem = "Failed to read system crontab"
	}

	// User crontab
	cmd := exec.CommandContext(ctx, "crontab", "-l")
	output, err := cmd.Output()
	if err != nil {
		logger.Info("No user crontab found or access denied")
		info.CrontabUser = "No user crontab or access denied"
	} else {
		info.CrontabUser = string(output)
		logger.Info("User crontab collected successfully")
	}

	return nil
}

// collectDmesg gathers kernel message buffer
func collectDmesg(rc *eos_io.RuntimeContext, info *SystemInfo) error {
	ctx, span := telemetry.Start(rc.Ctx, "system.collectDmesg")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Collecting dmesg output")

	cmd := exec.CommandContext(ctx, "dmesg")
	output, err := cmd.Output()
	if err != nil {
		logger.Error("Failed to run dmesg", zap.Error(err))
		return fmt.Errorf("failed to collect dmesg output: %w", err)
	}

	// Limit dmesg output to last 100 lines
	lines := strings.Split(string(output), "\n")
	if len(lines) > 100 {
		lines = lines[len(lines)-100:]
	}

	info.DmesgOutput = strings.Join(lines, "\n")
	logger.Info("Dmesg output collected successfully")
	return nil
}

// collectNetworkInfo gathers network configuration
func collectNetworkInfo(rc *eos_io.RuntimeContext, info *SystemInfo) error {
	ctx, span := telemetry.Start(rc.Ctx, "system.collectNetworkInfo")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Collecting network information")

	cmd := exec.CommandContext(ctx, "ip", "a")
	output, err := cmd.Output()
	if err != nil {
		logger.Error("Failed to get network information", zap.Error(err))
		return fmt.Errorf("failed to collect network information: %w", err)
	}

	info.NetworkInfo = string(output)
	logger.Info("Network information collected successfully")
	return nil
}

// DisplaySystemInfo outputs the collected system information in a structured format
func DisplaySystemInfo(rc *eos_io.RuntimeContext, info *SystemInfo) error {
	ctx, span := telemetry.Start(rc.Ctx, "system.DisplaySystemInfo")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Displaying system information")

	sections := []struct {
		title   string
		content string
	}{
		{"System Information Collection", fmt.Sprintf("Timestamp: %s", info.Timestamp.Format(time.RFC3339))},
		{"Running Processes", info.Processes},
		{"Current Users", strings.Join(info.Users, ", ")},
		{"Temporary Files (/tmp)", info.TempFiles},
		{"Installed APT Packages", info.InstalledPackages},
		{"Installed Snap Packages", info.SnapPackages},
		{"Disk Usage", info.DiskUsage},
		{"Block Devices", info.BlockDevices},
		{"Bash History (Last 50 lines)", info.BashHistory},
		{"System Crontab", info.CrontabSystem},
		{"User Crontab", info.CrontabUser},
		{"Kernel Messages (Last 100 lines)", info.DmesgOutput},
		{"Network Configuration", info.NetworkInfo},
	}

	for _, section := range sections {
		logger.Info(fmt.Sprintf("\n=== %s ===", section.title))
		
		if section.content == "" {
			logger.Info("No data available")
		} else {
			// Split content into lines and log each line
			scanner := bufio.NewScanner(strings.NewReader(section.content))
			for scanner.Scan() {
				logger.Info(scanner.Text())
			}
		}
		logger.Info("")
	}

	logger.Info("System information display completed")
	return nil
}

// SaveSystemInfoToFile saves the collected system information to a file
func SaveSystemInfoToFile(rc *eos_io.RuntimeContext, info *SystemInfo, filename string) error {
	ctx, span := telemetry.Start(rc.Ctx, "system.SaveSystemInfoToFile")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Saving system information to file", zap.String("filename", filename))

	file, err := os.Create(filename)
	if err != nil {
		logger.Error("Failed to create output file", zap.Error(err))
		return fmt.Errorf("failed to create file %s: %w", filename, err)
	}
	defer func() { _ = file.Close() }()

	// Write header
	if _, err := fmt.Fprintf(file, "Ubuntu System Information Report\n"); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}
	if _, err := fmt.Fprintf(file, "Generated: %s\n", info.Timestamp.Format(time.RFC3339)); err != nil {
		return fmt.Errorf("failed to write timestamp: %w", err)
	}
	if _, err := fmt.Fprintf(file, "========================================\n\n"); err != nil {
		return fmt.Errorf("failed to write separator: %w", err)
	}

	sections := []struct {
		title   string
		content string
	}{
		{"Running Processes", info.Processes},
		{"Current Users", strings.Join(info.Users, ", ")},
		{"Temporary Files (/tmp)", info.TempFiles},
		{"Installed APT Packages", info.InstalledPackages},
		{"Installed Snap Packages", info.SnapPackages},
		{"Disk Usage", info.DiskUsage},
		{"Block Devices", info.BlockDevices},
		{"Bash History (Last 50 lines)", info.BashHistory},
		{"System Crontab", info.CrontabSystem},
		{"User Crontab", info.CrontabUser},
		{"Kernel Messages (Last 100 lines)", info.DmesgOutput},
		{"Network Configuration", info.NetworkInfo},
	}

	for _, section := range sections {
		if _, err := fmt.Fprintf(file, "=== %s ===\n", section.title); err != nil {
			return fmt.Errorf("failed to write section title: %w", err)
		}
		if _, err := fmt.Fprintf(file, "%s\n\n", section.content); err != nil {
			return fmt.Errorf("failed to write section content: %w", err)
		}
	}

	logger.Info("System information saved successfully", zap.String("filename", filename))
	return nil
}