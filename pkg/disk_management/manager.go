package disk_management

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/privilege_check"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

func OutputMountOpJSON(result *MountOperation) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func OutputMountOpText(result *MountOperation) error {
	// SECURITY: Use structured logging instead of fmt.Printf per CLAUDE.md P0 rule
	logger := otelzap.L()

	if result.DryRun {
		logger.Info("Mount operation (dry run)",
			zap.String("mode", "DRY_RUN"),
			zap.String("message", result.Message))
	} else if result.Success {
		logger.Info("Mount operation success",
			zap.String("status", "✓"),
			zap.String("message", result.Message),
			zap.Duration("duration", result.Duration))
	} else {
		logger.Error("Mount operation failed",
			zap.String("status", "✗"),
			zap.String("message", result.Message))
	}
	return nil
}

// DiskManager handles disk and partition operations
type DiskManager struct {
	config *DiskManagerConfig
	use    bool
	Client ClientInterface
}

// ClientInterface defines the interface for  operations
type ClientInterface interface {
	CmdRun(ctx context.Context, target string, command string) (string, error)
}

// NewDiskManager creates a new disk manager
func NewDiskManager(config *DiskManagerConfig) *DiskManager {
	if config == nil {
		config = DefaultDiskManagerConfig()
	}

	return &DiskManager{
		config: config,
		use:    false, // Default to direct execution
	}
}

// NewDiskManagerWith creates a new disk manager that uses  for execution
func NewDiskManagerWith(config *DiskManagerConfig, Client ClientInterface) *DiskManager {
	if config == nil {
		config = DefaultDiskManagerConfig()
	}

	return &DiskManager{
		config: config,
		use:    true,
		Client: Client,
	}
}

// ListDisks lists all available disk devices
func (dm *DiskManager) ListDisks(rc *eos_io.RuntimeContext) (*DiskListResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Listing disk devices", zap.String("platform", runtime.GOOS))

	result := &DiskListResult{
		Disks:     make([]DiskInfo, 0),
		Timestamp: time.Now(),
	}

	var disks []DiskInfo
	var err error

	switch runtime.GOOS {
	case "darwin":
		// macOS uses diskutil
		disks, err = dm.listDisksDarwin(rc)
		if err != nil {
			logger.Error("Failed to list disks on macOS", zap.Error(err))
			return nil, fmt.Errorf("failed to list disks on macOS: %w", err)
		}
	case "linux":
		// Linux uses lsblk
		disks, err = dm.listDisksLinux(rc)
		if err != nil {
			logger.Error("Failed to list disks on Linux", zap.Error(err))
			return nil, fmt.Errorf("failed to list disks on Linux: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}

	result.Disks = disks
	result.Total = len(disks)

	logger.Info("Disk listing completed", zap.Int("total_disks", result.Total))
	return result, nil
}

// listDisksLinux lists disks on Linux using lsblk
func (dm *DiskManager) listDisksLinux(rc *eos_io.RuntimeContext) ([]DiskInfo, error) {
	logger := otelzap.Ctx(rc.Ctx)

	var output []byte
	var err error

	if dm.use && dm.Client != nil {
		// Execute through
		logger.Info("Executing lsblk through ")
		cmdStr := "lsblk -J -o NAME,SIZE,TYPE,MOUNTPOINT,VENDOR,MODEL,SERIAL,RM,FSTYPE,LABEL,UUID"
		outputStr, err := dm.Client.CmdRun(rc.Ctx, "*", cmdStr)
		if err != nil {
			logger.Error("Failed to run lsblk through ",
				zap.Error(err),
				zap.String("output", outputStr))
			return nil, fmt.Errorf("lsblk failed through : %w", err)
		}
		output = []byte(outputStr)
	} else {
		// Execute directly
		logger.Info("Executing lsblk directly (bootstrap mode)")
		cmd := exec.CommandContext(rc.Ctx, "lsblk", "-J", "-o", "NAME,SIZE,TYPE,MOUNTPOINT,VENDOR,MODEL,SERIAL,RM,FSTYPE,LABEL,UUID")
		output, err = cmd.CombinedOutput()
		if err != nil {
			logger.Error("Failed to run lsblk directly",
				zap.Error(err),
				zap.String("output", string(output)))

			// Check if lsblk exists
			if _, lookupErr := exec.LookPath("lsblk"); lookupErr != nil {
				return nil, fmt.Errorf("lsblk command not found. This command requires the lsblk utility which is typically part of util-linux package")
			}

			return nil, fmt.Errorf("lsblk failed: %w (output: %s)", err, string(output))
		}
	}

	return dm.parseLsblkOutput(string(output))
}

// listDisksDarwin lists disks on macOS using diskutil
func (dm *DiskManager) listDisksDarwin(rc *eos_io.RuntimeContext) ([]DiskInfo, error) {
	logger := otelzap.Ctx(rc.Ctx)

	var output []byte
	var err error

	if dm.use && dm.Client != nil {
		// Execute through
		logger.Info("Executing diskutil through ")
		cmdStr := "diskutil list -plist"
		outputStr, err := dm.Client.CmdRun(rc.Ctx, "*", cmdStr)
		if err != nil {
			logger.Error("Failed to run diskutil through ",
				zap.Error(err),
				zap.String("output", outputStr))
			return nil, fmt.Errorf("diskutil failed through : %w", err)
		}
		output = []byte(outputStr)
	} else {
		// Execute directly
		logger.Info("Executing diskutil directly (bootstrap mode)")
		cmd := exec.CommandContext(rc.Ctx, "diskutil", "list", "-plist")
		output, err = cmd.CombinedOutput()
		if err != nil {
			logger.Error("Failed to run diskutil directly",
				zap.Error(err),
				zap.String("output", string(output)))

			// Check if diskutil exists
			if _, lookupErr := exec.LookPath("diskutil"); lookupErr != nil {
				return nil, fmt.Errorf("diskutil command not found. This is a system command that should be available on macOS")
			}

			return nil, fmt.Errorf("diskutil failed: %w (output: %s)", err, string(output))
		}
	}

	// For now, parse basic diskutil output
	// In a full implementation, we would parse the plist XML format
	return dm.parseDiskutilOutput(string(output))
}

// CreatePartition creates a new partition on the specified disk
func (dm *DiskManager) CreatePartition(rc *eos_io.RuntimeContext, device string, options *PartitionOptions) (*PartitionOperation, error) {
	logger := otelzap.Ctx(rc.Ctx)
	startTime := time.Now()

	if options == nil {
		options = DefaultPartitionOptions()
	}

	operation := &PartitionOperation{
		Operation: "create",
		Device:    device,
		Timestamp: time.Now(),
		DryRun:    options.DryRun,
	}

	logger.Info("Creating partition",
		zap.String("device", device),
		zap.String("type", options.PartitionType),
		zap.Bool("dry_run", options.DryRun))

	// Check privileges
	privilegeManager := privilege_check.NewPrivilegeManager(nil)
	if err := privilegeManager.CheckSudoOnly(rc); err != nil {
		operation.Success = false
		operation.Message = "Root privileges required for partition operations"
		logger.Error("Insufficient privileges", zap.Error(err))
		return operation, err
	}

	// Safety checks
	if dm.config.SafetyChecks {
		if err := dm.performSafetyChecks(device); err != nil {
			operation.Success = false
			operation.Message = fmt.Sprintf("Safety check failed: %v", err)
			logger.Error("Safety check failed", zap.Error(err))
			return operation, err
		}
	}

	// Confirmation if required
	if dm.config.RequireConfirmation && !options.Force && !options.DryRun {
		if !dm.promptForConfirmation(fmt.Sprintf("Create partition on %s", device)) {
			operation.Success = false
			operation.Message = "Operation cancelled by user"
			logger.Info("Operation cancelled by user")
			return operation, nil
		}
	}

	if options.DryRun {
		operation.Success = true
		operation.Message = fmt.Sprintf("Would create partition on %s", device)
		operation.Duration = time.Since(startTime)
		logger.Info("Dry run: would create partition")
		return operation, nil
	}

	// Backup partition table if enabled
	if dm.config.BackupPartitionTable {
		if err := dm.backupPartitionTable(rc, device); err != nil {
			logger.Warn("Failed to backup partition table", zap.Error(err))
			// Don't fail the operation for backup errors
		}
	}

	// Create partition using fdisk
	if err := dm.createPartitionWithFdisk(rc, device, options); err != nil {
		operation.Success = false
		operation.Message = fmt.Sprintf("Failed to create partition: %v", err)
		logger.Error("Partition creation failed", zap.Error(err))
		return operation, err
	}

	operation.Success = true
	operation.Message = fmt.Sprintf("Successfully created partition on %s", device)
	operation.Duration = time.Since(startTime)

	logger.Info("Partition created successfully",
		zap.String("device", device),
		zap.Duration("duration", operation.Duration))

	return operation, nil
}

// FormatPartition formats a partition with the specified filesystem
func (dm *DiskManager) FormatPartition(rc *eos_io.RuntimeContext, device string, filesystem string, label string, dryRun bool) (*FormatOperation, error) {
	logger := otelzap.Ctx(rc.Ctx)
	startTime := time.Now()

	operation := &FormatOperation{
		Device:     device,
		FileSystem: filesystem,
		Label:      label,
		Timestamp:  time.Now(),
		DryRun:     dryRun,
	}

	logger.Info("Formatting partition",
		zap.String("device", device),
		zap.String("filesystem", filesystem),
		zap.String("label", label),
		zap.Bool("dry_run", dryRun))

	// Check privileges
	privilegeManager := privilege_check.NewPrivilegeManager(nil)
	if err := privilegeManager.CheckSudoOnly(rc); err != nil {
		operation.Success = false
		operation.Message = "Root privileges required for format operations"
		logger.Error("Insufficient privileges", zap.Error(err))
		return operation, err
	}

	if dryRun {
		operation.Success = true
		operation.Message = fmt.Sprintf("Would format %s as %s", device, filesystem)
		operation.Duration = time.Since(startTime)
		logger.Info("Dry run: would format partition")
		return operation, nil
	}

	// Confirmation if required
	if dm.config.RequireConfirmation {
		if !dm.promptForConfirmation(fmt.Sprintf("Format %s as %s (THIS WILL DESTROY ALL DATA)", device, filesystem)) {
			operation.Success = false
			operation.Message = "Operation cancelled by user"
			logger.Info("Format operation cancelled by user")
			return operation, nil
		}
	}

	// Format the partition
	var cmd *exec.Cmd
	switch filesystem {
	case "ext4":
		args := []string{"-F", device}
		if label != "" {
			args = append([]string{"-L", label}, args...)
		}
		cmd = exec.CommandContext(rc.Ctx, "mkfs.ext4", args...)
	case "ext3":
		args := []string{"-F", device}
		if label != "" {
			args = append([]string{"-L", label}, args...)
		}
		cmd = exec.CommandContext(rc.Ctx, "mkfs.ext3", args...)
	case "xfs":
		args := []string{"-f", device}
		if label != "" {
			args = append([]string{"-L", label}, args...)
		}
		cmd = exec.CommandContext(rc.Ctx, "mkfs.xfs", args...)
	case "btrfs":
		args := []string{"-f", device}
		if label != "" {
			args = append([]string{"-L", label}, args...)
		}
		cmd = exec.CommandContext(rc.Ctx, "mkfs.btrfs", args...)
	default:
		operation.Success = false
		operation.Message = fmt.Sprintf("Unsupported filesystem: %s", filesystem)
		logger.Error("Unsupported filesystem", zap.String("filesystem", filesystem))
		return operation, fmt.Errorf("unsupported filesystem: %s", filesystem)
	}

	output, err := cmd.CombinedOutput()
	operation.Output = string(output)
	operation.Duration = time.Since(startTime)

	if err != nil {
		operation.Success = false
		operation.Message = fmt.Sprintf("Format failed: %v", err)
		logger.Error("Format operation failed", zap.Error(err), zap.String("output", operation.Output))
		return operation, err
	}

	operation.Success = true
	operation.Message = fmt.Sprintf("Successfully formatted %s as %s", device, filesystem)

	logger.Info("Partition formatted successfully",
		zap.String("device", device),
		zap.String("filesystem", filesystem),
		zap.Duration("duration", operation.Duration))

	return operation, nil
}

// MountPartition mounts a partition to the specified mount point
func (dm *DiskManager) MountPartition(rc *eos_io.RuntimeContext, device string, mountPoint string, options string, dryRun bool) (*MountOperation, error) {
	logger := otelzap.Ctx(rc.Ctx)
	startTime := time.Now()

	operation := &MountOperation{
		Operation:  "mount",
		Device:     device,
		MountPoint: mountPoint,
		Timestamp:  time.Now(),
		DryRun:     dryRun,
	}

	logger.Info("Mounting partition",
		zap.String("device", device),
		zap.String("mount_point", mountPoint),
		zap.String("options", options),
		zap.Bool("dry_run", dryRun))

	// Check privileges
	privilegeManager := privilege_check.NewPrivilegeManager(nil)
	if err := privilegeManager.CheckSudoOnly(rc); err != nil {
		operation.Success = false
		operation.Message = "Root privileges required for mount operations"
		logger.Error("Insufficient privileges", zap.Error(err))
		return operation, err
	}

	if dryRun {
		operation.Success = true
		operation.Message = fmt.Sprintf("Would mount %s at %s", device, mountPoint)
		operation.Duration = time.Since(startTime)
		logger.Info("Dry run: would mount partition")
		return operation, nil
	}

	// Create mount point if it doesn't exist
	if err := os.MkdirAll(mountPoint, shared.ServiceDirPerm); err != nil {
		operation.Success = false
		operation.Message = fmt.Sprintf("Failed to create mount point: %v", err)
		logger.Error("Failed to create mount point", zap.Error(err))
		return operation, err
	}

	// Build mount command
	args := []string{device, mountPoint}
	if options != "" {
		args = append([]string{"-o", options}, args...)
	}

	cmd := exec.CommandContext(rc.Ctx, "mount", args...)
	output, err := cmd.CombinedOutput()
	operation.Duration = time.Since(startTime)

	if err != nil {
		operation.Success = false
		operation.Message = fmt.Sprintf("Mount failed: %v", err)
		logger.Error("Mount operation failed", zap.Error(err), zap.String("output", string(output)))
		return operation, err
	}

	operation.Success = true
	operation.Message = fmt.Sprintf("Successfully mounted %s at %s", device, mountPoint)

	logger.Info("Partition mounted successfully",
		zap.String("device", device),
		zap.String("mount_point", mountPoint),
		zap.Duration("duration", operation.Duration))

	return operation, nil
}

// Helper methods

func (dm *DiskManager) parseLsblkOutput(output string) ([]DiskInfo, error) {
	// Parse JSON output from lsblk
	type lsblkDevice struct {
		Name       string        `json:"name"`
		Size       string        `json:"size"`
		Type       string        `json:"type"`
		Mountpoint string        `json:"mountpoint"`
		Vendor     string        `json:"vendor"`
		Model      string        `json:"model"`
		Serial     string        `json:"serial"`
		Removable  bool          `json:"rm"`
		Fstype     string        `json:"fstype"`
		Label      string        `json:"label"`
		UUID       string        `json:"uuid"`
		Children   []lsblkDevice `json:"children"`
	}

	type lsblkOutput struct {
		Blockdevices []lsblkDevice `json:"blockdevices"`
	}

	var lsblkData lsblkOutput
	if err := json.Unmarshal([]byte(output), &lsblkData); err != nil {
		return nil, fmt.Errorf("failed to parse lsblk JSON output: %w", err)
	}

	var disks []DiskInfo

	for _, device := range lsblkData.Blockdevices {
		// Only process disk type devices (not partitions)
		if device.Type != "disk" {
			continue
		}

		disk := DiskInfo{
			Device:      "/dev/" + device.Name,
			Name:        device.Name,
			Description: fmt.Sprintf("%s %s", device.Vendor, device.Model),
			SizeHuman:   device.Size,
			IsRemovable: device.Removable,
			Vendor:      strings.TrimSpace(device.Vendor),
			Model:       strings.TrimSpace(device.Model),
			Serial:      strings.TrimSpace(device.Serial),
			Mountpoints: make([]MountPoint, 0),
			Partitions:  make([]PartitionInfo, 0),
			Properties:  make(map[string]string),
		}

		// Add mount point if disk is directly mounted
		if device.Mountpoint != "" {
			disk.Mountpoints = append(disk.Mountpoints, MountPoint{
				Path:     device.Mountpoint,
				Readonly: false, // Would need to parse mount options to determine this
			})
		}

		// Process partitions (children)
		for _, child := range device.Children {
			if child.Type == "part" {
				partition := PartitionInfo{
					Device:     "/dev/" + child.Name,
					SizeHuman:  child.Size,
					Type:       child.Type,
					Filesystem: child.Fstype,
					Label:      child.Label,
					UUID:       child.UUID,
					IsMounted:  child.Mountpoint != "",
					MountPoint: child.Mountpoint,
				}
				disk.Partitions = append(disk.Partitions, partition)

				// Add partition mount points to disk mount points
				if child.Mountpoint != "" {
					disk.Mountpoints = append(disk.Mountpoints, MountPoint{
						Path:     child.Mountpoint,
						Readonly: false,
					})
				}
			}
		}

		// Set properties
		disk.Properties["uuid"] = device.UUID
		disk.Properties["fstype"] = device.Fstype
		disk.Properties["label"] = device.Label

		disks = append(disks, disk)
	}

	return disks, nil
}

// parseDiskutilOutput parses output from diskutil on macOS
func (dm *DiskManager) parseDiskutilOutput(output string) ([]DiskInfo, error) {
	// For a simple implementation, parse the text output from diskutil list
	// A production implementation would parse the plist XML format
	var disks []DiskInfo

	// Run diskutil info for each disk to get detailed information
	// First, get list of disks
	cmd := exec.Command("diskutil", "list")
	listOutput, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get disk list: %w", err)
	}

	// Parse the output to find disk identifiers
	lines := strings.Split(string(listOutput), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "/dev/disk") {
			// Extract disk identifier
			parts := strings.Fields(line)
			if len(parts) > 0 {
				diskID := parts[0]

				// Get detailed info for this disk
				infoCmd := exec.Command("diskutil", "info", diskID)
				infoOutput, err := infoCmd.Output()
				if err != nil {
					continue // Skip disks we can't get info for
				}

				disk := parseDiskutilInfo(diskID, string(infoOutput))
				if disk != nil {
					disks = append(disks, *disk)
				}
			}
		}
	}

	return disks, nil
}

func (dm *DiskManager) performSafetyChecks(device string) error {
	// Check if device is in excluded list
	for _, excluded := range dm.config.ExcludedDevices {
		if device == excluded {
			return fmt.Errorf("device %s is in the excluded devices list", device)
		}
	}

	// Check if device exists
	if _, err := os.Stat(device); err != nil {
		return fmt.Errorf("device %s does not exist", device)
	}

	// Check if device is mounted
	mountsFile, err := os.Open("/proc/mounts")
	if err != nil {
		return fmt.Errorf("failed to check mounts: %w", err)
	}
	defer func() {
		if err := mountsFile.Close(); err != nil {
			// Log but don't fail the operation
			logger := otelzap.Ctx(context.Background())
			logger.Warn("Failed to close mounts file", zap.Error(err))
		}
	}()

	scanner := bufio.NewScanner(mountsFile)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, device) {
			return fmt.Errorf("device %s or its partitions are currently mounted", device)
		}
	}

	return nil
}

func (dm *DiskManager) createPartitionWithFdisk(rc *eos_io.RuntimeContext, device string, options *PartitionOptions) error {
	// This is a simplified implementation - production would need more sophisticated fdisk interaction
	fdiskCommands := "n\np\n1\n\n\nw\n"

	cmd := exec.CommandContext(rc.Ctx, "fdisk", device)
	cmd.Stdin = strings.NewReader(fdiskCommands)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("fdisk failed: %w, output: %s", err, string(output))
	}

	return nil
}

func (dm *DiskManager) backupPartitionTable(rc *eos_io.RuntimeContext, device string) error {
	timestamp := time.Now().Format("2006-01-02_15-04-05")
	backupFile := fmt.Sprintf("/tmp/partition_table_%s_%s.backup",
		strings.ReplaceAll(device, "/", "_"), timestamp)

	cmd := exec.CommandContext(rc.Ctx, "sfdisk", "-d", device)
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to dump partition table: %w", err)
	}

	return os.WriteFile(backupFile, output, shared.ConfigFilePerm)
}

func (dm *DiskManager) promptForConfirmation(message string) bool {
	// SECURITY: Use structured logging instead of fmt.Printf per CLAUDE.md P0 rule
	logger := otelzap.L()
	logger.Info("terminal prompt: confirmation required", zap.String("message", message))

	var response string
	_, _ = fmt.Scanln(&response) // Ignore error as empty input is valid
	return response == "y" || response == "Y" || response == "yes"
}

// GetDiskUsage returns disk usage information for mounted filesystems
func (dm *DiskManager) GetDiskUsage(rc *eos_io.RuntimeContext) (map[string]DiskUsageInfo, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Getting disk usage information")

	cmd := exec.CommandContext(rc.Ctx, "df", "-h")
	output, err := cmd.Output()
	if err != nil {
		logger.Error("Failed to get disk usage", zap.Error(err))
		return nil, fmt.Errorf("failed to get disk usage: %w", err)
	}

	usage := make(map[string]DiskUsageInfo)
	lines := strings.Split(string(output), "\n")

	for i, line := range lines {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue // Skip header and empty lines
		}

		parts := strings.Fields(line)
		if len(parts) >= 6 {
			filesystem := parts[0]
			usage[filesystem] = DiskUsageInfo{
				Filesystem: filesystem,
				Size:       parts[1],
				Used:       parts[2],
				Available:  parts[3],
				UsePercent: parts[4],
				MountPoint: parts[5],
			}
		}
	}

	return usage, nil
}

// DiskUsageInfo represents disk usage information
type DiskUsageInfo struct {
	Filesystem string `json:"filesystem"`
	Size       string `json:"size"`
	Used       string `json:"used"`
	Available  string `json:"available"`
	UsePercent string `json:"use_percent"`
	MountPoint string `json:"mount_point"`
}

func OutputFormatOpJSON(result *FormatOperation) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func OutputFormatOpText(result *FormatOperation) error {
	// SECURITY: Use structured logging instead of fmt.Printf per CLAUDE.md P0 rule
	logger := otelzap.L()

	if result.DryRun {
		logger.Info("Format operation (dry run)",
			zap.String("mode", "DRY_RUN"),
			zap.String("message", result.Message))
	} else if result.Success {
		logger.Info("Format operation success",
			zap.String("status", "✓"),
			zap.String("message", result.Message),
			zap.Duration("duration", result.Duration))
	} else {
		logger.Error("Format operation failed",
			zap.String("status", "✗"),
			zap.String("message", result.Message))
	}
	return nil
}
