package disk_management

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
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
	if result.DryRun {
		fmt.Printf("[DRY RUN] %s\n", result.Message)
	} else if result.Success {
		fmt.Printf("✓ %s\n", result.Message)
		if result.Duration > 0 {
			fmt.Printf("  Duration: %v\n", result.Duration)
		}
	} else {
		fmt.Printf("✗ %s\n", result.Message)
	}
	return nil
}

// DiskManager handles disk and partition operations
type DiskManager struct {
	config *DiskManagerConfig
}

// NewDiskManager creates a new disk manager
func NewDiskManager(config *DiskManagerConfig) *DiskManager {
	if config == nil {
		config = DefaultDiskManagerConfig()
	}

	return &DiskManager{
		config: config,
	}
}

// ListDisks lists all available disk devices
func (dm *DiskManager) ListDisks(rc *eos_io.RuntimeContext) (*DiskListResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Listing disk devices")

	result := &DiskListResult{
		Disks:     make([]DiskInfo, 0),
		Timestamp: time.Now(),
	}

	// Use lsblk to get disk information
	cmd := exec.CommandContext(rc.Ctx, "lsblk", "-J", "-o", "NAME,SIZE,TYPE,MOUNTPOINT,VENDOR,MODEL,SERIAL,REMOVABLE,FSTYPE,LABEL,UUID")
	output, err := cmd.Output()
	if err != nil {
		logger.Error("Failed to list disks with lsblk", zap.Error(err))
		return nil, fmt.Errorf("failed to list disks: %w", err)
	}

	// Parse lsblk JSON output (simplified parsing for now)
	disks, err := dm.parseLsblkOutput(string(output))
	if err != nil {
		logger.Error("Failed to parse lsblk output", zap.Error(err))
		return nil, fmt.Errorf("failed to parse disk information: %w", err)
	}

	result.Disks = disks
	result.Total = len(disks)

	logger.Info("Disk listing completed", zap.Int("total_disks", result.Total))
	return result, nil
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
	if err := os.MkdirAll(mountPoint, 0755); err != nil {
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
	// This is a simplified parser - in production, you'd use proper JSON parsing
	// For now, return a basic structure
	var disks []DiskInfo

	// Parse the output line by line for basic information
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.Contains(line, "blockdevices") {
			continue
		}

		// This is a very basic parser - would need proper JSON parsing for production
		if strings.Contains(line, "/dev/") {
			// Extract basic device info
			parts := strings.Fields(line)
			if len(parts) > 0 {
				device := "/dev/" + parts[0]
				disk := DiskInfo{
					Device:      device,
					Name:        parts[0],
					Description: fmt.Sprintf("Block device %s", parts[0]),
					Mountpoints: make([]MountPoint, 0),
					Partitions:  make([]PartitionInfo, 0),
					Properties:  make(map[string]string),
				}
				disks = append(disks, disk)
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
	defer mountsFile.Close()

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

	return os.WriteFile(backupFile, output, 0644)
}

func (dm *DiskManager) promptForConfirmation(message string) bool {
	fmt.Printf("%s? [y/N]: ", message)
	var response string
	fmt.Scanln(&response)
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
	if result.DryRun {
		fmt.Printf("[DRY RUN] %s\n", result.Message)
	} else if result.Success {
		fmt.Printf("✓ %s\n", result.Message)
		if result.Duration > 0 {
			fmt.Printf("  Duration: %v\n", result.Duration)
		}
	} else {
		fmt.Printf("✗ %s\n", result.Message)
	}
	return nil
}
