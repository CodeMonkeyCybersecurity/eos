package storage

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/telemetry"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// BlockDevice represents a block device detected on the system
type BlockDevice struct {
	Name       string
	UUID       string
	Label      string
	Type       string
	Mountpoint string
	Size       string
}

// FstabEntry represents an entry in /etc/fstab
type FstabEntry struct {
	UUID       string
	Mountpoint string
	Type       string
	Options    string
	Dump       int
	Pass       int
}

// ListBlockDevices lists all available block devices with their details
func ListBlockDevices(rc *eos_io.RuntimeContext) ([]BlockDevice, error) {
	ctx, span := telemetry.Start(rc.Ctx, "storage.ListBlockDevices")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Listing block devices")

	// Run lsblk to get block device information
	cmd := exec.CommandContext(ctx, "lsblk", "-f", "-o", "NAME,UUID,LABEL,FSTYPE,MOUNTPOINT,SIZE")
	output, err := cmd.Output()
	if err != nil {
		logger.Error("Failed to list block devices", zap.Error(err))
		return nil, fmt.Errorf("failed to list block devices: %w", err)
	}

	var devices []BlockDevice
	lines := strings.Split(string(output), "\n")
	
	// Skip header line
	for i := 1; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		
		fields := strings.Fields(line)
		if len(fields) >= 6 {
			device := BlockDevice{
				Name:       fields[0],
				UUID:       fields[1],
				Label:      fields[2],
				Type:       fields[3],
				Mountpoint: fields[4],
				Size:       fields[5],
			}
			
			// Clean up fields that might show "-" for empty values
			if device.UUID == "-" {
				device.UUID = ""
			}
			if device.Label == "-" {
				device.Label = ""
			}
			if device.Type == "-" {
				device.Type = ""
			}
			if device.Mountpoint == "-" {
				device.Mountpoint = ""
			}
			
			devices = append(devices, device)
		}
	}

	logger.Info("Found block devices", zap.Int("count", len(devices)))
	return devices, nil
}

// GetUUIDsWithBlkid gets UUIDs using blkid command for additional verification
func GetUUIDsWithBlkid(rc *eos_io.RuntimeContext) (map[string]string, error) {
	ctx, span := telemetry.Start(rc.Ctx, "storage.GetUUIDsWithBlkid")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Getting UUIDs with blkid")

	cmd := exec.CommandContext(ctx, "blkid")
	output, err := cmd.Output()
	if err != nil {
		logger.Error("Failed to run blkid", zap.Error(err))
		return nil, fmt.Errorf("failed to run blkid: %w", err)
	}

	uuidMap := make(map[string]string)
	lines := strings.Split(string(output), "\n")
	
	// Parse blkid output: /dev/sda1: UUID="..." TYPE="..." ...
	uuidRegex := regexp.MustCompile(`UUID="([^"]+)"`)
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		
		// Extract device name
		parts := strings.Split(line, ":")
		if len(parts) < 2 {
			continue
		}
		
		device := strings.TrimSpace(parts[0])
		
		// Extract UUID
		matches := uuidRegex.FindStringSubmatch(line)
		if len(matches) > 1 {
			uuidMap[device] = matches[1]
		}
	}

	logger.Info("Found UUIDs", zap.Int("count", len(uuidMap)))
	return uuidMap, nil
}

// BackupFstab creates a backup of /etc/fstab
func BackupFstab(rc *eos_io.RuntimeContext) (string, error) {
	ctx, span := telemetry.Start(rc.Ctx, "storage.BackupFstab")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	
	backupDir := "/etc/fabric/fstab"
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		logger.Error("Failed to create backup directory", zap.Error(err))
		return "", fmt.Errorf("failed to create backup directory: %w", err)
	}

	timestamp := time.Now().Format("2006-01-02")
	backupPath := filepath.Join(backupDir, fmt.Sprintf("fstab_backup_%s", timestamp))

	// Copy /etc/fstab to backup location
	cmd := exec.CommandContext(ctx, "cp", "/etc/fstab", backupPath)
	if err := cmd.Run(); err != nil {
		logger.Error("Failed to backup fstab", zap.Error(err))
		return "", fmt.Errorf("failed to backup fstab: %w", err)
	}

	logger.Info("Fstab backed up successfully", zap.String("backup_path", backupPath))
	return backupPath, nil
}

// AddFstabEntry adds a new entry to /etc/fstab
func AddFstabEntry(rc *eos_io.RuntimeContext, entry FstabEntry) error {
	ctx, span := telemetry.Start(rc.Ctx, "storage.AddFstabEntry")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Adding fstab entry",
		zap.String("uuid", entry.UUID),
		zap.String("mountpoint", entry.Mountpoint),
		zap.String("type", entry.Type))

	// Validate entry
	if entry.UUID == "" || entry.Mountpoint == "" || entry.Type == "" {
		return eos_err.NewExpectedError(ctx, fmt.Errorf("UUID, mountpoint, and filesystem type are required"))
	}

	if !strings.HasPrefix(entry.Mountpoint, "/") {
		return eos_err.NewExpectedError(ctx, fmt.Errorf("mountpoint must be an absolute path starting with '/'"))
	}

	// Set defaults
	if entry.Options == "" {
		entry.Options = "defaults"
	}
	if entry.Pass == 0 {
		entry.Pass = 2
	}

	// Create mount point directory if it doesn't exist
	if err := os.MkdirAll(entry.Mountpoint, 0755); err != nil {
		logger.Error("Failed to create mount point", zap.Error(err))
		return fmt.Errorf("failed to create mount point %s: %w", entry.Mountpoint, err)
	}

	// Format fstab line
	fstabLine := fmt.Sprintf("UUID=%s %s %s %s %d %d\n",
		entry.UUID, entry.Mountpoint, entry.Type, entry.Options, entry.Dump, entry.Pass)

	// Append to /etc/fstab
	file, err := os.OpenFile("/etc/fstab", os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		logger.Error("Failed to open fstab for writing", zap.Error(err))
		return fmt.Errorf("failed to open /etc/fstab: %w", err)
	}
	defer func() { _ = file.Close() }()

	if _, err := file.WriteString(fstabLine); err != nil {
		logger.Error("Failed to write to fstab", zap.Error(err))
		return fmt.Errorf("failed to write to /etc/fstab: %w", err)
	}

	logger.Info("Fstab entry added successfully")
	return nil
}

// MountAll mounts all filesystems listed in /etc/fstab
func MountAll(rc *eos_io.RuntimeContext) error {
	ctx, span := telemetry.Start(rc.Ctx, "storage.MountAll")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Mounting all filesystems from fstab")

	cmd := exec.CommandContext(ctx, "mount", "-a")
	if err := cmd.Run(); err != nil {
		logger.Error("Failed to mount filesystems", zap.Error(err))
		return fmt.Errorf("failed to mount filesystems: %w", err)
	}

	logger.Info("All filesystems mounted successfully")
	return nil
}

// ReloadSystemd reloads systemd daemon after fstab changes
func ReloadSystemd(rc *eos_io.RuntimeContext) error {
	ctx, span := telemetry.Start(rc.Ctx, "storage.ReloadSystemd")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Reloading systemd daemon")

	cmd := exec.CommandContext(ctx, "systemctl", "daemon-reload")
	if err := cmd.Run(); err != nil {
		logger.Error("Failed to reload systemd", zap.Error(err))
		return fmt.Errorf("failed to reload systemd: %w", err)
	}

	logger.Info("Systemd daemon reloaded successfully")
	return nil
}

// GetDiskUsage returns disk usage information
func GetDiskUsage(rc *eos_io.RuntimeContext) (string, error) {
	ctx, span := telemetry.Start(rc.Ctx, "storage.GetDiskUsage")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Getting disk usage information")

	cmd := exec.CommandContext(ctx, "df", "-h")
	output, err := cmd.Output()
	if err != nil {
		logger.Error("Failed to get disk usage", zap.Error(err))
		return "", fmt.Errorf("failed to get disk usage: %w", err)
	}

	return string(output), nil
}

// InteractiveFstabManager provides an interactive interface for managing fstab entries
func InteractiveFstabManager(rc *eos_io.RuntimeContext) error {
	ctx, span := telemetry.Start(rc.Ctx, "storage.InteractiveFstabManager")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Starting interactive fstab manager")

	// Display current block devices
	devices, err := ListBlockDevices(rc)
	if err != nil {
		return err
	}

	logger.Info("Available block devices:")
	for _, device := range devices {
		if device.UUID != "" {
			logger.Info(fmt.Sprintf("Device: %s, UUID: %s, Type: %s, Size: %s",
				device.Name, device.UUID, device.Type, device.Size))
		}
	}

	// Get UUIDs from blkid for verification
	uuids, err := GetUUIDsWithBlkid(rc)
	if err != nil {
		logger.Warn("Failed to get UUIDs from blkid", zap.Error(err))
	} else {
		logger.Info("UUIDs from blkid:")
		for device, uuid := range uuids {
			logger.Info(fmt.Sprintf("%s: %s", device, uuid))
		}
	}

	// Backup fstab
	backupPath, err := BackupFstab(rc)
	if err != nil {
		return err
	}
	logger.Info("Fstab backed up", zap.String("path", backupPath))

	// Prompt for UUID
	uuid, err := interaction.PromptUser(rc, "Copy the UUID for the drive you want to mount and paste it here")
	if err != nil {
		return err
	}
	uuid = strings.TrimSpace(uuid)
	if uuid == "" {
		return eos_err.NewExpectedError(ctx, fmt.Errorf("UUID cannot be empty"))
	}

	// Prompt for filesystem type
	fsType, err := interaction.PromptUser(rc, "Copy the TYPE (e.g., ext4, ntfs, zfs) for the drive you want to mount")
	if err != nil {
		return err
	}
	fsType = strings.TrimSpace(fsType)
	if fsType == "" {
		return eos_err.NewExpectedError(ctx, fmt.Errorf("filesystem type cannot be empty"))
	}

	// Prompt for mount point
	mountPoint, err := interaction.PromptUser(rc, "Enter the directory where you want to mount the new drive (e.g., /mnt/usbdrive)")
	if err != nil {
		return err
	}
	mountPoint = strings.TrimSpace(mountPoint)
	if mountPoint == "" {
		return eos_err.NewExpectedError(ctx, fmt.Errorf("mount point cannot be empty"))
	}

	// Create and add fstab entry
	entry := FstabEntry{
		UUID:       uuid,
		Mountpoint: mountPoint,
		Type:       fsType,
		Options:    "defaults",
		Dump:       0,
		Pass:       2,
	}

	if err := AddFstabEntry(rc, entry); err != nil {
		return err
	}

	// Display updated fstab
	fstabContent, err := os.ReadFile("/etc/fstab")
	if err != nil {
		logger.Warn("Failed to read updated fstab", zap.Error(err))
	} else {
		logger.Info("Updated /etc/fstab:")
		scanner := bufio.NewScanner(strings.NewReader(string(fstabContent)))
		for scanner.Scan() {
			logger.Info(scanner.Text())
		}
	}

	// Mount all filesystems
	if err := MountAll(rc); err != nil {
		logger.Error("Failed to mount filesystems", zap.Error(err))
		return err
	}

	// Show current disk usage
	usage, err := GetDiskUsage(rc)
	if err != nil {
		logger.Warn("Failed to get disk usage", zap.Error(err))
	} else {
		logger.Info("Current disk usage:")
		scanner := bufio.NewScanner(strings.NewReader(usage))
		for scanner.Scan() {
			logger.Info(scanner.Text())
		}
	}

	// Reload systemd
	if err := ReloadSystemd(rc); err != nil {
		logger.Warn("Failed to reload systemd", zap.Error(err))
	}

	logger.Info("Fstab management completed successfully")
	return nil
}