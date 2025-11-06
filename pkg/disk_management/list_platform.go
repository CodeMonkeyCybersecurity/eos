// pkg/disk_management/list_platform.go
package disk_management

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// listDisksLinux lists disks on Linux using lsblk
func listDisksLinux(rc *eos_io.RuntimeContext) ([]DiskInfo, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Executing lsblk directly")
	cmd := exec.CommandContext(rc.Ctx, "lsblk", "-J", "-o", "NAME,SIZE,TYPE,MOUNTPOINT,VENDOR,MODEL,SERIAL,RM,FSTYPE,LABEL,UUID")
	output, err := cmd.CombinedOutput()
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

	return parseLsblkOutput(string(output))
}

// listDisksDarwin lists disks on macOS using diskutil
func listDisksDarwin(rc *eos_io.RuntimeContext) ([]DiskInfo, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Executing diskutil directly")
	cmd := exec.CommandContext(rc.Ctx, "diskutil", "list", "-plist")
	output, err := cmd.CombinedOutput()
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

	// For now, parse basic diskutil output
	// In a full implementation, we would parse the plist XML format
	return parseDiskutilOutput(string(output))
}

// listPartitionsLinux lists partitions on a specific disk using lsblk
func listPartitionsLinux(rc *eos_io.RuntimeContext, diskPath string) ([]PartitionInfo, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Listing partitions for disk", zap.String("disk", diskPath))
	cmd := exec.CommandContext(rc.Ctx, "lsblk", "-J", "-o", "NAME,SIZE,TYPE,MOUNTPOINT,FSTYPE,LABEL,UUID", diskPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to list partitions: %w", err)
	}

	// Parse lsblk output and extract partitions
	disks, err := parseLsblkOutput(string(output))
	if err != nil {
		return nil, err
	}

	if len(disks) == 0 {
		return []PartitionInfo{}, nil
	}

	return disks[0].Partitions, nil
}

// listPartitionsDarwin lists partitions on a specific disk using diskutil
func listPartitionsDarwin(rc *eos_io.RuntimeContext, diskPath string) ([]PartitionInfo, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Listing partitions for disk", zap.String("disk", diskPath))
	cmd := exec.CommandContext(rc.Ctx, "diskutil", "list", diskPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to list partitions: %w", err)
	}

	// Parse diskutil output to extract partitions
	return parseDiskutilPartitions(string(output)), nil
}

// getMountedVolumesLinux returns all currently mounted volumes on Linux
func getMountedVolumesLinux(rc *eos_io.RuntimeContext) ([]MountedVolume, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Getting mounted volumes on Linux")
	cmd := exec.CommandContext(rc.Ctx, "mount")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get mounted volumes: %w", err)
	}

	return parseMountOutput(string(output)), nil
}

// getMountedVolumesDarwin returns all currently mounted volumes on macOS
func getMountedVolumesDarwin(rc *eos_io.RuntimeContext) ([]MountedVolume, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Getting mounted volumes on macOS")
	cmd := exec.CommandContext(rc.Ctx, "mount")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get mounted volumes: %w", err)
	}

	return parseMountOutput(string(output)), nil
}

// parseLsblkOutput parses JSON output from lsblk
func parseLsblkOutput(output string) ([]DiskInfo, error) {
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
func parseDiskutilOutput(output string) ([]DiskInfo, error) {
	// For a simple implementation, parse the text output from diskutil list
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

// parseDiskutilInfo parses the output of diskutil info command
func parseDiskutilInfo(device string, output string) *DiskInfo {
	disk := &DiskInfo{
		Device:      device,
		Name:        device,
		Mountpoints: make([]MountPoint, 0),
		Partitions:  make([]PartitionInfo, 0),
		Properties:  make(map[string]string),
	}

	// Parse the diskutil info output
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Parse key-value pairs
		colonIndex := strings.Index(line, ":")
		if colonIndex > 0 {
			key := strings.TrimSpace(line[:colonIndex])
			value := strings.TrimSpace(line[colonIndex+1:])

			switch key {
			case "Device / Media Name":
				disk.Name = value
			case "Disk Size":
				// Extract human-readable size
				parts := strings.Fields(value)
				if len(parts) >= 2 {
					disk.SizeHuman = parts[0] + parts[1]
				}
			case "Device Block Size":
				disk.Properties["block_size"] = value
			case "Volume Name":
				disk.Properties["volume_name"] = value
			case "Mount Point":
				if value != "" && value != "Not applicable" {
					disk.Mountpoints = append(disk.Mountpoints, MountPoint{
						Path:     value,
						Readonly: false,
					})
				}
			case "Content":
				disk.Properties["content"] = value
			case "Volume UUID":
				disk.Properties["uuid"] = value
			case "Disk / Partition UUID":
				if disk.Properties["uuid"] == "" {
					disk.Properties["uuid"] = value
				}
			case "Removable Media":
				disk.IsRemovable = (value == "Yes" || value == "Removable")
			case "Protocol":
				disk.Properties["protocol"] = value
				if strings.Contains(value, "USB") {
					disk.IsUSB = true
				}
			}
		}
	}

	// Set a description
	if mediaName, ok := disk.Properties["volume_name"]; ok && mediaName != "" {
		disk.Description = mediaName
	} else {
		disk.Description = fmt.Sprintf("Disk %s", disk.Name)
	}

	return disk
}

// parseDiskutilPartitions parses diskutil list output to extract partitions
func parseDiskutilPartitions(output string) []PartitionInfo {
	var partitions []PartitionInfo

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "/dev/disk") && !strings.Contains(line, "whole") {
			// This looks like a partition line
			parts := strings.Fields(line)
			if len(parts) > 0 {
				partition := PartitionInfo{
					Device:     parts[0],
					Type:       "partition",
					IsMounted:  false, // Would need additional logic to determine
					MountPoint: "",    // Would need additional logic to determine
				}
				partitions = append(partitions, partition)
			}
		}
	}

	return partitions
}

// parseMountOutput parses the output of the mount command
func parseMountOutput(output string) []MountedVolume {
	var volumes []MountedVolume

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Parse mount output format: device on mountpoint type filesystem (options)
		parts := strings.Fields(line)
		if len(parts) >= 4 && parts[1] == "on" {
			device := parts[0]
			mountPoint := parts[2]

			// Find filesystem type (after "type")
			var filesystem string
			for i, part := range parts {
				if part == "type" && i+1 < len(parts) {
					filesystem = parts[i+1]
					break
				}
			}

			volume := MountedVolume{
				Device:     device,
				MountPoint: mountPoint,
				Filesystem: filesystem,
				Options:    "", // Could parse options from the line if needed
			}
			volumes = append(volumes, volume)
		}
	}

	return volumes
}
