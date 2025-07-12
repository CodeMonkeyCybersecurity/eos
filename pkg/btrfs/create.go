package btrfs

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CreateVolume creates a new BTRFS volume
func CreateVolume(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Validate configuration for security
	if err := validateBtrfsConfig(config); err != nil {
		return err
	}

	// ASSESS
	logger.Info("Assessing device for BTRFS volume creation",
		zap.String("device", config.Device))

	// Check if device exists
	if _, err := os.Stat(config.Device); err != nil {
		return eos_err.NewUserError("device not found: %s", config.Device)
	}

	// Check if device is mounted
	if mounted, mountPoint := isDeviceMounted(rc, config.Device); mounted {
		return eos_err.NewUserError("device %s is mounted at %s. Please unmount first",
			config.Device, mountPoint)
	}

	// Check for existing filesystem
	if !config.Force {
		if hasFS, fsType := deviceHasFilesystem(rc, config.Device); hasFS {
			return eos_err.NewUserError("device %s contains %s filesystem. Use --force to overwrite",
				config.Device, fsType)
		}
	}

	// INTERVENE
	logger.Info("Creating BTRFS volume",
		zap.String("device", config.Device),
		zap.String("label", config.Label))

	// Build mkfs.btrfs command
	args := []string{"mkfs.btrfs"}

	if config.Force {
		args = append(args, "-f")
	}

	if config.Label != "" {
		args = append(args, "-L", config.Label)
	}

	if config.UUID != "" {
		args = append(args, "-U", config.UUID)
	}

	if config.MixedMode {
		args = append(args, "-M")
	}

	if config.Nodatasum {
		args = append(args, "--nodatasum")
	}

	args = append(args, config.Device)

	mkfsCmd := exec.CommandContext(rc.Ctx, args[0], args[1:]...)
	output, err := mkfsCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to create BTRFS volume: %w, output: %s", err, string(output))
	}

	logger.Debug("BTRFS volume created",
		zap.String("output", string(output)))

	// Mount if mount point specified
	if config.MountPoint != "" {
		if err := mountVolume(rc, config); err != nil {
			return fmt.Errorf("volume created but mount failed: %w", err)
		}
	}

	// EVALUATE
	logger.Info("Verifying BTRFS volume creation")

	// Verify filesystem was created
	info, err := GetVolumeInfo(rc, config.Device)
	if err != nil {
		return fmt.Errorf("volume verification failed: %w", err)
	}

	if config.Label != "" && info.Label != config.Label {
		logger.Warn("Volume label mismatch",
			zap.String("expected", config.Label),
			zap.String("actual", info.Label))
	}

	logger.Info("BTRFS volume created successfully",
		zap.String("uuid", info.UUID),
		zap.Int64("size", info.TotalSize))

	return nil
}

// CreateSubvolume creates a BTRFS subvolume
func CreateSubvolume(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Validate configuration for security
	if err := validateBtrfsConfig(config); err != nil {
		return err
	}

	// ASSESS
	logger.Info("Assessing subvolume creation requirements",
		zap.String("path", config.SubvolumePath))

	// Check if parent path exists
	parentPath := getParentPath(config.SubvolumePath)
	if _, err := os.Stat(parentPath); err != nil {
		return eos_err.NewUserError("parent path does not exist: %s", parentPath)
	}

	// Check if path is on BTRFS
	if !isPathOnBTRFS(rc, parentPath) {
		return eos_err.NewUserError("path %s is not on a BTRFS filesystem", parentPath)
	}

	// Check if subvolume already exists
	if _, err := os.Stat(config.SubvolumePath); err == nil {
		return eos_err.NewUserError("subvolume already exists: %s", config.SubvolumePath)
	}

	// INTERVENE
	logger.Info("Creating BTRFS subvolume",
		zap.String("path", config.SubvolumePath))

	// Create subvolume
	if err := execute.RunSimple(rc.Ctx, "btrfs", "subvolume", "create", config.SubvolumePath); err != nil {
		return fmt.Errorf("failed to create subvolume: %w", err)
	}

	// Set compression if specified
	if config.Compression != "" && config.Compression != CompressionNone {
		if err := setCompression(rc, config.SubvolumePath, config.Compression, config.CompressionLevel); err != nil {
			logger.Warn("Failed to set compression on subvolume",
				zap.Error(err))
		}
	}

	// Set CoW settings if specified
	if config.DisableCoW || config.Nodatacow {
		if err := disableCoW(rc, config.SubvolumePath); err != nil {
			logger.Warn("Failed to disable CoW on subvolume",
				zap.Error(err))
		}
	}

	// EVALUATE
	logger.Info("Verifying subvolume creation")

	// Get subvolume info
	info, err := GetSubvolumeInfo(rc, config.SubvolumePath)
	if err != nil {
		return fmt.Errorf("subvolume verification failed: %w", err)
	}

	logger.Info("BTRFS subvolume created successfully",
		zap.String("path", config.SubvolumePath),
		zap.Int64("id", info.ID))

	return nil
}

// GetVolumeInfo retrieves BTRFS volume information
func GetVolumeInfo(rc *eos_io.RuntimeContext, device string) (*VolumeInfo, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing BTRFS volume",
		zap.String("device", device))

	// INTERVENE
	logger.Info("Reading BTRFS volume information")

	info := &VolumeInfo{
		Devices: []string{device},
	}

	// Get filesystem info
	showCmd := exec.CommandContext(rc.Ctx, "btrfs", "filesystem", "show", device)
	output, err := showCmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get volume info: %w", err)
	}

	// Parse output
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "Label:") {
			// Parse label and UUID
			parts := strings.Fields(line)
			for i, part := range parts {
				if part == "Label:" && i+1 < len(parts) {
					info.Label = strings.Trim(parts[i+1], "'\"")
				}
				if part == "uuid:" && i+1 < len(parts) {
					info.UUID = parts[i+1]
				}
			}
		} else if strings.Contains(line, "Total devices") {
			// Parse device count
			fields := strings.Fields(line)
			for i, field := range fields {
				if field == "devices" && i > 0 {
					if _, err := fmt.Sscanf(fields[i-1], "%d", &info.DeviceCount); err != nil {
						logger.Warn("Failed to parse device count",
							zap.String("value", fields[i-1]),
							zap.Error(err))
					}
				}
			}
		} else if strings.Contains(line, "devid") && strings.Contains(line, "size") {
			// Parse device size
			fields := strings.Fields(line)
			for i, field := range fields {
				if field == "size" && i+1 < len(fields) {
					sizeStr := fields[i+1]
					info.TotalSize = parseBTRFSSize(sizeStr)
				}
			}
		}
	}

	// Get usage information
	if usage, err := getUsageInfo(rc, device); err == nil {
		info.UsedSize = usage.UsedSize
	}

	// Get features
	if features, err := getFeatures(rc, device); err == nil {
		info.Features = features
	}

	// Get mount points
	if mounts, err := getMountPoints(rc, info.UUID); err == nil {
		info.MountPoints = mounts
	}

	// EVALUATE
	logger.Info("BTRFS volume information retrieved",
		zap.String("uuid", info.UUID),
		zap.String("label", info.Label),
		zap.Int64("totalSize", info.TotalSize),
		zap.Int64("usedSize", info.UsedSize))

	return info, nil
}

// GetSubvolumeInfo retrieves subvolume information
func GetSubvolumeInfo(rc *eos_io.RuntimeContext, path string) (*SubvolumeInfo, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing BTRFS subvolume",
		zap.String("path", path))

	// INTERVENE
	logger.Info("Reading subvolume information")

	// Get subvolume info
	showCmd := exec.CommandContext(rc.Ctx, "btrfs", "subvolume", "show", path)
	output, err := showCmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get subvolume info: %w", err)
	}

	info := &SubvolumeInfo{
		Path: path,
	}

	// Parse output
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "Subvolume ID:") {
			fmt.Sscanf(line, "Subvolume ID: %d", &info.ID)
		} else if strings.HasPrefix(line, "Parent ID:") {
			fmt.Sscanf(line, "Parent ID: %d", &info.ParentID)
		} else if strings.HasPrefix(line, "Top level ID:") {
			fmt.Sscanf(line, "Top level ID: %d", &info.TopLevel)
		} else if strings.HasPrefix(line, "Generation:") {
			fmt.Sscanf(line, "Generation: %d", &info.Generation)
		} else if strings.HasPrefix(line, "UUID:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				info.UUID = fields[1]
			}
		} else if strings.HasPrefix(line, "Parent UUID:") {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				info.ParentUUID = fields[2]
			}
		}
	}

	// Get snapshots of this subvolume
	if snapshots, err := listSnapshots(rc, info.UUID); err == nil {
		info.Snapshots = snapshots
	}

	// EVALUATE
	logger.Info("Subvolume information retrieved",
		zap.String("path", path),
		zap.Int64("id", info.ID),
		zap.String("uuid", info.UUID))

	return info, nil
}

// Helper functions

func mountVolume(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Create mount point
	if err := os.MkdirAll(config.MountPoint, 0755); err != nil {
		return fmt.Errorf("failed to create mount point: %w", err)
	}

	// Build mount options
	options := config.MountOptions
	if len(options) == 0 {
		// Use default options based on use case
		if strings.Contains(config.MountPoint, "backup") {
			options = MountOptions["backup"]
		} else {
			options = MountOptions["general"]
		}
	}

	// Mount the filesystem
	args := []string{"mount", "-t", "btrfs"}
	if len(options) > 0 {
		args = append(args, "-o", strings.Join(options, ","))
	}
	args = append(args, config.Device, config.MountPoint)

	mountCmd := exec.CommandContext(rc.Ctx, args[0], args[1:]...)
	if output, err := mountCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to mount: %w, output: %s", err, string(output))
	}

	logger.Info("BTRFS volume mounted",
		zap.String("device", config.Device),
		zap.String("mountPoint", config.MountPoint),
		zap.Strings("options", options))

	return nil
}

func isDeviceMounted(rc *eos_io.RuntimeContext, device string) (bool, string) {
	findmntCmd := exec.CommandContext(rc.Ctx, "findmnt", "-n", "-o", "TARGET", device)
	if output, err := findmntCmd.Output(); err == nil {
		return true, strings.TrimSpace(string(output))
	}
	return false, ""
}

func deviceHasFilesystem(rc *eos_io.RuntimeContext, device string) (bool, string) {
	blkidCmd := exec.CommandContext(rc.Ctx, "blkid", "-o", "value", "-s", "TYPE", device)
	if output, err := blkidCmd.Output(); err == nil {
		fsType := strings.TrimSpace(string(output))
		return fsType != "", fsType
	}
	return false, ""
}

func isPathOnBTRFS(rc *eos_io.RuntimeContext, path string) bool {
	statCmd := exec.CommandContext(rc.Ctx, "stat", "-f", "-c", "%T", path)
	if output, err := statCmd.Output(); err == nil {
		return strings.TrimSpace(string(output)) == "btrfs"
	}
	return false
}

func getParentPath(path string) string {
	return strings.TrimSuffix(path, "/"+filepath.Base(path))
}

func setCompression(rc *eos_io.RuntimeContext, path string, algorithm string, level int) error {
	// Set compression property
	compression := algorithm
	if algorithm == CompressionZSTD && level > 0 {
		compression = fmt.Sprintf("%s:%d", algorithm, level)
	}

	propCmd := exec.CommandContext(rc.Ctx, "btrfs", "property", "set", path, "compression", compression)
	if output, err := propCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to set compression: %w, output: %s", err, string(output))
	}

	return nil
}

func disableCoW(rc *eos_io.RuntimeContext, path string) error {
	// Use chattr to disable CoW
	return execute.RunSimple(rc.Ctx, "chattr", "+C", path)
}

func getUsageInfo(rc *eos_io.RuntimeContext, device string) (*UsageInfo, error) {
	// Implementation would parse btrfs filesystem usage output
	return &UsageInfo{}, nil
}

func getFeatures(rc *eos_io.RuntimeContext, device string) ([]string, error) {
	// Implementation would get enabled features
	return []string{}, nil
}

func getMountPoints(rc *eos_io.RuntimeContext, uuid string) ([]string, error) {
	// Implementation would find all mount points for the UUID
	return []string{}, nil
}

func listSnapshots(rc *eos_io.RuntimeContext, parentUUID string) ([]string, error) {
	// Implementation would list all snapshots of a subvolume
	return []string{}, nil
}

func parseBTRFSSize(sizeStr string) int64 {
	// Parse size strings like "10.00GiB"
	// Implementation would handle various size formats
	return 0
}

// validateBtrfsConfig validates BTRFS configuration for security vulnerabilities
func validateBtrfsConfig(config *Config) error {
	// Validate device path
	if err := validateDevicePath(config.Device); err != nil {
		return fmt.Errorf("invalid device path: %w", err)
	}

	// Validate mount point if specified
	if config.MountPoint != "" {
		if err := validateMountPath(config.MountPoint); err != nil {
			return fmt.Errorf("invalid mount point: %w", err)
		}
	}

	// Validate subvolume paths if specified
	if config.SubvolumePath != "" {
		if err := validateSubvolumePath(config.SubvolumePath); err != nil {
			return fmt.Errorf("invalid subvolume path: %w", err)
		}
	}

	// Validate mount options
	for _, option := range config.MountOptions {
		if err := validateMountOption(option); err != nil {
			return fmt.Errorf("invalid mount option: %w", err)
		}
	}

	// Validate label for command injection
	if config.Label != "" {
		if err := validateLabel(config.Label); err != nil {
			return fmt.Errorf("invalid label: %w", err)
		}
	}

	return nil
}

// validateDevicePath validates that a device path is safe
func validateDevicePath(path string) error {
	// Check for empty path
	if path == "" {
		return fmt.Errorf("device path cannot be empty")
	}

	// Check for null bytes and control characters
	if strings.ContainsAny(path, "\x00\n\r\t") {
		return fmt.Errorf("device path cannot contain null bytes or control characters")
	}

	// Check for command injection patterns
	if strings.ContainsAny(path, ";|&`$(){}[]<>\"'") {
		return fmt.Errorf("device path contains command injection patterns")
	}

	// Check for path traversal attempts
	if strings.Contains(path, "..") {
		return fmt.Errorf("device path cannot contain '..' (path traversal)")
	}

	// Device paths should be absolute and start with /dev/
	if !strings.HasPrefix(path, "/dev/") {
		return fmt.Errorf("device path must start with /dev/")
	}

	// Clean the path and check it hasn't changed
	cleanPath := filepath.Clean(path)
	if cleanPath != path {
		return fmt.Errorf("device path contains unsafe elements")
	}

	// Check path length limit
	if len(path) > 256 {
		return fmt.Errorf("device path too long (max 256 characters)")
	}

	return nil
}

// validateMountPath validates that a mount path is safe
func validateMountPath(path string) error {
	// Check for empty path
	if path == "" {
		return fmt.Errorf("mount path cannot be empty")
	}

	// Check for null bytes and control characters
	if strings.ContainsAny(path, "\x00\n\r\t") {
		return fmt.Errorf("mount path cannot contain null bytes or control characters")
	}

	// Check for command injection patterns
	if strings.ContainsAny(path, ";|&`$(){}[]<>\"'") {
		return fmt.Errorf("mount path contains command injection patterns")
	}

	// Check for path traversal attempts
	if strings.Contains(path, "..") {
		return fmt.Errorf("mount path cannot contain '..' (path traversal)")
	}

	// Ensure path is absolute
	if !filepath.IsAbs(path) {
		return fmt.Errorf("mount path must be absolute (start with /)")
	}

	// Clean the path and check it hasn't changed
	cleanPath := filepath.Clean(path)
	if cleanPath != path {
		return fmt.Errorf("mount path contains unsafe elements")
	}

	// Check for sensitive system paths
	sensitivePaths := []string{"/", "/etc", "/boot", "/dev", "/proc", "/sys", "/root"}
	for _, sensitive := range sensitivePaths {
		if cleanPath == sensitive || strings.HasPrefix(cleanPath, sensitive+"/") {
			return fmt.Errorf("cannot mount on sensitive system path: %s", sensitive)
		}
	}

	// Check path length limit
	if len(path) > 4096 {
		return fmt.Errorf("mount path too long (max 4096 characters)")
	}

	return nil
}

// validateSubvolumePath validates that a subvolume path is safe
func validateSubvolumePath(path string) error {
	// Check for empty path
	if path == "" {
		return fmt.Errorf("subvolume path cannot be empty")
	}

	// Check for null bytes and control characters
	if strings.ContainsAny(path, "\x00\n\r\t") {
		return fmt.Errorf("subvolume path cannot contain null bytes or control characters")
	}

	// Check for command injection patterns
	if strings.ContainsAny(path, ";|&`$(){}[]<>\"'") {
		return fmt.Errorf("subvolume path contains command injection patterns")
	}

	// Check for path traversal attempts
	if strings.Contains(path, "..") {
		return fmt.Errorf("subvolume path cannot contain '..' (path traversal)")
	}

	// Ensure path is absolute
	if !filepath.IsAbs(path) {
		return fmt.Errorf("subvolume path must be absolute (start with /)")
	}

	// Clean the path and check it hasn't changed
	cleanPath := filepath.Clean(path)
	if cleanPath != path {
		return fmt.Errorf("subvolume path contains unsafe elements")
	}

	// Check for sensitive system paths
	sensitivePaths := []string{"/", "/etc", "/boot", "/dev", "/proc", "/sys", "/root"}
	for _, sensitive := range sensitivePaths {
		if cleanPath == sensitive || strings.HasPrefix(cleanPath, sensitive+"/") {
			return fmt.Errorf("cannot create subvolume on sensitive system path: %s", sensitive)
		}
	}

	// Check path length limit
	if len(path) > 4096 {
		return fmt.Errorf("subvolume path too long (max 4096 characters)")
	}

	return nil
}

// validateMountOption validates that a mount option is safe
func validateMountOption(option string) error {
	// Check for empty option
	if option == "" {
		return fmt.Errorf("mount option cannot be empty")
	}

	// Check for null bytes and control characters
	if strings.ContainsAny(option, "\x00\n\r\t") {
		return fmt.Errorf("mount option cannot contain null bytes or control characters")
	}

	// Check for command injection patterns
	if strings.ContainsAny(option, ";|&`$(){}[]<>\"'") {
		return fmt.Errorf("mount option contains command injection patterns")
	}

	// Check option length limit
	if len(option) > 256 {
		return fmt.Errorf("mount option too long (max 256 characters)")
	}

	// Validate against known safe mount options
	validOptions := map[string]bool{
		"compress":        true,
		"compress-force":  true,
		"noatime":         true,
		"nodatacow":       true,
		"nodatasum":       true,
		"autodefrag":      true,
		"space_cache":     true,
		"space_cache=v2":  true,
		"ssd":             true,
		"discard":         true,
		"discard=async":   true,
		"nossd":           true,
		"noacl":           true,
		"barrier":         true,
		"nobarrier":       true,
		"datacow":         true,
		"datasum":         true,
		"treelog":         true,
		"notreelog":       true,
		"flushoncommit":   true,
		"noflushoncommit": true,
		"degraded":        true,
		"ro":              true,
		"rw":              true,
	}

	// Extract base option (before = or :)
	baseOption := strings.Split(strings.Split(option, "=")[0], ":")[0]

	// Check for compression options with levels
	if strings.HasPrefix(baseOption, "compress") {
		// Allow compress, compress-force with compression types and levels
		return nil
	}

	// Check if it's a known valid option
	if !validOptions[baseOption] {
		return fmt.Errorf("unknown or unsafe mount option: %s", baseOption)
	}

	return nil
}

// validateLabel validates that a filesystem label is safe
func validateLabel(label string) error {
	// Check for null bytes and control characters
	if strings.ContainsAny(label, "\x00\n\r\t") {
		return fmt.Errorf("label cannot contain null bytes or control characters")
	}

	// Check for command injection patterns
	if strings.ContainsAny(label, ";|&`$(){}[]<>\"'") {
		return fmt.Errorf("label contains command injection patterns")
	}

	// Check label length limit (BTRFS max is 256 bytes)
	if len(label) > 256 {
		return fmt.Errorf("label too long (max 256 characters)")
	}

	return nil
}
