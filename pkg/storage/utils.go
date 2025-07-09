package storage

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// ParseSize parses size strings like "100G", "1T", "500M" to bytes
func ParseSize(sizeStr string) (int64, error) {
	sizeStr = strings.TrimSpace(strings.ToUpper(sizeStr))
	
	// Regular expression to match size format
	re := regexp.MustCompile(`^(\d+(?:\.\d+)?)\s*([KMGTPE]?)(?:I?B)?$`)
	matches := re.FindStringSubmatch(sizeStr)
	
	if len(matches) != 3 {
		return 0, fmt.Errorf("invalid size format: %s (expected format: 100G, 1.5T, etc.)", sizeStr)
	}
	
	// Parse the numeric value
	value, err := strconv.ParseFloat(matches[1], 64)
	if err != nil {
		return 0, fmt.Errorf("invalid numeric value: %s", matches[1])
	}
	
	// Parse the unit
	unit := matches[2]
	var multiplier float64
	
	switch unit {
	case "", "B":
		multiplier = 1
	case "K":
		multiplier = 1024
	case "M":
		multiplier = 1024 * 1024
	case "G":
		multiplier = 1024 * 1024 * 1024
	case "T":
		multiplier = 1024 * 1024 * 1024 * 1024
	case "P":
		multiplier = 1024 * 1024 * 1024 * 1024 * 1024
	case "E":
		multiplier = 1024 * 1024 * 1024 * 1024 * 1024 * 1024
	default:
		return 0, fmt.Errorf("invalid unit: %s", unit)
	}
	
	bytes := int64(value * multiplier)
	
	// Validate size is within reasonable bounds
	if bytes < MinVolumeSize {
		return 0, fmt.Errorf("size too small: minimum is %s", FormatSize(MinVolumeSize))
	}
	
	if bytes > MaxVolumeSize {
		return 0, fmt.Errorf("size too large: maximum is %s", FormatSize(MaxVolumeSize))
	}
	
	return bytes, nil
}

// FormatSize formats bytes to human-readable size string
func FormatSize(bytes int64) string {
	const (
		KB = 1024
		MB = 1024 * KB
		GB = 1024 * MB
		TB = 1024 * GB
		PB = 1024 * TB
	)
	
	switch {
	case bytes >= PB:
		return fmt.Sprintf("%.2f PB", float64(bytes)/float64(PB))
	case bytes >= TB:
		return fmt.Sprintf("%.2f TB", float64(bytes)/float64(TB))
	case bytes >= GB:
		return fmt.Sprintf("%.2f GB", float64(bytes)/float64(GB))
	case bytes >= MB:
		return fmt.Sprintf("%.2f MB", float64(bytes)/float64(MB))
	case bytes >= KB:
		return fmt.Sprintf("%.2f KB", float64(bytes)/float64(KB))
	default:
		return fmt.Sprintf("%d bytes", bytes)
	}
}

// CalculateUsagePercent calculates usage percentage
func CalculateUsagePercent(used, total int64) float64 {
	if total == 0 {
		return 0
	}
	return float64(used) / float64(total) * 100
}

// IsValidFilesystem checks if a filesystem type is valid
func IsValidFilesystem(fs FilesystemType) bool {
	switch fs {
	case FilesystemExt4, FilesystemXFS, FilesystemBTRFS, FilesystemZFS:
		return true
	default:
		return false
	}
}

// IsValidStorageType checks if a storage type is valid
func IsValidStorageType(st StorageType) bool {
	switch st {
	case StorageTypeLVM, StorageTypeBTRFS, StorageTypeZFS, StorageTypeCephFS:
		return true
	default:
		return false
	}
}

// GetDefaultMountOptions returns default mount options for a filesystem
func GetDefaultMountOptions(fs FilesystemType) []string {
	switch fs {
	case FilesystemExt4:
		return []string{"defaults", "noatime"}
	case FilesystemXFS:
		return []string{"defaults", "noatime", "nodiratime"}
	case FilesystemBTRFS:
		return []string{"defaults", "noatime", "space_cache=v2"}
	case FilesystemZFS:
		return []string{"defaults"}
	default:
		return []string{"defaults"}
	}
}

// ValidateMountPath validates a mount path
func ValidateMountPath(path string) error {
	if path == "" {
		return nil // Empty path is valid (no mount)
	}
	
	if !strings.HasPrefix(path, "/") {
		return fmt.Errorf("mount path must be absolute: %s", path)
	}
	
	if len(path) > MaxMountPathLength {
		return fmt.Errorf("mount path too long: maximum %d characters", MaxMountPathLength)
	}
	
	// Check for invalid characters
	invalidChars := []string{"..", "//", " ", "\t", "\n", "\r"}
	for _, char := range invalidChars {
		if strings.Contains(path, char) {
			return fmt.Errorf("mount path contains invalid characters: %s", path)
		}
	}
	
	return nil
}

// ValidateLabel validates a volume label
func ValidateLabel(label string) error {
	if label == "" {
		return nil // Empty label is valid
	}
	
	if len(label) > MaxLabelLength {
		return fmt.Errorf("label too long: maximum %d characters", MaxLabelLength)
	}
	
	// Check for valid characters (alphanumeric, dash, underscore)
	validLabel := regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	if !validLabel.MatchString(label) {
		return fmt.Errorf("label contains invalid characters: %s", label)
	}
	
	return nil
}

// GetStorageTypeFromDevice attempts to determine storage type from device path
func GetStorageTypeFromDevice(device string) (StorageType, error) {
	device = strings.ToLower(device)
	
	// LVM logical volumes
	if strings.Contains(device, "/dev/mapper/") || strings.Contains(device, "/dev/") && strings.Count(device, "/") > 2 {
		return StorageTypeLVM, nil
	}
	
	// ZFS datasets
	if strings.HasPrefix(device, "zfs:") || strings.Contains(device, "zpool") {
		return StorageTypeZFS, nil
	}
	
	// CephFS
	if strings.Contains(device, "ceph") || strings.Contains(device, "rbd") {
		return StorageTypeCephFS, nil
	}
	
	// BTRFS (harder to detect from device alone)
	// Would need to check filesystem type
	
	return "", fmt.Errorf("unable to determine storage type from device: %s", device)
}

// MergeStringSlices merges two string slices, removing duplicates
func MergeStringSlices(a, b []string) []string {
	seen := make(map[string]bool)
	result := []string{}
	
	for _, s := range a {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	
	for _, s := range b {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	
	return result
}

// ParseMountOptions parses mount options string to slice
func ParseMountOptions(options string) []string {
	if options == "" {
		return []string{}
	}
	
	// Split by comma and trim spaces
	opts := strings.Split(options, ",")
	for i := range opts {
		opts[i] = strings.TrimSpace(opts[i])
	}
	
	return opts
}

// JoinMountOptions joins mount options slice to string
func JoinMountOptions(options []string) string {
	return strings.Join(options, ",")
}

// HealthStatusFromUsage returns health status based on usage percentage
func HealthStatusFromUsage(usagePercent float64) HealthStatus {
	switch {
	case usagePercent >= CriticalThreshold:
		return HealthCritical
	case usagePercent >= WarningThreshold:
		return HealthDegraded
	default:
		return HealthGood
	}
}

// StorageStateFromString converts string to StorageState
func StorageStateFromString(s string) StorageState {
	switch strings.ToLower(s) {
	case "active", "online":
		return StorageStateActive
	case "inactive", "offline":
		return StorageStateInactive
	case "degraded":
		return StorageStateDegraded
	case "failed", "error":
		return StorageStateFailed
	case "creating":
		return StorageStateCreating
	case "deleting":
		return StorageStateDeleting
	default:
		return StorageStateUnknown
	}
}