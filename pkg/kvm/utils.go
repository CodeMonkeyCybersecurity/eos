package kvm

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// GenerateVMName generates a unique VM name with timestamp
func GenerateVMName(base string) string {
	timestamp := time.Now().Format("20060102-1504")
	if base == "" {
		base = "ubuntu"
	}
	return fmt.Sprintf("%s-vm-%s", base, timestamp)
}

// GetRealUserIDs returns the real user's UID and GID when running under sudo
// Returns (-1, -1) if not running under sudo or if values can't be determined
func GetRealUserIDs() (uid int, gid int) {
	uid = -1
	gid = -1

	// Check if running under sudo
	sudoUID := os.Getenv("SUDO_UID")
	sudoGID := os.Getenv("SUDO_GID")

	if sudoUID != "" {
		if parsedUID, err := strconv.Atoi(sudoUID); err == nil {
			uid = parsedUID
		}
	}

	if sudoGID != "" {
		if parsedGID, err := strconv.Atoi(sudoGID); err == nil {
			gid = parsedGID
		}
	}

	return uid, gid
}

// ParseMemorySize parses a human-readable memory size (e.g., "4GB", "512MB") to megabytes
func ParseMemorySize(size string) (int, error) {
	size = strings.TrimSpace(strings.ToUpper(size))

	if size == "" {
		return 0, fmt.Errorf("empty memory size")
	}

	// Check for units
	var multiplier int
	var numberPart string

	if strings.HasSuffix(size, "TB") {
		multiplier = 1024 * 1024
		numberPart = strings.TrimSuffix(size, "TB")
	} else if strings.HasSuffix(size, "GB") {
		multiplier = 1024
		numberPart = strings.TrimSuffix(size, "GB")
	} else if strings.HasSuffix(size, "MB") {
		multiplier = 1
		numberPart = strings.TrimSuffix(size, "MB")
	} else if strings.HasSuffix(size, "KB") {
		// Convert KB to MB (round up)
		numberPart = strings.TrimSuffix(size, "KB")
		value, err := strconv.ParseFloat(numberPart, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid memory size: %s", size)
		}
		return int((value + 1023) / 1024), nil
	} else {
		// Assume bytes if no unit
		value, err := strconv.ParseInt(size, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid memory size: %s", size)
		}
		// Convert bytes to MB
		return int((value + 1024*1024 - 1) / (1024 * 1024)), nil
	}

	value, err := strconv.ParseFloat(numberPart, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid memory size: %s", size)
	}

	return int(value * float64(multiplier)), nil
}

// ParseDiskSize parses a human-readable disk size (e.g., "100GB", "1TB") to bytes
func ParseDiskSize(size string) (int64, error) {
	size = strings.TrimSpace(strings.ToUpper(size))

	if size == "" {
		return 0, fmt.Errorf("empty disk size")
	}

	// Check for units
	var multiplier int64
	var numberPart string

	if strings.HasSuffix(size, "PB") {
		multiplier = 1024 * 1024 * 1024 * 1024 * 1024
		numberPart = strings.TrimSuffix(size, "PB")
	} else if strings.HasSuffix(size, "TB") {
		multiplier = 1024 * 1024 * 1024 * 1024
		numberPart = strings.TrimSuffix(size, "TB")
	} else if strings.HasSuffix(size, "GB") {
		multiplier = 1024 * 1024 * 1024
		numberPart = strings.TrimSuffix(size, "GB")
	} else if strings.HasSuffix(size, "MB") {
		multiplier = 1024 * 1024
		numberPart = strings.TrimSuffix(size, "MB")
	} else if strings.HasSuffix(size, "KB") {
		multiplier = 1024
		numberPart = strings.TrimSuffix(size, "KB")
	} else {
		// Assume bytes if no unit
		value, err := strconv.ParseInt(size, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid disk size: %s", size)
		}
		return value, nil
	}

	value, err := strconv.ParseFloat(numberPart, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid disk size: %s", size)
	}

	return int64(value * float64(multiplier)), nil
}

// FormatMemorySize formats memory size in MB to human-readable format
func FormatMemorySize(mb int) string {
	if mb >= 1024*1024 {
		return fmt.Sprintf("%.1fTB", float64(mb)/(1024*1024))
	}
	if mb >= 1024 {
		return fmt.Sprintf("%.1fGB", float64(mb)/1024)
	}
	return fmt.Sprintf("%dMB", mb)
}

// FormatDiskSize formats disk size in bytes to human-readable format
func FormatDiskSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}

	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}

	units := []string{"KB", "MB", "GB", "TB", "PB"}
	if exp >= len(units) {
		exp = len(units) - 1
	}

	return fmt.Sprintf("%.1f %s", float64(bytes)/float64(div), units[exp])
}

// ValidateVMName validates a VM name according to libvirt/KVM requirements
func ValidateVMName(name string) error {
	if name == "" {
		return fmt.Errorf("VM name cannot be empty")
	}

	if len(name) > 50 {
		return fmt.Errorf("VM name too long (max 50 characters)")
	}

	// Check for valid characters (alphanumeric, dash, underscore)
	for i, r := range name {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9' && i > 0) || r == '-' || r == '_') {
			return fmt.Errorf("VM name contains invalid character: %c", r)
		}
	}

	// Check it doesn't start with a number
	if name[0] >= '0' && name[0] <= '9' {
		return fmt.Errorf("VM name cannot start with a number")
	}

	return nil
}

// GetDefaultNetwork returns the default network name based on the hypervisor
func GetDefaultNetwork() string {
	return "default"
}

// GetDefaultStoragePool returns the default storage pool name
func GetDefaultStoragePool() string {
	return "default"
}

// EstimateVMCreationTime estimates how long VM creation will take based on configuration
func EstimateVMCreationTime(config *SecureVMConfig) string {
	// Base time in seconds
	baseTime := 60

	// Add time based on disk size
	diskGB, _ := ParseDiskSize(config.DiskSize)
	diskGB = diskGB / (1024 * 1024 * 1024)
	baseTime += int(diskGB) * 2

	// Add time for security features
	if config.EncryptDisk {
		baseTime += 120
	}
	if config.SecurityLevel == "paranoid" {
		baseTime += 180
	} else if config.SecurityLevel == "high" {
		baseTime += 90
	}

	// Convert to human-readable format
	if baseTime < 120 {
		return fmt.Sprintf("~%d seconds", baseTime)
	}
	return fmt.Sprintf("~%d minutes", baseTime/60)
}

// GetVMRequirements returns minimum requirements based on configuration
func GetVMRequirements(config *SecureVMConfig) (minMemoryMB int, minDiskGB int, minVCPUs int) {
	// Base requirements
	minMemoryMB = 512
	minDiskGB = 10
	minVCPUs = 1

	// Adjust based on security level
	switch config.SecurityLevel {
	case "paranoid":
		minMemoryMB = 4096
		minDiskGB = 40
		minVCPUs = 2
	case "high":
		minMemoryMB = 2048
		minDiskGB = 20
		minVCPUs = 2
	case "moderate":
		minMemoryMB = 1024
		minDiskGB = 15
		minVCPUs = 1
	}

	return minMemoryMB, minDiskGB, minVCPUs
}

// CheckSystemResources checks if the system has enough resources for the VM
func CheckSystemResources(config *SecureVMConfig) error {
	// Parse requested resources
	requestedMemoryMB, err := ParseMemorySize(config.Memory)
	if err != nil {
		return fmt.Errorf("invalid memory size: %w", err)
	}

	requestedDiskBytes, err := ParseDiskSize(config.DiskSize)
	if err != nil {
		return fmt.Errorf("invalid disk size: %w", err)
	}
	requestedDiskGB := requestedDiskBytes / (1024 * 1024 * 1024)

	// Get minimum requirements
	minMemoryMB, minDiskGB, minVCPUs := GetVMRequirements(config)

	// Check against minimums
	if requestedMemoryMB < minMemoryMB {
		return fmt.Errorf("insufficient memory: %s requested, minimum %s required for security level %s",
			config.Memory, FormatMemorySize(minMemoryMB), config.SecurityLevel)
	}

	if requestedDiskGB < int64(minDiskGB) {
		return fmt.Errorf("insufficient disk space: %s requested, minimum %dGB required for security level %s",
			config.DiskSize, minDiskGB, config.SecurityLevel)
	}

	if config.VCPUs < minVCPUs {
		return fmt.Errorf("insufficient vCPUs: %d requested, minimum %d required for security level %s",
			config.VCPUs, minVCPUs, config.SecurityLevel)
	}

	return nil
}