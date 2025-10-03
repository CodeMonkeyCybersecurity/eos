// pkg/kvm/utils.go
// Utility functions available in all builds (no build tags)

package kvm

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// SetLibvirtACL sets ACL permissions for libvirt on a directory
func SetLibvirtACL(dir string) {
	fmt.Println("Setting libvirt ACL on directory:", dir)
	cmd := exec.Command("setfacl", "-R", "-m", "u:libvirt-qemu:rx", dir)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	_ = cmd.Run()
}

// ParseMemorySize parses memory size strings (e.g., "2G", "512M", "1024") and returns size in MB
func ParseMemorySize(size string) (int, error) {
	if size == "" {
		return 0, fmt.Errorf("memory size cannot be empty")
	}

	// Handle plain numbers (assume MB)
	if num, err := strconv.Atoi(size); err == nil {
		if num <= 0 {
			return 0, fmt.Errorf("memory size must be positive")
		}
		return num, nil
	}

	// Parse size with unit (e.g., "2G", "512M")
	re := regexp.MustCompile(`^(\d+(?:\.\d+)?)\s*([KMGT]i?B?)?$`)
	matches := re.FindStringSubmatch(strings.ToUpper(size))
	if matches == nil {
		return 0, fmt.Errorf("invalid memory size format: %s (expected: number or number with unit like 2G, 512M)", size)
	}

	value, err := strconv.ParseFloat(matches[1], 64)
	if err != nil {
		return 0, fmt.Errorf("invalid numeric value in memory size: %w", err)
	}

	unit := matches[2]
	if unit == "" {
		unit = "M" // Default to MB
	}

	// Convert to MB
	var multiplier float64
	switch {
	case strings.HasPrefix(unit, "K"):
		multiplier = 1.0 / 1024.0
	case strings.HasPrefix(unit, "M"):
		multiplier = 1.0
	case strings.HasPrefix(unit, "G"):
		multiplier = 1024.0
	case strings.HasPrefix(unit, "T"):
		multiplier = 1024.0 * 1024.0
	default:
		return 0, fmt.Errorf("unsupported memory unit: %s (use K, M, G, or T)", unit)
	}

	result := int(value * multiplier)
	if result <= 0 {
		return 0, fmt.Errorf("memory size must be positive")
	}

	return result, nil
}

// ParseDiskSize parses disk size strings (e.g., "20G", "100G", "1T") and returns size in GB
func ParseDiskSize(size string) (int, error) {
	if size == "" {
		return 0, fmt.Errorf("disk size cannot be empty")
	}

	// Handle plain numbers (assume GB)
	if num, err := strconv.Atoi(size); err == nil {
		if num <= 0 {
			return 0, fmt.Errorf("disk size must be positive")
		}
		return num, nil
	}

	// Parse size with unit (e.g., "20G", "100G")
	re := regexp.MustCompile(`^(\d+(?:\.\d+)?)\s*([KMGT]i?B?)?$`)
	matches := re.FindStringSubmatch(strings.ToUpper(size))
	if matches == nil {
		return 0, fmt.Errorf("invalid disk size format: %s (expected: number or number with unit like 20G, 100G)", size)
	}

	value, err := strconv.ParseFloat(matches[1], 64)
	if err != nil {
		return 0, fmt.Errorf("invalid numeric value in disk size: %w", err)
	}

	unit := matches[2]
	if unit == "" {
		unit = "G" // Default to GB
	}

	// Convert to GB
	var multiplier float64
	switch {
	case strings.HasPrefix(unit, "K"):
		multiplier = 1.0 / (1024.0 * 1024.0)
	case strings.HasPrefix(unit, "M"):
		multiplier = 1.0 / 1024.0
	case strings.HasPrefix(unit, "G"):
		multiplier = 1.0
	case strings.HasPrefix(unit, "T"):
		multiplier = 1024.0
	default:
		return 0, fmt.Errorf("unsupported disk unit: %s (use K, M, G, or T)", unit)
	}

	result := int(value * multiplier)
	if result <= 0 {
		return 0, fmt.Errorf("disk size must be positive")
	}

	return result, nil
}

// GenerateVMName generates a VM name using the provided prefix
// If UserProvidedVMName is set, it uses that instead
// Returns the generated name without validation (caller should validate)
func GenerateVMName(prefix string) string {
	if UserProvidedVMName != "" {
		return UserProvidedVMName
	}

	// Use timestamp-based naming for simplicity
	// Format: prefix-YYYYMMDD-HHMMSS
	return fmt.Sprintf("%s-%s", prefix, strings.ReplaceAll(strings.ReplaceAll(fmt.Sprintf("%d", os.Getpid()), " ", ""), ":", ""))
}
