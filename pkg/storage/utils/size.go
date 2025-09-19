package utils

import (
	"fmt"
	"strings"
)

// ParseStorageSize parses a human-readable storage size string into bytes
func ParseStorageSize(size string) (uint64, error) {
	if size == "" || size == "0" {
		return 0, nil
	}

	size = strings.ToUpper(strings.TrimSpace(size))
	
	var multiplier uint64 = 1
	var numStr string

	if strings.HasSuffix(size, "TB") {
		multiplier = 1024 * 1024 * 1024 * 1024
		numStr = strings.TrimSuffix(size, "TB")
	} else if strings.HasSuffix(size, "GB") {
		multiplier = 1024 * 1024 * 1024
		numStr = strings.TrimSuffix(size, "GB")
	} else if strings.HasSuffix(size, "MB") {
		multiplier = 1024 * 1024
		numStr = strings.TrimSuffix(size, "MB")
	} else if strings.HasSuffix(size, "KB") {
		multiplier = 1024
		numStr = strings.TrimSuffix(size, "KB")
	} else {
		numStr = size
	}

	var num float64
	if _, err := fmt.Sscanf(numStr, "%f", &num); err != nil {
		return 0, fmt.Errorf("invalid number format: %s", numStr)
	}

	return uint64(num * float64(multiplier)), nil
}

// ParseMemorySize parses a human-readable memory size string into MB
func ParseMemorySize(memory string) (uint, error) {
	if memory == "" {
		return 0, fmt.Errorf("memory size cannot be empty")
	}

	memory = strings.ToUpper(strings.TrimSpace(memory))
	
	var multiplier uint = 1
	var numStr string

	if strings.HasSuffix(memory, "GB") {
		multiplier = 1024
		numStr = strings.TrimSuffix(memory, "GB")
	} else if strings.HasSuffix(memory, "MB") {
		multiplier = 1
		numStr = strings.TrimSuffix(memory, "MB")
	} else {
		numStr = memory
	}

	var num float64
	if _, err := fmt.Sscanf(numStr, "%f", &num); err != nil {
		return 0, fmt.Errorf("invalid number format: %s", numStr)
	}

	return uint(num * float64(multiplier)), nil
}

// FormatBytes formats bytes into a human-readable string
func FormatBytes(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// FormatMemory formats memory in MB into a human-readable string
func FormatMemory(memoryMB uint) string {
	if memoryMB < 1024 {
		return fmt.Sprintf("%d MB", memoryMB)
	}
	return fmt.Sprintf("%.1f GB", float64(memoryMB)/1024)
}
