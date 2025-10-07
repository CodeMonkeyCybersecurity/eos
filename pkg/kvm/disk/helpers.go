package disk

import (
	"fmt"
	"regexp"
	"strconv"
)

// ParseSizeChange parses size specifications like "+50G", "-10G", "200G"
func ParseSizeChange(spec string) (*SizeChange, error) {
	if spec == "" {
		return nil, fmt.Errorf("size specification cannot be empty")
	}

	// Pattern: optional +/-, digits, optional decimal, unit (K/M/G/T), optional B
	re := regexp.MustCompile(`^([+-]?)(\d+(?:\.\d+)?)([KMGT])B?$`)
	matches := re.FindStringSubmatch(spec)
	if len(matches) != 4 {
		return nil, fmt.Errorf("invalid size format: %s (expected: +50G, -10G, or 200G)", spec)
	}

	sign := matches[1]
	valueStr := matches[2]
	unit := matches[3]

	// Parse numeric value
	value, err := strconv.ParseFloat(valueStr, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid numeric value: %s", valueStr)
	}

	// Convert to bytes based on unit
	multipliers := map[string]int64{
		"K": 1024,
		"M": 1024 * 1024,
		"G": 1024 * 1024 * 1024,
		"T": 1024 * 1024 * 1024 * 1024,
	}

	bytes := int64(value * float64(multipliers[unit]))

	sc := &SizeChange{
		IsAbsolute: sign == "",
		IsGrowth:   sign != "-",
		Bytes:      bytes,
	}

	// Adjust for negative sign
	if sign == "-" {
		sc.Bytes = -sc.Bytes
	}

	return sc, nil
}

// FormatBytes converts bytes to human-readable format
func FormatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGT"[exp])
}

// CalculateTargetSize determines the final size based on current size and change
func CalculateTargetSize(currentBytes int64, change *SizeChange) (int64, error) {
	if change.IsAbsolute {
		// Absolute size specification
		if change.Bytes <= 0 {
			return 0, fmt.Errorf("target size must be positive")
		}
		return change.Bytes, nil
	}

	// Relative change
	targetSize := currentBytes + change.Bytes
	if targetSize <= 0 {
		return 0, fmt.Errorf("resulting size would be negative or zero")
	}

	return targetSize, nil
}

// CalculateRequiredSpace determines how much host space is needed
func CalculateRequiredSpace(currentBytes int64, targetBytes int64) int64 {
	if targetBytes > currentBytes {
		// Growing - need the increase plus 20% buffer
		increase := targetBytes - currentBytes
		buffer := int64(float64(increase) * 0.2)
		return increase + buffer
	}
	// Shrinking - no additional space needed
	return 0
}
