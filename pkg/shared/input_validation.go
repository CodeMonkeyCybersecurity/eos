package shared

import (
	"fmt"
	"regexp"
	"strings"
)

// Global input validation utilities for use across all Eos packages

var (
	// SafeStringPattern allows only alphanumeric, hyphens, underscores, and dots
	SafeStringPattern = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)
	
	// SafePathPattern allows safe relative paths
	SafePathPattern = regexp.MustCompile(`^[a-zA-Z0-9._/-]+$`)
	
	// AlphanumericPattern allows only letters and numbers
	AlphanumericPattern = regexp.MustCompile(`^[a-zA-Z0-9]+$`)
)

// ValidateSafeString ensures input contains only safe characters
func ValidateSafeString(input string, maxLength int, fieldName string) error {
	if input == "" {
		return fmt.Errorf("%s cannot be empty", fieldName)
	}
	
	if len(input) > maxLength {
		return fmt.Errorf("%s too long: %d characters (max %d)", fieldName, len(input), maxLength)
	}
	
	if !SafeStringPattern.MatchString(input) {
		return fmt.Errorf("%s contains invalid characters (only alphanumeric, dots, hyphens, underscores allowed)", fieldName)
	}
	
	// Additional safety checks
	if strings.Contains(input, "..") {
		return fmt.Errorf("%s cannot contain consecutive dots", fieldName)
	}
	
	return nil
}

// ValidateSafePath ensures file paths are safe
func ValidateSafePath(path string, fieldName string) error {
	if path == "" {
		return fmt.Errorf("%s cannot be empty", fieldName)
	}
	
	if len(path) > 512 {
		return fmt.Errorf("%s too long: %d characters (max 512)", fieldName, len(path))
	}
	
	// Check for dangerous patterns
	dangerousPatterns := []string{
		"..", "/etc/", "/var/", "/usr/", "/root/", "/home/",
		"~", "$", "`", ";", "&", "|", ">", "<",
	}
	
	for _, pattern := range dangerousPatterns {
		if strings.Contains(path, pattern) {
			return fmt.Errorf("%s contains dangerous pattern: %s", fieldName, pattern)
		}
	}
	
	if !SafePathPattern.MatchString(path) {
		return fmt.Errorf("%s contains invalid characters", fieldName)
	}
	
	return nil
}

// SanitizeForLogging removes sensitive information from strings for safe logging
func SanitizeForLogging(input string) string {
	// Replace common sensitive patterns
	input = regexp.MustCompile(`hvs\.[A-Za-z0-9._-]+`).ReplaceAllString(input, "hvs.[REDACTED]")
	input = regexp.MustCompile(`s\.[A-Za-z0-9._-]+`).ReplaceAllString(input, "s.[REDACTED]")
	input = regexp.MustCompile(`password[=:]\s*\S+`).ReplaceAllStringFunc(input, func(match string) string {
		return regexp.MustCompile(`\S+$`).ReplaceAllString(match, "[REDACTED]")
	})
	input = regexp.MustCompile(`token[=:]\s*\S+`).ReplaceAllStringFunc(input, func(match string) string {
		return regexp.MustCompile(`\S+$`).ReplaceAllString(match, "[REDACTED]")
	})
	
	return input
}