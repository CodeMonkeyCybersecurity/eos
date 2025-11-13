//go:build darwin
// +build darwin

package cephfs

import (
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

// Install stub for macOS
func Install(rc *eos_io.RuntimeContext, config *Config) error {
	return fmt.Errorf("CephFS installation not available on macOS - deploy to Ubuntu Linux to use this feature")
}

// validateConfiguration validates the provided configuration (stub for macOS)
// This function is available on all platforms for testing purposes
func validateConfiguration(rc *eos_io.RuntimeContext, config *Config) error {
	// Validate required fields
	if config.AdminHost == "" {
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("admin host is required"))
	}

	if config.PublicNetwork == "" {
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("public network is required"))
	}

	if config.ClusterNetwork == "" {
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("cluster network is required"))
	}

	// Validate Ceph image format
	if !IsValidCephImage(config.CephImage) {
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("invalid Ceph image format: %s", config.CephImage))
	}

	// Validate network CIDR format (basic validation)
	if !strings.Contains(config.PublicNetwork, "/") {
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("public network must be in CIDR format (e.g., 10.0.0.0/24)"))
	}

	if !strings.Contains(config.ClusterNetwork, "/") {
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("cluster network must be in CIDR format (e.g., 10.1.0.0/24)"))
	}

	// Security validation: Check for control characters and injection patterns
	dangerousChars := []string{"\x00", "\n", "\r", "\t"}
	fields := map[string]string{
		"admin host":      config.AdminHost,
		"public network":  config.PublicNetwork,
		"cluster network": config.ClusterNetwork,
		"cluster FSID":    config.ClusterFSID,
	}

	for fieldName, fieldValue := range fields {
		for _, char := range dangerousChars {
			if strings.Contains(fieldValue, char) {
				return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("%s contains invalid control characters", fieldName))
			}
		}
	}

	// Check for command injection patterns
	injectionPatterns := []string{";", "&&", "||", "|", "`", "$(", "${"}
	for fieldName, fieldValue := range fields {
		for _, pattern := range injectionPatterns {
			if strings.Contains(fieldValue, pattern) {
				return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("%s contains potentially dangerous pattern: %s", fieldName, pattern))
			}
		}
	}

	return nil
}
