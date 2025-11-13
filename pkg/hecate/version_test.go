// pkg/hecate/version_test.go
// Tests for Authentik version detection

package hecate

import (
	"context"
	"strings"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
)

// TestGetLatestAuthentikVersion verifies GitHub API integration
func TestGetLatestAuthentikVersion(t *testing.T) {
	// Create minimal runtime context
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	version, err := GetLatestAuthentikVersion(rc)
	if err != nil {
		// API failure is acceptable - will use fallback
		t.Logf("GitHub API failed (acceptable): %v", err)
		if version != DefaultAuthentikVersion {
			t.Errorf("Expected fallback version %s, got %s", DefaultAuthentikVersion, version)
		}
		return
	}

	// Version should be valid format
	if version == "" {
		t.Error("Retrieved version is empty")
	}

	// Version should be YYYY.M.P format
	if !isValidAuthentikVersion(version) {
		t.Errorf("Version %s does not match expected format (YYYY.M.P)", version)
	}

	// Version should be ≥ 2025.10 (latest stable as of 2025-10-30)
	if compareAuthentikVersions(version, "2025.10.0") < 0 {
		t.Logf("Warning: Detected version %s is older than 2025.10.0", version)
		t.Logf("This may indicate fallback is being used or new release pending")
	}

	t.Logf("Successfully retrieved Authentik version: %s", version)
}

// TestIsRedisFreVersion verifies Redis deprecation detection
func TestIsRedisFreVersion(t *testing.T) {
	tests := []struct {
		version  string
		expected bool
		name     string
	}{
		{"2025.10.0", true, "Latest stable (Redis-free)"},
		{"2025.8.0", true, "First Redis-free version"},
		{"2024.8.3", false, "Older version (Redis required)"},
		{"2024.6.0", false, "Much older (Redis required)"},
		{"2026.1.0", true, "Future version (Redis-free)"},
		{"invalid", false, "Invalid version format"},
		{"", false, "Empty version"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsRedisFreVersion(tt.version)
			if result != tt.expected {
				t.Errorf("IsRedisFreVersion(%q) = %v, expected %v", tt.version, result, tt.expected)
			}
		})
	}
}

// TestCompareAuthentikVersions verifies version comparison logic
func TestCompareAuthentikVersions(t *testing.T) {
	tests := []struct {
		v1       string
		v2       string
		expected int // -1: v1 < v2, 0: v1 == v2, 1: v1 > v2
		name     string
	}{
		{"2025.10.0", "2025.10.0", 0, "Equal versions"},
		{"2025.10.0", "2024.8.3", 1, "Newer > older"},
		{"2024.8.3", "2025.10.0", -1, "Older < newer"},
		{"2025.10.1", "2025.10.0", 1, "Patch version difference"},
		{"2025.11.0", "2025.10.0", 1, "Minor version difference"},
		{"2026.1.0", "2025.10.0", 1, "Major (year) difference"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := compareAuthentikVersions(tt.v1, tt.v2)
			if result != tt.expected {
				t.Errorf("compareAuthentikVersions(%q, %q) = %d, expected %d",
					tt.v1, tt.v2, result, tt.expected)
			}
		})
	}
}

// TestDefaultAuthentikVersionIsValid ensures fallback is recent enough
func TestDefaultAuthentikVersionIsValid(t *testing.T) {
	// Fallback version should be ≥ 2025.8.0 (Redis deprecated)
	if !IsRedisFreVersion(DefaultAuthentikVersion) {
		t.Errorf("DefaultAuthentikVersion %s is too old (requires Redis)", DefaultAuthentikVersion)
		t.Logf("Update DefaultAuthentikVersion in pkg/hecate/version.go to 2025.10.0 or newer")
	}

	// Fallback should be valid format
	if !isValidAuthentikVersion(DefaultAuthentikVersion) {
		t.Errorf("DefaultAuthentikVersion %s is not a valid Authentik version format", DefaultAuthentikVersion)
	}

	t.Logf("DefaultAuthentikVersion: %s (valid)", DefaultAuthentikVersion)
}

// isValidAuthentikVersion checks if version matches YYYY.M.P format
func isValidAuthentikVersion(version string) bool {
	if version == "" {
		return false
	}

	parts := strings.Split(version, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return false
	}

	// Year should be 4 digits (2024, 2025, etc.)
	if len(parts[0]) != 4 {
		return false
	}

	// All parts should be numeric
	for _, part := range parts {
		for _, char := range part {
			if char < '0' || char > '9' {
				return false
			}
		}
	}

	return true
}

// compareAuthentikVersions compares two Authentik version strings
// Returns: -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
func compareAuthentikVersions(v1, v2 string) int {
	// Parse versions using platform package
	major1, minor1, patch1, err1 := platform.ParseVersion(v1)
	major2, minor2, patch2, err2 := platform.ParseVersion(v2)

	// If either is invalid, fall back to string comparison
	if err1 != nil || err2 != nil {
		return strings.Compare(v1, v2)
	}

	// Compare major (year)
	if major1 != major2 {
		if major1 < major2 {
			return -1
		}
		return 1
	}

	// Compare minor (month)
	if minor1 != minor2 {
		if minor1 < minor2 {
			return -1
		}
		return 1
	}

	// Compare patch
	if patch1 != patch2 {
		if patch1 < patch2 {
			return -1
		}
		return 1
	}

	return 0
}
