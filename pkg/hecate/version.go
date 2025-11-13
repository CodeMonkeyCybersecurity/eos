// pkg/hecate/version.go
// Authentik version detection and management for Hecate

package hecate

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

const (
	// DefaultAuthentikVersion is the fallback version if detection fails
	// Updated: 2025-10-30 to latest stable (Redis deprecated in 2025.8+)
	DefaultAuthentikVersion = "2025.10.0"

	// AuthentikImage is the container registry path
	AuthentikImage = "ghcr.io/goauthentik/server"

	// RedisDeprecatedVersion is the first version where Redis is fully optional
	// Authentik 2025.8+ uses PostgreSQL-only architecture
	RedisDeprecatedVersion = "2025.8.0"
)

// IsRedisFreVersion checks if the given Authentik version is Redis-free
//
// Authentik 2025.8+ deprecated Redis in favor of PostgreSQL-only architecture.
// This function returns true for versions ≥ 2025.8.0
//
// Parameters:
//   - version: Authentik version string (e.g., "2025.10.0")
//
// Returns: true if version supports Redis-free mode (≥ 2025.8.0)
func IsRedisFreVersion(version string) bool {
	if version == "" {
		return false
	}

	// Validate version format before comparison
	_, _, _, err := platform.ParseVersion(version)
	if err != nil {
		// Invalid version format - assume Redis required (safe default)
		return false
	}

	// Use platform's version comparison
	return platform.CompareVersions(version, RedisDeprecatedVersion) >= 0
}

// GetLatestAuthentikVersion resolves the latest stable Authentik version
//
// This function:
// - Queries GitHub API for latest release
// - Falls back to hardcoded stable version if API fails
// - Caches result for 24 hours
//
// Returns: version tag (e.g., "2024.8.3")
func GetLatestAuthentikVersion(rc *eos_io.RuntimeContext) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Resolving latest Authentik version")

	// Use platform version resolver
	resolver := platform.NewVersionResolver(rc, "authentik")

	version, err := resolver.GetLatestVersion()
	if err != nil {
		logger.Warn("Failed to resolve latest Authentik version, using default",
			zap.Error(err),
			zap.String("default_version", DefaultAuthentikVersion))
		return DefaultAuthentikVersion, nil // Don't fail deployment, use fallback
	}

	logger.Info("Resolved Authentik version",
		zap.String("version", version),
		zap.String("image", fmt.Sprintf("%s:%s", AuthentikImage, version)))

	return version, nil
}

// GetAuthentikImageReference returns the full image reference (repository:tag)
func GetAuthentikImageReference(rc *eos_io.RuntimeContext) (string, error) {
	version, err := GetLatestAuthentikVersion(rc)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s:%s", AuthentikImage, version), nil
}
