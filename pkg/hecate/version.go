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
	DefaultAuthentikVersion = "2024.8.3"

	// AuthentikImage is the container registry path
	AuthentikImage = "ghcr.io/goauthentik/server"
)

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
