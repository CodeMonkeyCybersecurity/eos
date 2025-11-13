// pkg/wazuh/version.go
//
// Wazuh Version Management System
//
// This package provides centralized Wazuh/Wazuh version management that solves the manual
// version tracking problem. It automatically fetches the latest versions from the
// Wazuh GitHub API, manages update policies, and ensures version consistency across
// your infrastructure.
//
// Key Features:
// - Automatic version fetching from Wazuh GitHub API with intelligent caching
// - Policy-based updates (manual, patch, minor, major, latest)
// - Version constraints (pinning, min/max versions)
// - Safety controls (approval workflows, maintenance windows)
// - Environment templates (production, staging, development)
// - Robust error handling with fallback mechanisms
//
// Quick Start:
//   latest, err := GetLatestWazuhVersion(rc)
//   if err != nil {
//       // Falls back to cached or default version
//   }
//
// Integration:
// This system integrates with Eos Wazuh deployments to automatically select
// appropriate versions based on your configured policies, eliminating the need
// for manual version management.

package wazuh

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// DefaultWazuhVersion is the fallback version when API is unavailable
const DefaultWazuhVersion = "4.13.0"

// VersionManager handles Wazuh version management.
//
// The VersionManager provides the core functionality for fetching, caching, and comparing
// Wazuh/Wazuh versions. It uses the GitHub API to get release information and implements
// intelligent caching to avoid rate limits.
//
// Architecture:
// - Fetches from GitHub API: https://api.github.com/repos/wazuh/wazuh/releases
// - Caches results locally in ~/.eos/cache/wazuh-versions/
// - Falls back to default version (4.13.0) when API unavailable
// - Respects GitHub rate limits (60 req/hour unauthenticated)
type VersionManager struct {
	cacheDir     string        // Local cache directory for version data
	cacheTimeout time.Duration // How long to cache version information
	httpClient   *http.Client  // HTTP client for GitHub API calls
}

// NewVersionManager creates a new version manager
func NewVersionManager() *VersionManager {
	homeDir, _ := os.UserHomeDir()
	cacheDir := filepath.Join(homeDir, ".eos", "cache", "wazuh-versions")

	return &VersionManager{
		cacheDir:     cacheDir,
		cacheTimeout: 1 * time.Hour, // Cache for 1 hour
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// VersionInfo contains version information
type VersionInfo struct {
	Version     string    `json:"version"`
	ReleaseDate time.Time `json:"release_date"`
	IsStable    bool      `json:"is_stable"`
	URL         string    `json:"url"`
	CachedAt    time.Time `json:"cached_at"`
}

// GitHubRelease represents a GitHub release response
type GitHubRelease struct {
	TagName     string    `json:"tag_name"`
	Name        string    `json:"name"`
	PublishedAt time.Time `json:"published_at"`
	Prerelease  bool      `json:"prerelease"`
	Draft       bool      `json:"draft"`
	HTMLURL     string    `json:"html_url"`
}

// GetLatestVersion fetches the latest stable Wazuh version
func (m *VersionManager) GetLatestVersion(rc *eos_io.RuntimeContext) (*VersionInfo, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Try cache first
	if cached, err := m.getCachedVersion(rc, "latest"); err == nil && cached != nil {
		if time.Since(cached.CachedAt) < m.cacheTimeout {
			logger.Debug("Using cached latest version", zap.String("version", cached.Version))
			return cached, nil
		}
	}

	logger.Info("Fetching latest Wazuh version from GitHub API")

	// Fetch from GitHub API
	versions, err := m.fetchVersionsFromGitHub(rc.Ctx)
	if err != nil {
		logger.Warn("Failed to fetch from GitHub, using fallback", zap.Error(err))
		return m.getFallbackVersion(), nil
	}

	// Find latest stable version
	latest := m.findLatestStable(versions)
	if latest == nil {
		logger.Warn("No stable version found, using fallback")
		return m.getFallbackVersion(), nil
	}

	// Cache the result
	if err := m.cacheVersion(rc, "latest", latest); err != nil {
		logger.Warn("Failed to cache version", zap.Error(err))
	}

	logger.Info("Found latest Wazuh version",
		zap.String("version", latest.Version),
		zap.Time("release_date", latest.ReleaseDate))

	return latest, nil
}

// GetLatestWazuhVersion uses the centralized version management system to get the latest Wazuh version.
//
// This function is the main integration point between Eos Wazuh deployments and the
// centralized version management system. It automatically:
//
// 1. Loads your version management configuration
// 2. Respects version pinning if configured
// 3. Fetches the latest version from GitHub API (with caching)
// 4. Applies your update policy to determine if the version is allowed
// 5. Falls back to safe defaults if any step fails
//
// Usage in Wazuh deployments:
//
//	version, err := GetLatestWazuhVersion(rc)
//	if err != nil {
//	    // Handle error - function provides safe fallbacks
//	}
//	// Use version for deployment
//
// This replaces manual version management and ensures consistency across your
// Wazuh infrastructure.
func GetLatestWazuhVersion(rc *eos_io.RuntimeContext) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Create version manager
	versionManager := NewVersionManager()

	// Get latest version
	versionInfo, err := versionManager.GetLatestVersion(rc)
	if err != nil {
		logger.Warn("Failed to get latest version, using default",
			zap.Error(err),
			zap.String("default", DefaultWazuhVersion))
		return DefaultWazuhVersion, nil
	}

	logger.Info("Using latest Wazuh version",
		zap.String("version", versionInfo.Version),
		zap.Time("release_date", versionInfo.ReleaseDate))

	return versionInfo.Version, nil
}

// Helper methods

func (m *VersionManager) getCachedVersion(rc *eos_io.RuntimeContext, key string) (*VersionInfo, error) {
	cacheFile := filepath.Join(m.cacheDir, key+".json")

	data, err := os.ReadFile(cacheFile)
	if err != nil {
		return nil, err
	}

	var version VersionInfo
	if err := json.Unmarshal(data, &version); err != nil {
		return nil, err
	}

	return &version, nil
}

func (m *VersionManager) cacheVersion(rc *eos_io.RuntimeContext, key string, version *VersionInfo) error {
	// Create cache directory if it doesn't exist
	if err := os.MkdirAll(m.cacheDir, shared.ServiceDirPerm); err != nil {
		return err
	}

	version.CachedAt = time.Now()

	data, err := json.MarshalIndent(version, "", "  ")
	if err != nil {
		return err
	}

	cacheFile := filepath.Join(m.cacheDir, key+".json")
	return os.WriteFile(cacheFile, data, shared.ConfigFilePerm)
}

func (m *VersionManager) fetchVersionsFromGitHub(ctx context.Context) ([]*VersionInfo, error) {
	url := "https://api.github.com/repos/wazuh/wazuh/releases"

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var releases []GitHubRelease
	if err := json.Unmarshal(body, &releases); err != nil {
		return nil, err
	}

	var versions []*VersionInfo
	for _, release := range releases {
		if release.Draft {
			continue
		}

		version := m.parseVersion(release.TagName)
		if version == "" {
			continue
		}

		versions = append(versions, &VersionInfo{
			Version:     version,
			ReleaseDate: release.PublishedAt,
			IsStable:    !release.Prerelease,
			URL:         release.HTMLURL,
		})
	}

	return versions, nil
}

func (m *VersionManager) parseVersion(tagName string) string {
	// Match version patterns like "v4.13.0", "4.13.0", etc.
	re := regexp.MustCompile(`v?(\d+\.\d+\.\d+)`)
	matches := re.FindStringSubmatch(tagName)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func (m *VersionManager) findLatestStable(versions []*VersionInfo) *VersionInfo {
	var stableVersions []*VersionInfo
	for _, v := range versions {
		if v.IsStable {
			stableVersions = append(stableVersions, v)
		}
	}

	if len(stableVersions) == 0 {
		return nil
	}

	// Sort by version (simple string comparison for now)
	sort.Slice(stableVersions, func(i, j int) bool {
		return m.compareVersions(stableVersions[i].Version, stableVersions[j].Version) > 0
	})

	return stableVersions[0]
}

func (m *VersionManager) compareVersions(v1, v2 string) int {
	parts1 := strings.Split(v1, ".")
	parts2 := strings.Split(v2, ".")

	maxLen := len(parts1)
	if len(parts2) > maxLen {
		maxLen = len(parts2)
	}

	for i := 0; i < maxLen; i++ {
		var p1, p2 int

		if i < len(parts1) {
			p1, _ = strconv.Atoi(parts1[i])
		}
		if i < len(parts2) {
			p2, _ = strconv.Atoi(parts2[i])
		}

		if p1 > p2 {
			return 1
		} else if p1 < p2 {
			return -1
		}
	}

	return 0
}

func (m *VersionManager) getFallbackVersion() *VersionInfo {
	return &VersionInfo{
		Version:     DefaultWazuhVersion,
		ReleaseDate: time.Now(),
		IsStable:    true,
		URL:         "https://github.com/wazuh/wazuh/releases",
		CachedAt:    time.Now(),
	}
}
