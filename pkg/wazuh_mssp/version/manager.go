// pkg/wazuh_mssp/version/manager.go
//
// Wazuh Version Management System
//
// This package provides centralized Wazuh version management that solves the manual
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
//   manager := version.NewManager()
//   latest, err := manager.GetLatestVersion(rc)
//   if err != nil {
//       // Falls back to cached or default version
//   }
//
// Integration:
// This system integrates with EOS Wazuh deployments to automatically select
// appropriate versions based on your configured policies, eliminating the need
// for manual version management.
package version

import (
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

// Manager handles Wazuh version management.
//
// The Manager provides the core functionality for fetching, caching, and comparing
// Wazuh versions. It uses the GitHub API to get release information and implements
// intelligent caching to avoid rate limits.
//
// Architecture:
// - Fetches from GitHub API: https://api.github.com/repos/wazuh/wazuh/releases
// - Caches results locally in ~/.eos/cache/wazuh-versions/
// - Falls back to default version (4.13.0) when API unavailable
// - Respects GitHub rate limits (60 req/hour unauthenticated)
type Manager struct {
	cacheDir     string        // Local cache directory for version data
	cacheTimeout time.Duration // How long to cache version information
	httpClient   *http.Client  // HTTP client for GitHub API calls
}

// NewManager creates a new version manager
func NewManager() *Manager {
	homeDir, _ := os.UserHomeDir()
	cacheDir := filepath.Join(homeDir, ".eos", "cache", "wazuh-versions")
	
	return &Manager{
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
func (m *Manager) GetLatestVersion(rc *eos_io.RuntimeContext) (*VersionInfo, error) {
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

// GetSpecificVersion fetches information about a specific version
func (m *Manager) GetSpecificVersion(rc *eos_io.RuntimeContext, version string) (*VersionInfo, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Normalize version (remove 'v' prefix if present)
	version = strings.TrimPrefix(version, "v")
	
	// Try cache first
	cacheKey := fmt.Sprintf("version-%s", version)
	if cached, err := m.getCachedVersion(rc, cacheKey); err == nil && cached != nil {
		if time.Since(cached.CachedAt) < m.cacheTimeout {
			logger.Debug("Using cached version info", zap.String("version", version))
			return cached, nil
		}
	}
	
	// Fetch all versions and find the specific one
	versions, err := m.fetchVersionsFromGitHub(rc.Ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch versions: %w", err)
	}
	
	for _, v := range versions {
		if v.Version == version {
			// Cache the result
			if err := m.cacheVersion(rc, cacheKey, v); err != nil {
				logger.Warn("Failed to cache version", zap.Error(err))
			}
			return v, nil
		}
	}
	
	return nil, fmt.Errorf("version %s not found", version)
}

// ListAvailableVersions returns all available versions
func (m *Manager) ListAvailableVersions(rc *eos_io.RuntimeContext, includePrerelease bool) ([]*VersionInfo, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	cacheKey := fmt.Sprintf("all-versions-%t", includePrerelease)
	
	// Try cache first
	if cached := m.getCachedVersionList(rc, cacheKey); cached != nil {
		if len(cached) > 0 && time.Since(cached[0].CachedAt) < m.cacheTimeout {
			logger.Debug("Using cached version list", zap.Int("count", len(cached)))
			return cached, nil
		}
	}
	
	// Fetch from GitHub
	versions, err := m.fetchVersionsFromGitHub(rc.Ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch versions: %w", err)
	}
	
	// Filter based on prerelease preference
	var filtered []*VersionInfo
	for _, v := range versions {
		if includePrerelease || v.IsStable {
			filtered = append(filtered, v)
		}
	}
	
	// Cache the result
	if err := m.cacheVersionList(rc, cacheKey, filtered); err != nil {
		logger.Warn("Failed to cache version list", zap.Error(err))
	}
	
	return filtered, nil
}

// CompareVersions compares two version strings (returns -1, 0, 1)
func (m *Manager) CompareVersions(v1, v2 string) int {
	// Normalize versions
	v1 = strings.TrimPrefix(v1, "v")
	v2 = strings.TrimPrefix(v2, "v")
	
	// Split into parts
	parts1 := strings.Split(v1, ".")
	parts2 := strings.Split(v2, ".")
	
	// Pad to same length
	maxLen := len(parts1)
	if len(parts2) > maxLen {
		maxLen = len(parts2)
	}
	
	for len(parts1) < maxLen {
		parts1 = append(parts1, "0")
	}
	for len(parts2) < maxLen {
		parts2 = append(parts2, "0")
	}
	
	// Compare each part
	for i := 0; i < maxLen; i++ {
		n1, err1 := strconv.Atoi(parts1[i])
		n2, err2 := strconv.Atoi(parts2[i])
		
		if err1 != nil || err2 != nil {
			// String comparison for non-numeric parts
			if parts1[i] < parts2[i] {
				return -1
			} else if parts1[i] > parts2[i] {
				return 1
			}
			continue
		}
		
		if n1 < n2 {
			return -1
		} else if n1 > n2 {
			return 1
		}
	}
	
	return 0
}

// IsVersionNewer checks if version1 is newer than version2
func (m *Manager) IsVersionNewer(version1, version2 string) bool {
	return m.CompareVersions(version1, version2) > 0
}

// fetchVersionsFromGitHub fetches version information from GitHub API
func (m *Manager) fetchVersionsFromGitHub(ctx context.Context) ([]*VersionInfo, error) {
	url := "https://api.github.com/repos/wazuh/wazuh/releases"
	
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	// Set User-Agent to avoid rate limiting
	req.Header.Set("User-Agent", "EOS-Wazuh-Version-Manager/1.0")
	
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch releases: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}
	
	var releases []GitHubRelease
	if err := json.Unmarshal(body, &releases); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}
	
	// Convert to VersionInfo
	var versions []*VersionInfo
	versionRegex := regexp.MustCompile(`^v?(\d+\.\d+\.\d+)`)
	
	for _, release := range releases {
		if release.Draft {
			continue
		}
		
		matches := versionRegex.FindStringSubmatch(release.TagName)
		if len(matches) < 2 {
			continue
		}
		
		version := &VersionInfo{
			Version:     matches[1],
			ReleaseDate: release.PublishedAt,
			IsStable:    !release.Prerelease,
			URL:         release.HTMLURL,
			CachedAt:    time.Now(),
		}
		
		versions = append(versions, version)
	}
	
	// Sort by version (newest first)
	sort.Slice(versions, func(i, j int) bool {
		return m.CompareVersions(versions[i].Version, versions[j].Version) > 0
	})
	
	return versions, nil
}

// findLatestStable finds the latest stable version from a list
func (m *Manager) findLatestStable(versions []*VersionInfo) *VersionInfo {
	for _, v := range versions {
		if v.IsStable {
			return v
		}
	}
	return nil
}

// getFallbackVersion returns a fallback version when API is unavailable
func (m *Manager) getFallbackVersion() *VersionInfo {
	return &VersionInfo{
		Version:     "4.13.0", // Updated fallback to current version
		ReleaseDate: time.Now().AddDate(0, -1, 0), // Approximate
		IsStable:    true,
		URL:         "https://github.com/wazuh/wazuh/releases",
		CachedAt:    time.Now(),
	}
}

// Cache management functions

func (m *Manager) getCachedVersion(rc *eos_io.RuntimeContext, key string) (*VersionInfo, error) {
	if err := os.MkdirAll(m.cacheDir, 0755); err != nil {
		return nil, err
	}
	
	cachePath := filepath.Join(m.cacheDir, key+".json")
	data, err := os.ReadFile(cachePath)
	if err != nil {
		return nil, err
	}
	
	var version VersionInfo
	if err := json.Unmarshal(data, &version); err != nil {
		return nil, err
	}
	
	return &version, nil
}

func (m *Manager) cacheVersion(rc *eos_io.RuntimeContext, key string, version *VersionInfo) error {
	if err := os.MkdirAll(m.cacheDir, 0755); err != nil {
		return err
	}
	
	version.CachedAt = time.Now()
	data, err := json.MarshalIndent(version, "", "  ")
	if err != nil {
		return err
	}
	
	cachePath := filepath.Join(m.cacheDir, key+".json")
	return os.WriteFile(cachePath, data, 0644)
}

func (m *Manager) getCachedVersionList(rc *eos_io.RuntimeContext, key string) []*VersionInfo {
	if err := os.MkdirAll(m.cacheDir, 0755); err != nil {
		return nil
	}
	
	cachePath := filepath.Join(m.cacheDir, key+".json")
	data, err := os.ReadFile(cachePath)
	if err != nil {
		return nil
	}
	
	var versions []*VersionInfo
	if err := json.Unmarshal(data, &versions); err != nil {
		return nil
	}
	
	return versions
}

func (m *Manager) cacheVersionList(rc *eos_io.RuntimeContext, key string, versions []*VersionInfo) error {
	if err := os.MkdirAll(m.cacheDir, 0755); err != nil {
		return err
	}
	
	// Update cache time for all versions
	now := time.Now()
	for _, v := range versions {
		v.CachedAt = now
	}
	
	data, err := json.MarshalIndent(versions, "", "  ")
	if err != nil {
		return err
	}
	
	cachePath := filepath.Join(m.cacheDir, key+".json")
	return os.WriteFile(cachePath, data, 0644)
}

// ClearCache removes all cached version data
func (m *Manager) ClearCache() error {
	return os.RemoveAll(m.cacheDir)
}
