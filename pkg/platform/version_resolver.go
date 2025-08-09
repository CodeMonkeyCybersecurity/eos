package platform

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// VersionInfo represents information about a software release
type VersionInfo struct {
	Version      string            `json:"version"`
	ReleaseDate  time.Time         `json:"release_date"`
	IsStable     bool              `json:"is_stable"`
	IsLTS        bool              `json:"is_lts"`
	DownloadURLs map[string]string `json:"download_urls"`
	Notes        string            `json:"notes"`
}

// VersionResolver handles version detection for various software packages
type VersionResolver struct {
	rc            *eos_io.RuntimeContext
	software      string
	cacheDuration time.Duration
	cachedVersion string
	cacheExpiry   time.Time
	strategies    []VersionStrategy
}

// VersionStrategy represents a method for detecting software versions
type VersionStrategy struct {
	Name        string
	Description string
	Timeout     time.Duration
	Fn          func(*VersionResolver) (string, error)
}

// GitHubRelease represents a GitHub release API response
type GitHubRelease struct {
	TagName    string    `json:"tag_name"`
	Name       string    `json:"name"`
	Draft      bool      `json:"draft"`
	Prerelease bool      `json:"prerelease"`
	CreatedAt  time.Time `json:"created_at"`
	Body       string    `json:"body"`
}

// NewVersionResolver creates a new version resolver for the specified software
func NewVersionResolver(rc *eos_io.RuntimeContext, software string) *VersionResolver {
	resolver := &VersionResolver{
		rc:            rc,
		software:      software,
		cacheDuration: 24 * time.Hour, // Cache for 24 hours
	}

	// Initialize strategies based on software type
	resolver.initializeStrategies()
	return resolver
}

// initializeStrategies sets up detection strategies based on the software type
func (r *VersionResolver) initializeStrategies() {
	switch strings.ToLower(r.software) {
	case "salt", "saltstack":
		r.strategies = []VersionStrategy{
			{
				Name:        "GitHub API",
				Description: "Query Salt's GitHub releases API",
				Timeout:     10 * time.Second,
				Fn:          r.getSaltVersionFromGitHub,
			},
			{
				Name:        "Salt Project Repository",
				Description: "Check official Salt repository metadata",
				Timeout:     15 * time.Second,
				Fn:          r.getSaltVersionFromRepo,
			},
			{
				Name:        "Fallback to Known Good",
				Description: "Use hardcoded fallback version",
				Timeout:     1 * time.Second,
				Fn:          r.getSaltFallbackVersion,
			},
		}
	case "consul":
		r.strategies = []VersionStrategy{
			{
				Name:        "GitHub API",
				Description: "Query Consul's GitHub releases API",
				Timeout:     10 * time.Second,
				Fn:          r.getConsulVersionFromGitHub,
			},
			{
				Name:        "HashiCorp Checkpoint",
				Description: "Check HashiCorp's checkpoint service",
				Timeout:     10 * time.Second,
				Fn:          r.getConsulVersionFromCheckpoint,
			},
			{
				Name:        "Fallback to Known Good",
				Description: "Use hardcoded fallback version",
				Timeout:     1 * time.Second,
				Fn:          r.getConsulFallbackVersion,
			},
		}
	case "minio":
		r.strategies = []VersionStrategy{
			{
				Name:        "GitHub API",
				Description: "Query MinIO's GitHub releases API",
				Timeout:     10 * time.Second,
				Fn:          r.getMinIOVersionFromGitHub,
			},
			{
				Name:        "MinIO Update Service",
				Description: "Check MinIO's official update service",
				Timeout:     10 * time.Second,
				Fn:          r.getMinIOVersionFromUpdateService,
			},
			{
				Name:        "Fallback to Known Good",
				Description: "Use hardcoded fallback version",
				Timeout:     1 * time.Second,
				Fn:          r.getMinIOFallbackVersion,
			},
		}
	default:
		// Generic strategies for other software
		r.strategies = []VersionStrategy{
			{
				Name:        "GitHub API Generic",
				Description: "Generic GitHub releases API query",
				Timeout:     10 * time.Second,
				Fn:          r.getGenericVersionFromGitHub,
			},
			{
				Name:        "Fallback",
				Description: "Use default version",
				Timeout:     1 * time.Second,
				Fn:          r.getGenericFallbackVersion,
			},
		}
	}
}

// GetLatestVersion tries multiple methods to determine the latest software version
func (r *VersionResolver) GetLatestVersion() (string, error) {
	logger := otelzap.Ctx(r.rc.Ctx)

	// Check cache first
	if r.isCacheValid() {
		logger.Debug("Using cached version",
			zap.String("software", r.software),
			zap.String("version", r.cachedVersion),
			zap.Time("expires", r.cacheExpiry))
		return r.cachedVersion, nil
	}

	logger.Info("Resolving latest version",
		zap.String("software", r.software),
		zap.Int("strategies", len(r.strategies)))

	var lastErr error
	for _, strategy := range r.strategies {
		logger.Info("Attempting version resolution strategy",
			zap.String("strategy", strategy.Name),
			zap.String("description", strategy.Description))

		// Use a timeout for each strategy
		resultCh := make(chan string, 1)
		errorCh := make(chan error, 1)

		go func() {
			version, err := strategy.Fn(r)
			if err != nil {
				errorCh <- err
				return
			}
			resultCh <- version
		}()

		select {
		case version := <-resultCh:
			if version != "" && r.isValidVersion(version) {
				logger.Info("Successfully resolved version",
					zap.String("strategy", strategy.Name),
					zap.String("version", version),
					zap.String("software", r.software))

				// Cache the successful result
				r.updateCache(version)
				return version, nil
			}
		case err := <-errorCh:
			logger.Warn("Strategy failed",
				zap.String("strategy", strategy.Name),
				zap.Error(err))
			lastErr = err
		case <-time.After(strategy.Timeout):
			err := fmt.Errorf("strategy timed out after %v", strategy.Timeout)
			logger.Warn("Strategy timed out",
				zap.String("strategy", strategy.Name),
				zap.Duration("timeout", strategy.Timeout))
			lastErr = err
		}
	}

	return "", fmt.Errorf("all version resolution strategies failed for %s: %w", r.software, lastErr)
}

// getSaltVersionFromGitHub queries Salt's GitHub releases API
func (r *VersionResolver) getSaltVersionFromGitHub(resolver *VersionResolver) (string, error) {
	logger := otelzap.Ctx(r.rc.Ctx)

	apiURL := "https://api.github.com/repos/saltstack/salt/releases/latest"

	client := &http.Client{Timeout: 10 * time.Second}

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	// GitHub API prefers this header
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "EOS-Salt-Installer/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to query GitHub API: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			fmt.Printf("Warning: Failed to close response body: %v\n", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var release GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", fmt.Errorf("failed to parse GitHub response: %w", err)
	}

	// Skip draft and prerelease versions
	if release.Draft || release.Prerelease {
		logger.Warn("Latest GitHub release is not stable",
			zap.String("version", release.TagName),
			zap.Bool("draft", release.Draft),
			zap.Bool("prerelease", release.Prerelease))
		return r.getLatestStableFromAllReleases()
	}

	// Clean up the version string (remove 'v' prefix if present)
	version := strings.TrimPrefix(release.TagName, "v")

	logger.Debug("Found version from GitHub",
		zap.String("version", version),
		zap.String("name", release.Name),
		zap.Time("created", release.CreatedAt))

	return version, nil
}

// getLatestStableFromAllReleases fetches all releases to find the latest stable one
func (r *VersionResolver) getLatestStableFromAllReleases() (string, error) {
	logger := otelzap.Ctx(r.rc.Ctx)

	apiURL := "https://api.github.com/repos/saltstack/salt/releases?per_page=50"

	client := &http.Client{Timeout: 15 * time.Second}

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "EOS-Salt-Installer/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to query GitHub API: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			fmt.Printf("Warning: Failed to close response body: %v\n", err)
		}
	}()

	var releases []GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil {
		return "", fmt.Errorf("failed to parse GitHub response: %w", err)
	}

	// Find the latest stable release
	for _, release := range releases {
		if !release.Draft && !release.Prerelease {
			version := strings.TrimPrefix(release.TagName, "v")
			logger.Debug("Found latest stable release",
				zap.String("version", version),
				zap.String("name", release.Name))
			return version, nil
		}
	}

	return "", fmt.Errorf("no stable releases found")
}

// getSaltVersionFromRepo checks the official Salt repository for version info
func (r *VersionResolver) getSaltVersionFromRepo(resolver *VersionResolver) (string, error) {
	// This would implement repository metadata parsing
	// For now, return an error to fall back to other methods
	return "", fmt.Errorf("repository metadata parsing not yet implemented")
}

// getSaltFallbackVersion returns a known good Salt version
func (r *VersionResolver) getSaltFallbackVersion(resolver *VersionResolver) (string, error) {
	logger := otelzap.Ctx(r.rc.Ctx)

	// Updated fallback version - check Salt's releases for current stable
	fallbackVersion := "3007.1"

	logger.Warn("Using hardcoded fallback version",
		zap.String("software", r.software),
		zap.String("version", fallbackVersion),
		zap.String("note", "Update this periodically"))

	return fallbackVersion, nil
}

// getGenericVersionFromGitHub provides generic GitHub version detection
func (r *VersionResolver) getGenericVersionFromGitHub(resolver *VersionResolver) (string, error) {
	// This would be implemented for other software packages
	return "", fmt.Errorf("generic GitHub version detection not implemented")
}

// getGenericFallbackVersion provides a generic fallback
func (r *VersionResolver) getGenericFallbackVersion(resolver *VersionResolver) (string, error) {
	return "", fmt.Errorf("no fallback version defined for %s", r.software)
}

// Cache management functions
func (r *VersionResolver) isCacheValid() bool {
	return r.cachedVersion != "" && time.Now().Before(r.cacheExpiry)
}

func (r *VersionResolver) updateCache(version string) {
	r.cachedVersion = version
	r.cacheExpiry = time.Now().Add(r.cacheDuration)
}

// isValidVersion validates if a version string is reasonable
func (r *VersionResolver) isValidVersion(version string) bool {
	if version == "" {
		return false
	}

	switch strings.ToLower(r.software) {
	case "salt", "saltstack":
		// Salt versions typically follow patterns like "3007.1", "3006.4", etc.
		pattern := regexp.MustCompile(`^\d{4}(\.\d+)*$`)
		return pattern.MatchString(version)
	default:
		// Generic validation - just check it's not empty and doesn't contain spaces
		return !strings.Contains(version, " ") && len(version) > 0
	}
}

// ParseVersion parses a version string into major, minor, patch components
func ParseVersion(version string) (major, minor, patch int, err error) {
	// Remove any non-numeric prefix (like 'v')
	version = regexp.MustCompile(`^[^\d]*`).ReplaceAllString(version, "")

	parts := strings.Split(version, ".")
	if len(parts) == 0 {
		return 0, 0, 0, fmt.Errorf("invalid version format: %s", version)
	}

	// Parse major version
	major, err = strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, 0, fmt.Errorf("invalid major version: %w", err)
	}

	// Parse minor version if available
	if len(parts) > 1 {
		minor, err = strconv.Atoi(parts[1])
		if err != nil {
			minor = 0 // Default to 0 if parsing fails
		}
	}

	// Parse patch version if available
	if len(parts) > 2 {
		patch, err = strconv.Atoi(parts[2])
		if err != nil {
			patch = 0 // Default to 0 if parsing fails
		}
	}

	return major, minor, patch, nil
}

// CompareVersions compares two version strings
// Returns: -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
func CompareVersions(v1, v2 string) int {
	major1, minor1, patch1, err1 := ParseVersion(v1)
	major2, minor2, patch2, err2 := ParseVersion(v2)

	// If either version is invalid, use string comparison
	if err1 != nil || err2 != nil {
		return strings.Compare(v1, v2)
	}

	// Compare major version
	if major1 != major2 {
		if major1 < major2 {
			return -1
		}
		return 1
	}

	// Compare minor version
	if minor1 != minor2 {
		if minor1 < minor2 {
			return -1
		}
		return 1
	}

	// Compare patch version
	if patch1 != patch2 {
		if patch1 < patch2 {
			return -1
		}
		return 1
	}

	return 0
}

// SortVersions sorts a slice of version strings in descending order (newest first)
func SortVersions(versions []string) {
	sort.Slice(versions, func(i, j int) bool {
		return CompareVersions(versions[i], versions[j]) > 0
	})
}

// getMinIOVersionFromGitHub queries MinIO's GitHub releases API
func (r *VersionResolver) getMinIOVersionFromGitHub(resolver *VersionResolver) (string, error) {
	logger := otelzap.Ctx(r.rc.Ctx)
	
	apiURL := "https://api.github.com/repos/minio/minio/releases/latest"
	
	client := &http.Client{Timeout: 10 * time.Second}
	
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	
	// GitHub API prefers this header
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "EOS-MinIO-Installer/1.0")
	
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to query GitHub API: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}
	
	var release GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}
	
	// MinIO tags are like "RELEASE.2024-01-16T16-07-38Z"
	// Extract the version part
	version := strings.TrimPrefix(release.TagName, "RELEASE.")
	
	logger.Info("Retrieved MinIO version from GitHub",
		zap.String("version", version),
		zap.String("tag", release.TagName),
		zap.Time("released", release.CreatedAt))
	
	return version, nil
}

// getMinIOVersionFromUpdateService queries MinIO's update service
func (r *VersionResolver) getMinIOVersionFromUpdateService(resolver *VersionResolver) (string, error) {
	logger := otelzap.Ctx(r.rc.Ctx)
	
	// MinIO provides an update endpoint
	updateURL := "https://dl.min.io/server/minio/release/linux-amd64/minio.sha256sum"
	
	client := &http.Client{Timeout: 10 * time.Second}
	
	resp, err := client.Get(updateURL)
	if err != nil {
		return "", fmt.Errorf("failed to query MinIO update service: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("MinIO update service returned status %d", resp.StatusCode)
	}
	
	// The URL typically contains the version in the path when redirected
	// For now, we'll use the GitHub API as primary method
	logger.Debug("MinIO update service check completed")
	
	// Fallback to GitHub method
	return "", fmt.Errorf("update service parsing not implemented, use GitHub API")
}

// getMinIOFallbackVersion returns a known good MinIO version
func (r *VersionResolver) getMinIOFallbackVersion(resolver *VersionResolver) (string, error) {
	logger := otelzap.Ctx(r.rc.Ctx)
	
	// Updated fallback version - check MinIO's releases for current stable
	fallbackVersion := "2024-01-16T16-07-38Z"
	
	logger.Warn("Using hardcoded fallback version",
		zap.String("software", r.software),
		zap.String("version", fallbackVersion),
		zap.String("note", "Update this periodically"))
	
	return fallbackVersion, nil
}

// getConsulVersionFromGitHub queries Consul's GitHub releases API
func (r *VersionResolver) getConsulVersionFromGitHub(resolver *VersionResolver) (string, error) {
	logger := otelzap.Ctx(r.rc.Ctx)
	
	apiURL := "https://api.github.com/repos/hashicorp/consul/releases/latest"
	
	client := &http.Client{Timeout: 10 * time.Second}
	
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "EOS-Consul-Installer/1.0")
	
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to query GitHub API: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}
	
	var release GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}
	
	// Skip draft and prerelease versions
	if release.Draft || release.Prerelease {
		logger.Warn("Latest GitHub release is not stable",
			zap.String("version", release.TagName),
			zap.Bool("draft", release.Draft),
			zap.Bool("prerelease", release.Prerelease))
		return r.getLatestStableConsulFromAllReleases()
	}
	
	// Remove 'v' prefix if present
	version := strings.TrimPrefix(release.TagName, "v")
	
	logger.Info("Retrieved Consul version from GitHub",
		zap.String("version", version),
		zap.String("tag", release.TagName),
		zap.Time("released", release.CreatedAt))
	
	return version, nil
}

// getLatestStableConsulFromAllReleases fetches all releases to find the latest stable one
func (r *VersionResolver) getLatestStableConsulFromAllReleases() (string, error) {
	logger := otelzap.Ctx(r.rc.Ctx)
	
	apiURL := "https://api.github.com/repos/hashicorp/consul/releases?per_page=50"
	
	client := &http.Client{Timeout: 15 * time.Second}
	
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "EOS-Consul-Installer/1.0")
	
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to query GitHub API: %w", err)
	}
	defer resp.Body.Close()
	
	var releases []GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil {
		return "", fmt.Errorf("failed to parse GitHub response: %w", err)
	}
	
	// Find the latest stable release
	for _, release := range releases {
		if !release.Draft && !release.Prerelease {
			version := strings.TrimPrefix(release.TagName, "v")
			logger.Debug("Found latest stable Consul release",
				zap.String("version", version),
				zap.String("name", release.Name))
			return version, nil
		}
	}
	
	return "", fmt.Errorf("no stable releases found")
}

// getConsulVersionFromCheckpoint queries HashiCorp's checkpoint service
func (r *VersionResolver) getConsulVersionFromCheckpoint(resolver *VersionResolver) (string, error) {
	logger := otelzap.Ctx(r.rc.Ctx)
	
	// HashiCorp's checkpoint API
	checkpointURL := "https://checkpoint-api.hashicorp.com/v1/check/consul"
	
	client := &http.Client{Timeout: 10 * time.Second}
	
	resp, err := client.Get(checkpointURL)
	if err != nil {
		return "", fmt.Errorf("failed to query checkpoint service: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("checkpoint service returned status %d", resp.StatusCode)
	}
	
	var checkpointResp struct {
		CurrentVersion string `json:"current_version"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&checkpointResp); err != nil {
		return "", fmt.Errorf("failed to decode checkpoint response: %w", err)
	}
	
	version := strings.TrimPrefix(checkpointResp.CurrentVersion, "v")
	
	logger.Info("Retrieved Consul version from HashiCorp checkpoint",
		zap.String("version", version))
	
	return version, nil
}

// getConsulFallbackVersion returns a known good Consul version
func (r *VersionResolver) getConsulFallbackVersion(resolver *VersionResolver) (string, error) {
	logger := otelzap.Ctx(r.rc.Ctx)
	
	// Updated fallback version - check Consul's releases for current stable
	fallbackVersion := "1.17.1"
	
	logger.Warn("Using hardcoded fallback version",
		zap.String("software", r.software),
		zap.String("version", fallbackVersion),
		zap.String("note", "Update this periodically"))
	
	return fallbackVersion, nil
}
