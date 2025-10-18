// pkg/consul/installer/version.go
// Version detection and management for Consul installation

package lifecycle

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// VersionManager handles Consul version detection and resolution
type VersionManager struct {
	rc     *eos_io.RuntimeContext
	logger otelzap.LoggerWithCtx
	client *http.Client
}

// NewVersionManager creates a new version manager instance
func NewVersionManager(rc *eos_io.RuntimeContext) *VersionManager {
	return &VersionManager{
		rc:     rc,
		logger: otelzap.Ctx(rc.Ctx),
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// ResolveVersion resolves "latest" to actual version number, or validates specified version
func (vm *VersionManager) ResolveVersion(version string) (string, error) {
	if version == "" {
		version = "latest"
	}

	if version == "latest" {
		return vm.GetLatestVersion()
	}

	// Version is specified, validate format
	if !vm.isValidVersionFormat(version) {
		return "", fmt.Errorf("invalid version format: %s (expected format: X.Y.Z)", version)
	}

	return version, nil
}

// GetLatestVersion fetches the latest Consul version from HashiCorp checkpoint API
func (vm *VersionManager) GetLatestVersion() (string, error) {
	vm.logger.Info("Fetching latest Consul version from HashiCorp")

	resp, err := vm.httpGet("https://checkpoint-api.hashicorp.com/v1/check/consul")
	if err != nil {
		return "", fmt.Errorf("failed to fetch version info: %w", err)
	}

	var versionInfo struct {
		CurrentVersion string `json:"current_version"`
	}

	if err := json.Unmarshal(resp, &versionInfo); err != nil {
		return "", fmt.Errorf("failed to parse version info: %w", err)
	}

	if versionInfo.CurrentVersion == "" {
		return "", fmt.Errorf("no version found in response")
	}

	vm.logger.Info("Latest Consul version detected",
		zap.String("version", versionInfo.CurrentVersion))

	return versionInfo.CurrentVersion, nil
}

// isValidVersionFormat checks if version string matches expected format (e.g., "1.21.3")
func (vm *VersionManager) isValidVersionFormat(version string) bool {
	// Basic validation - should have format X.Y.Z
	// More sophisticated validation could be added here
	return len(version) > 0 && version[0] >= '0' && version[0] <= '9'
}

// httpGet performs HTTP GET request with context and timeout
func (vm *VersionManager) httpGet(url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(vm.rc.Ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	resp, err := vm.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP GET request failed for %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s for URL %s", resp.StatusCode, resp.Status, url)
	}

	body := make([]byte, 0, 4096)
	buf := make([]byte, 1024)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			body = append(body, buf[:n]...)
		}
		if err != nil {
			break
		}
	}

	return body, nil
}
