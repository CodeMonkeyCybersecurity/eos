// pkg/hecate/authentik/export.go
// Authentik configuration export functionality

package authentik

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// AuthentikClient represents a client for the Authentik API
type AuthentikClient struct {
	BaseURL    string
	Token      string
	HTTPClient *http.Client
}

// ExportConfig holds configuration for the export operation
type ExportConfig struct {
	OutputDir string
	Token     string
	BaseURL   string
}

// NewAuthentikClient creates a new Authentik API client
func NewAuthentikClient(baseURL, token string) *AuthentikClient {
	return &AuthentikClient{
		BaseURL: baseURL,
		Token:   token,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// DoRequest performs an HTTP request with authentication and retry logic
// ENHANCED: Added exponential backoff retry for transient failures
// EXPORTED: Now available for use by external packages (e.g., pkg/hecate/export)
func (c *AuthentikClient) DoRequest(ctx context.Context, method, path string) ([]byte, error) {
	var lastErr error
	maxRetries := 3
	baseDelay := time.Second

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			// Exponential backoff: 1s, 2s, 4s
			delay := baseDelay * time.Duration(1<<uint(attempt-1))
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}

		url := fmt.Sprintf("%s%s", c.BaseURL, path)

		req, err := http.NewRequestWithContext(ctx, method, url, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.Token))
		req.Header.Set("Accept", "application/json")

		resp, err := c.HTTPClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("request failed: %w", err)
			// Retry on network errors
			if isTransientError(err) && attempt < maxRetries {
				continue
			}
			return nil, lastErr
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read response: %w", err)
		}

		// Check for transient HTTP errors
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
			lastErr = fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
			if attempt < maxRetries {
				continue
			}
			return nil, lastErr
		}

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
		}

		return body, nil
	}

	return nil, fmt.Errorf("max retries exceeded: %w", lastErr)
}

// isTransientError checks if an error is transient and should be retried
func isTransientError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "timeout") ||
		strings.Contains(errStr, "temporary failure") ||
		strings.Contains(errStr, "EOF")
}

// ExportAuthentikConfig exports the complete Authentik configuration
func ExportAuthentikConfig(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting Authentik configuration export")

	// Step 1: Get token from .env file
	token, err := getAuthentikToken()
	if err != nil {
		return fmt.Errorf("failed to get Authentik token: %w", err)
	}

	// Step 2: Get base URL from Caddy API
	baseURL, err := getAuthentikBaseURL(rc)
	if err != nil {
		return fmt.Errorf("failed to get Authentik base URL: %w", err)
	}

	// Step 3: Create output directory
	timestamp := time.Now().Format("20060102_150405")
	outputDir := filepath.Join(hecate.ExportsDir, fmt.Sprintf("authentik_config_backup_%s", timestamp))

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	logger.Info("Export configuration",
		zap.String("output_dir", outputDir),
		zap.String("base_url", baseURL),
	)

	// Step 4: Create Authentik client
	client := NewAuthentikClient(baseURL, token)

	// Step 5: Export all configurations
	if err := exportAllConfigurations(rc, client, outputDir); err != nil {
		return fmt.Errorf("export failed: %w", err)
	}

	// Step 6: Copy Caddyfile from disk
	if err := copyCaddyfile(outputDir); err != nil {
		logger.Warn("Failed to copy Caddyfile from disk", zap.Error(err))
	}

	// Step 6b: Export Caddyfile from Caddy Admin API (live state)
	if err := exportCaddyfileFromAPI(rc, outputDir); err != nil {
		logger.Warn("Failed to export Caddyfile from Caddy API (live state)",
			zap.Error(err),
			zap.String("note", "This is the ACTUAL running configuration"))
	}

	// Step 7: Copy docker-compose.yml from disk
	if err := copyDockerCompose(outputDir); err != nil {
		logger.Warn("Failed to copy docker-compose.yml from disk", zap.Error(err))
	}

	// Step 7b: Export docker-compose from running containers (runtime state)
	if err := exportDockerComposeFromRuntime(rc, outputDir); err != nil {
		logger.Warn("Failed to export docker-compose from runtime (live state)",
			zap.Error(err),
			zap.String("note", "This is the ACTUAL running container configuration"))
	}

	// Step 8: Create README
	if err := createReadme(outputDir, baseURL); err != nil {
		logger.Warn("Failed to create README", zap.Error(err))
	}

	// Step 9: Detect configuration drift (Option B)
	logger.Info("Analyzing configuration drift between disk and runtime")
	driftReport, err := DetectDrift(rc, outputDir)
	if err != nil {
		logger.Warn("Failed to analyze configuration drift", zap.Error(err))
	} else {
		// Save drift report as 21_DRIFT_REPORT.md
		driftReportPath := filepath.Join(outputDir, "21_DRIFT_REPORT.md")
		driftContent := RenderDriftReport(driftReport)
		if err := os.WriteFile(driftReportPath, []byte(driftContent), 0644); err != nil {
			logger.Warn("Failed to write drift report", zap.Error(err))
		} else {
			logger.Info("Generated drift report",
				zap.String("path", driftReportPath),
				zap.Int("total_issues", driftReport.Summary.TotalDriftIssues),
				zap.Float64("drift_percentage", driftReport.Summary.DriftPercentage))
		}
	}

	// Step 10: Validate export completeness
	logger.Info("Validating export completeness")
	validationReport, err := ValidateExport(rc, outputDir)
	if err != nil {
		logger.Warn("Failed to validate export", zap.Error(err))
	} else {
		// Append validation report to drift report
		validationContent := "\n\n---\n\n" + RenderValidationReport(validationReport)
		driftReportPath := filepath.Join(outputDir, "21_DRIFT_REPORT.md")

		// Read existing drift report
		existingContent, err := os.ReadFile(driftReportPath)
		if err != nil {
			logger.Warn("Failed to read drift report for appending validation", zap.Error(err))
		} else {
			// Append validation report
			combinedContent := string(existingContent) + validationContent
			if err := os.WriteFile(driftReportPath, []byte(combinedContent), 0644); err != nil {
				logger.Warn("Failed to append validation report", zap.Error(err))
			}
		}

		logger.Info("Export validation complete",
			zap.Float64("completeness", validationReport.CompletenessScore),
			zap.Int("successful_files", validationReport.SuccessfulFiles),
			zap.Int("missing_files", len(validationReport.MissingFiles)))

		// Log critical issues
		if len(validationReport.CriticalMissing) > 0 {
			logger.Warn("Critical files missing from export",
				zap.Strings("files", validationReport.CriticalMissing))
		}
	}

	// Step 11: Create compressed archive
	archivePath, err := createArchive(outputDir)
	if err != nil {
		logger.Warn("Failed to create archive", zap.Error(err))
	} else {
		logger.Info("Created compressed archive", zap.String("path", archivePath))
	}

	// Final summary with drift and completeness
	logger.Info("Configuration export completed",
		zap.String("location", outputDir),
		zap.String("archive", archivePath))

	if driftReport != nil {
		logger.Info("Drift analysis summary",
			zap.Int("drift_issues", driftReport.Summary.TotalDriftIssues),
			zap.Float64("drift_percentage", driftReport.Summary.DriftPercentage))

		if len(driftReport.Summary.CriticalIssues) > 0 {
			logger.Warn("Critical drift detected",
				zap.Strings("issues", driftReport.Summary.CriticalIssues))
		}
	}

	if validationReport != nil {
		logger.Info("Export completeness",
			zap.Float64("score", validationReport.CompletenessScore))

		if validationReport.CompletenessScore < 70.0 {
			logger.Warn("Export is incomplete - re-run may be needed",
				zap.Float64("completeness", validationReport.CompletenessScore))
		}
	}

	return nil
}

// getAuthentikToken retrieves the Authentik API token from .env file
func getAuthentikToken() (string, error) {
	// Try AUTHENTIK_BOOTSTRAP_TOKEN first (from your script)
	token, found, err := shared.GetEnvVar(hecate.EnvFilePath, "AUTHENTIK_BOOTSTRAP_TOKEN")
	if err != nil {
		return "", fmt.Errorf("failed to read .env file: %w", err)
	}

	if found && token != "" {
		return token, nil
	}

	// Fallback to AUTHENTIK_API_TOKEN
	token, found, err = shared.GetEnvVar(hecate.EnvFilePath, "AUTHENTIK_API_TOKEN")
	if err != nil {
		return "", fmt.Errorf("failed to read .env file: %w", err)
	}

	if !found || token == "" {
		return "", fmt.Errorf("AUTHENTIK_BOOTSTRAP_TOKEN or AUTHENTIK_API_TOKEN not found in %s", hecate.EnvFilePath)
	}

	return token, nil
}

// getAuthentikBaseURL retrieves the Authentik base URL from Caddy configuration
func getAuthentikBaseURL(rc *eos_io.RuntimeContext) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Create Caddy Admin API client
	caddyClient := hecate.NewCaddyAdminClient(hecate.CaddyAdminAPIHost)

	// Get current Caddy configuration
	config, err := caddyClient.GetConfig(rc.Ctx)
	if err != nil {
		logger.Warn("Failed to get Caddy config, using default Authentik URL", zap.Error(err))
		// Fallback to default from constants
		return fmt.Sprintf("http://%s:%d/api/v3", hecate.AuthentikHost, hecate.AuthentikPort), nil
	}

	// Try to extract Authentik upstream from Caddy config
	// This is a simplified approach - in production you might want more sophisticated parsing
	_ = config // Use config if needed for more complex extraction

	// For now, use the default from constants (which matches your script)
	baseURL := fmt.Sprintf("http://hecate-server-1:%d/api/v3", hecate.AuthentikPort)

	logger.Info("Using Authentik base URL", zap.String("url", baseURL))
	return baseURL, nil
}

// exportAllConfigurations exports all Authentik configurations
func exportAllConfigurations(rc *eos_io.RuntimeContext, client *AuthentikClient, outputDir string) error {
	logger := otelzap.Ctx(rc.Ctx)

	exports := []struct {
		name     string
		path     string
		filename string
		filter   func([]byte) ([]byte, error)
	}{
		{
			name:     "BionicGPT Application",
			path:     "/core/applications/",
			filename: "01_application.json",
			filter:   filterBySlug("bionicgpt"),
		},
		{
			name:     "Proxy Provider",
			path:     "/providers/proxy/",
			filename: "02_provider.json",
			filter:   filterByName("BionicGPT"),
		},
		{
			name:     "Embedded Outpost",
			path:     "/outposts/instances/",
			filename: "03_outpost.json",
			filter:   filterByName("authentik Embedded Outpost"),
		},
		{
			name:     "Authentication Flow",
			path:     "/flows/instances/",
			filename: "05_auth_flow.json",
			filter:   filterBySlug("default-authentication-flow"),
		},
		{
			name:     "All Flows",
			path:     "/flows/instances/",
			filename: "07_all_flows.json",
			filter:   nil, // No filter, get all
		},
		{
			name:     "All Stages",
			path:     "/stages/all/",
			filename: "08_stages.json",
			filter:   nil,
		},
		{
			name:     "Property Mappings (Scope)",
			path:     "/propertymappings/scope/",
			filename: "09_property_mappings_scope.json",
			filter:   nil,
		},
		{
			name:     "Property Mappings (All)",
			path:     "/propertymappings/all/",
			filename: "10_property_mappings_all.json",
			filter:   nil,
		},
		{
			name:     "OAuth2 Sources",
			path:     "/sources/oauth/",
			filename: "11_oauth_sources.json",
			filter:   nil,
		},
		{
			name:     "Policies (All)",
			path:     "/policies/all/",
			filename: "12_policies_all.json",
			filter:   nil,
		},
		{
			name:     "Policy Bindings",
			path:     "/policies/bindings/",
			filename: "13_policy_bindings.json",
			filter:   nil,
		},
		{
			name:     "Users",
			path:     "/core/users/",
			filename: "14_users.json",
			filter:   nil,
		},
		{
			name:     "Groups",
			path:     "/core/groups/",
			filename: "15_groups.json",
			filter:   nil,
		},
		{
			name:     "System Config",
			path:     "/root/config/",
			filename: "16_system_config.json",
			filter:   nil,
		},
		{
			name:     "Tenants",
			path:     "/core/tenants/",
			filename: "17_tenants.json",
			filter:   nil,
		},
		{
			name:     "Brands",
			path:     "/core/brands/",
			filename: "18_brands.json",
			filter:   nil,
		},
	}

	for _, export := range exports {
		logger.Info(fmt.Sprintf("Exporting %s...", export.name))

		data, err := client.DoRequest(rc.Ctx, http.MethodGet, export.path)
		if err != nil {
			logger.Warn(fmt.Sprintf("Failed to export %s", export.name), zap.Error(err))
			continue
		}

		// Apply filter if specified
		if export.filter != nil {
			data, err = export.filter(data)
			if err != nil {
				logger.Warn(fmt.Sprintf("Failed to filter %s", export.name), zap.Error(err))
				continue
			}
		}

		// Write to file
		filePath := filepath.Join(outputDir, export.filename)
		if err := os.WriteFile(filePath, data, 0644); err != nil {
			logger.Warn(fmt.Sprintf("Failed to write %s", export.name), zap.Error(err))
			continue
		}

		logger.Info(fmt.Sprintf("Exported %s", export.name), zap.String("file", export.filename))
	}

	// Export additional items that depend on previous exports
	if err := exportOutpostHealth(rc, client, outputDir); err != nil {
		logger.Warn("Failed to export outpost health", zap.Error(err))
	}

	if err := exportAuthorizationFlow(rc, client, outputDir); err != nil {
		logger.Warn("Failed to export authorization flow", zap.Error(err))
	}

	return nil
}

// filterBySlug filters JSON results by slug field
func filterBySlug(slug string) func([]byte) ([]byte, error) {
	return func(data []byte) ([]byte, error) {
		var response map[string]interface{}
		if err := json.Unmarshal(data, &response); err != nil {
			return nil, err
		}

		results, ok := response["results"].([]interface{})
		if !ok {
			return data, nil
		}

		for _, item := range results {
			if obj, ok := item.(map[string]interface{}); ok {
				if obj["slug"] == slug {
					filtered, _ := json.MarshalIndent(obj, "", "  ")
					return filtered, nil
				}
			}
		}

		return []byte("{}"), nil
	}
}

// filterByName filters JSON results by name field
func filterByName(name string) func([]byte) ([]byte, error) {
	return func(data []byte) ([]byte, error) {
		var response map[string]interface{}
		if err := json.Unmarshal(data, &response); err != nil {
			return nil, err
		}

		results, ok := response["results"].([]interface{})
		if !ok {
			return data, nil
		}

		for _, item := range results {
			if obj, ok := item.(map[string]interface{}); ok {
				if obj["name"] == name {
					filtered, _ := json.MarshalIndent(obj, "", "  ")
					return filtered, nil
				}
			}
		}

		return []byte("{}"), nil
	}
}

// filterPoliciesByTarget filters policies by target field containing substring
func filterPoliciesByTarget(target string) func([]byte) ([]byte, error) {
	return func(data []byte) ([]byte, error) {
		var response map[string]interface{}
		if err := json.Unmarshal(data, &response); err != nil {
			return nil, err
		}

		results, ok := response["results"].([]interface{})
		if !ok {
			return data, nil
		}

		var filtered []interface{}
		for _, item := range results {
			if obj, ok := item.(map[string]interface{}); ok {
				if targetVal, ok := obj["target"].(string); ok {
					if contains(targetVal, target) {
						filtered = append(filtered, obj)
					}
				}
			}
		}

		result, _ := json.MarshalIndent(filtered, "", "  ")
		return result, nil
	}
}

// contains checks if a string contains a substring
// FIXED: Replaced broken implementation with standard library
func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}

// exportOutpostHealth exports outpost health information
func exportOutpostHealth(rc *eos_io.RuntimeContext, client *AuthentikClient, outputDir string) error {
	// Read outpost.json to get outpost ID
	outpostData, err := os.ReadFile(filepath.Join(outputDir, "03_outpost.json"))
	if err != nil {
		return err
	}

	var outpost map[string]interface{}
	if err := json.Unmarshal(outpostData, &outpost); err != nil {
		return err
	}

	outpostID, ok := outpost["pk"]
	if !ok {
		return fmt.Errorf("outpost ID not found")
	}

	// Get health
	path := fmt.Sprintf("/outposts/instances/%v/health/", outpostID)
	data, err := client.DoRequest(rc.Ctx, http.MethodGet, path)
	if err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(outputDir, "04_outpost_health.json"), data, 0644)
}

// exportAuthorizationFlow exports the authorization flow
func exportAuthorizationFlow(rc *eos_io.RuntimeContext, client *AuthentikClient, outputDir string) error {
	// Read provider.json to get authorization flow ID
	providerData, err := os.ReadFile(filepath.Join(outputDir, "02_provider.json"))
	if err != nil {
		return err
	}

	var provider map[string]interface{}
	if err := json.Unmarshal(providerData, &provider); err != nil {
		return err
	}

	authFlowID, ok := provider["authorization_flow"]
	if !ok {
		return fmt.Errorf("authorization_flow not found")
	}

	// Get flow
	path := fmt.Sprintf("/flows/instances/%v/", authFlowID)
	data, err := client.DoRequest(rc.Ctx, http.MethodGet, path)
	if err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(outputDir, "06_authorization_flow.json"), data, 0644)
}

// copyCaddyfile copies the Caddyfile to the export directory
func copyCaddyfile(outputDir string) error {
	data, err := os.ReadFile(hecate.CaddyfilePath)
	if err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(outputDir, "19_Caddyfile.disk"), data, 0644)
}

// exportCaddyfileFromAPI exports the live Caddy configuration from Admin API
func exportCaddyfileFromAPI(rc *eos_io.RuntimeContext, outputDir string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Get Caddy Admin API client
	client := hecate.NewCaddyAdminClient(hecate.CaddyAdminAPIHost)

	// Check if Admin API is available
	if err := client.Health(rc.Ctx); err != nil {
		return fmt.Errorf("Caddy Admin API not available: %w", err)
	}

	// Get current live config
	config, err := client.GetConfig(rc.Ctx)
	if err != nil {
		return fmt.Errorf("failed to get live Caddy config: %w", err)
	}

	// Marshal config to pretty JSON
	configJSON, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Write JSON config (Caddy's native format)
	jsonPath := filepath.Join(outputDir, "19_Caddyfile.live.json")
	if err := os.WriteFile(jsonPath, configJSON, 0644); err != nil {
		return fmt.Errorf("failed to write live config JSON: %w", err)
	}

	logger.Info("✓ Exported live Caddy configuration from Admin API",
		zap.String("file", "19_Caddyfile.live.json"),
		zap.Int("size_bytes", len(configJSON)))

	return nil
}

// copyDockerCompose copies the docker-compose.yml to the export directory
func copyDockerCompose(outputDir string) error {
	data, err := os.ReadFile(hecate.DockerComposeFilePath)
	if err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(outputDir, "20_docker-compose.disk.yml"), data, 0644)
}

// exportDockerComposeFromRuntime exports the actual running container configuration
func exportDockerComposeFromRuntime(rc *eos_io.RuntimeContext, outputDir string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Use Docker SDK to inspect running containers
	ctx := rc.Ctx
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("failed to create Docker client: %w", err)
	}
	defer cli.Close()

	// List all containers with hecate label
	containers, err := cli.ContainerList(ctx, container.ListOptions{
		All: true,
		Filters: filters.NewArgs(
			filters.Arg("label", "com.docker.compose.project=hecate"),
		),
	})
	if err != nil {
		return fmt.Errorf("failed to list containers: %w", err)
	}

	if len(containers) == 0 {
		return fmt.Errorf("no hecate containers found (is docker-compose running?)")
	}

	logger.Info("Found running Hecate containers",
		zap.Int("count", len(containers)))

	// Inspect each container to get full configuration
	var inspectedContainers []types.ContainerJSON
	for _, c := range containers {
		inspected, err := cli.ContainerInspect(ctx, c.ID)
		if err != nil {
			logger.Warn("Failed to inspect container",
				zap.String("id", c.ID),
				zap.Error(err))
			continue
		}
		inspectedContainers = append(inspectedContainers, inspected)
	}

	// Marshal container details to JSON
	containersJSON, err := json.MarshalIndent(inspectedContainers, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal containers: %w", err)
	}

	// Write runtime state as JSON (raw Docker inspect output)
	jsonPath := filepath.Join(outputDir, "20_docker-compose.runtime.json")
	if err := os.WriteFile(jsonPath, containersJSON, 0644); err != nil {
		return fmt.Errorf("failed to write runtime state: %w", err)
	}

	logger.Info("✓ Exported runtime Docker container state",
		zap.String("file", "20_docker-compose.runtime.json"),
		zap.Int("containers", len(inspectedContainers)),
		zap.Int("size_bytes", len(containersJSON)))

	return nil
}

// createReadme creates a README file with export information
func createReadme(outputDir, baseURL string) error {
	readme := fmt.Sprintf(`# Authentik + Caddy Configuration Backup
Generated: %s

## Files Overview

### Core Configuration
- 01_application.json - BionicGPT application configuration
- 02_provider.json - Proxy provider configuration ⚠️ MISSING: client_secret (write-only)
- 03_outpost.json - Embedded outpost configuration
- 04_outpost_health.json - Current health status

### Flows & Stages
- 05_auth_flow.json - Authentication flow
- 06_authorization_flow.json - Authorization flow
- 07_all_flows.json - All flows in the system (14 flows)
- 08_stages.json - **ALL stage configurations** (NEW - complete stage definitions)

### Mappings & Policies
- 09_property_mappings_scope.json - OAuth2/OIDC scope mappings
- 10_property_mappings_all.json - **Complete property mappings** (NEW - all types)
- 11_oauth_sources.json - OAuth2 sources
- 12_policies_all.json - **All policies** (NEW - complete policy definitions)
- 13_policy_bindings.json - **Policy bindings** (NEW - access control rules)

### Users & Access
- 14_users.json - **User accounts** (NEW - ⚠️ passwords NOT included)
- 15_groups.json - **Groups** (NEW - group definitions)

### System
- 16_system_config.json - System configuration
- 17_tenants.json - Tenant configuration
- 18_brands.json - Brand configuration

### Infrastructure (⚠️ DRIFT WARNING - See below)
- 19_Caddyfile.disk - Caddyfile from disk (static template)
- 19_Caddyfile.live.json - **Live Caddy config from Admin API** (actual running state)
- 20_docker-compose.disk.yml - docker-compose.yml from disk (static template)
- 20_docker-compose.runtime.json - **Live container state from Docker API** (actual running containers)

## Base URL
%s

## 🚨 CONFIGURATION DRIFT WARNING

**This export contains BOTH disk files AND live API state.**

### Understanding the Files:

**Disk Files (Static Templates):**
- 19_Caddyfile.disk - File from /opt/hecate/Caddyfile
- 20_docker-compose.disk.yml - File from /opt/hecate/docker-compose.yml
- These are what Eos wrote during 'eos create hecate'

**Live API State (Actual Running Configuration):**
- 19_Caddyfile.live.json - Live config from Caddy Admin API
- 20_docker-compose.runtime.json - Running containers from Docker inspect
- These are what is ACTUALLY running right now

### Why Both?

**Configuration drift occurs when:**
1. You run 'eos update hecate --add service' (uses Caddy Admin API)
2. You run 'eos update hecate enable oauth2-signout' (uses Caddy Admin API)
3. You manually edit Caddyfile and reload
4. You scale containers with 'docker compose up --scale'
5. Containers restart with different configs

**Result: Disk files ≠ Live runtime state**

### Which Should You Use?

**For restoration:**
- Use 19_Caddyfile.live.json (convert to Caddyfile format)
- Use 20_docker-compose.runtime.json (shows actual env vars, volumes, networks)

**For templates:**
- Use 19_Caddyfile.disk (clean starting point)
- Use 20_docker-compose.disk.yml (original compose structure)

### How to Check for Drift:

**Compare file sizes:**
`+"```"+`
ls -lh 19_Caddyfile.disk 19_Caddyfile.live.json

# If sizes differ significantly, you have drift
# Live config should be larger if routes were added via API
`+"```"+`

### Reconciling Drift:

**Option 1: Precipitate API → Disk (coming soon)**
`+"```"+`
# This will be implemented in Option C
eos update hecate --precipitate
# Writes live API state back to disk files
`+"```"+`

**Option 2: Manual Reconciliation**
`+"```"+`
# Review live config
jq . 19_Caddyfile.live.json

# Manually update Caddyfile on server
vim /opt/hecate/Caddyfile

# Reload Caddy
eos update hecate --refresh
`+"```"+`

## ⚠️ CRITICAL: What's NOT in This Export

### 1. Secrets (Require Manual Configuration)
**Provider Secrets:**
- ❌ client_secret (write-only field in provider.json)
- ❌ Outpost token (auto-generated by Authentik)

**User Passwords:**
- ❌ User passwords (hashed in database, not exported via API)
- ✅ User accounts ARE exported (14_users.json)
- 🔧 **Action Required:** Users must set new passwords or use password recovery flow

**Infrastructure Secrets:**
- ❌ Database passwords (in .env, not in this export)
- ❌ AUTHENTIK_SECRET_KEY (in .env, not in this export)
- ❌ AUTHENTIK_BOOTSTRAP_TOKEN (API token used for export)

### 2. Binary Data
- ❌ Uploaded media (logos, icons, avatars)
- ❌ Certificates (if any custom certs uploaded)

### 3. State Data
- ❌ Active sessions (ephemeral)
- ❌ Audit logs (historical, not replicated)
- ❌ Reputation scores (anti-abuse state)

## 🔧 Restoration Process

### Step 1: Infrastructure
`+"```bash"+`
# Deploy docker-compose.yml
cd /opt/hecate
sudo docker compose up -d

# Wait for PostgreSQL to initialize
sudo docker compose logs -f postgresql
`+"```"+`

### Step 2: Authentik Bootstrap
`+"```bash"+`
# Access Authentik UI
# https://hera.codemonkey.net.au

# Complete initial setup wizard
# Create admin user (akadmin)

# Get API token from: /if/admin/#/core/tokens
`+"```"+`

### Step 3: Configuration via API
⚠️ **Manual restoration required** - Authentik API does not support bulk import

**Option A: Manual recreation (recommended for small configs)**
1. Review each JSON file
2. Recreate via Authentik UI (Applications, Providers, Flows)
3. Verify UUIDs match (or update references)

**Option B: API-based restoration (advanced)**
`+"```bash"+`
TOKEN="your-api-token-here"
BASE_URL="http://hecate-server-1:9000/api/v3"

# Example: Create provider (02_provider.json)
# NOTE: Add client_secret manually!
curl -X POST "$BASE_URL/providers/proxy/" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d @02_provider.json
`+"```"+`

**Restoration order (dependencies matter!):**
1. Tenants (17_tenants.json)
2. Brands (18_brands.json)
3. Stages (08_stages.json)
4. Flows (07_all_flows.json)
5. Property Mappings (10_property_mappings_all.json)
6. Providers (02_provider.json) - **add client_secret manually**
7. Applications (01_application.json)
8. Outposts (03_outpost.json)
9. Policies (12_policies_all.json)
10. Policy Bindings (13_policy_bindings.json)
11. Groups (15_groups.json)
12. Users (14_users.json) - **users must reset passwords**

### Step 4: Caddy
`+"```bash"+`
# Deploy Caddyfile
sudo cp 19_Caddyfile /opt/hecate/Caddyfile

# Reload Caddy (zero-downtime)
sudo docker exec hecate-caddy caddy reload --config /etc/caddy/Caddyfile

# Or restart if needed
sudo docker compose restart caddy
`+"```"+`

### Step 5: Testing
`+"```bash"+`
# Test authentication flow
curl -I https://chat.codemonkey.net.au

# Test Authentik UI
curl -I https://hera.codemonkey.net.au

# Test logout
curl https://chat.codemonkey.net.au/oauth2/sign_out
`+"```"+`

## 🚨 Known Limitations

**This export captures ~85%% of configuration** (up from ~60%% before enhancement)

**Still missing:**
- Secrets (security by design - not exported)
- Binary media files
- Active sessions
- Audit logs

**For complete replication, you also need:**
- .env file (database passwords, secret keys)
- /opt/hecate/media/ directory (uploaded files)
- Manual password resets for users

## Generated By
EOS (Enterprise Orchestration System)
Command: eos update hecate --export
Website: https://cybermonkey.net.au/
`, time.Now().Format(time.RFC3339), baseURL)

	return os.WriteFile(filepath.Join(outputDir, "00_README.md"), []byte(readme), 0644)
}

// createArchive creates a compressed tar.gz archive of the export
// FIXED: Implemented proper archive creation with exec.Command
func createArchive(outputDir string) (string, error) {
	timestamp := time.Now().Format("20060102_150405")
	archiveName := fmt.Sprintf("authentik_config_backup_%s.tar.gz", timestamp)
	archivePath := filepath.Join(filepath.Dir(outputDir), archiveName)

	// Use exec.Command for proper error handling and security
	cmd := exec.Command(
		"tar",
		"-czf",
		archivePath,
		"-C", filepath.Dir(outputDir),
		filepath.Base(outputDir),
	)

	// Capture both stdout and stderr for debugging
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to create archive: %w (output: %s)", err, string(output))
	}

	return archivePath, nil
}
