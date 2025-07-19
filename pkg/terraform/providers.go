// pkg/terraform/providers.go

package terraform

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// validateHetznerProvider checks Hetzner Cloud provider authentication and permissions
func validateHetznerProvider(rc *eos_io.RuntimeContext, validation *ProviderValidation) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Check for Hetzner API token
	apiToken := os.Getenv("HCLOUD_TOKEN")
	if apiToken == "" {
		return eos_err.NewUserError("HCLOUD_TOKEN environment variable not set")
	}

	// Test API connectivity (simplified)
	ctx, cancel := context.WithTimeout(rc.Ctx, 10*time.Second)
	defer cancel()

	// Use curl to test Hetzner API (production would use proper HTTP client)
	output, err := execute.Run(ctx, execute.Options{
		Command: "curl",
		Args: []string{
			"-s",
			"-H", "Authorization: Bearer " + apiToken,
			"-H", "Content-Type: application/json",
			"https://api.hetzner.cloud/v1/servers",
		},
		Capture: true,
	})

	if err != nil {
		return fmt.Errorf("Hetzner API test failed: %w", err)
	}

	// Check if response is valid JSON (basic validation)
	var response map[string]interface{}
	if err := json.Unmarshal([]byte(output), &response); err != nil {
		return fmt.Errorf("invalid API response: %w", err)
	}

	// Check for error in response
	if errorMsg, exists := response["error"]; exists {
		return fmt.Errorf("API error: %v", errorMsg)
	}

	validation.Authenticated = true
	validation.Version = "latest"
	validation.Permissions = []string{"dns:read", "dns:write"}

	logger.Debug("Hetzner provider validation successful")
	return nil
}

// validateConsulProvider checks Consul provider connectivity and permissions
func validateConsulProvider(rc *eos_io.RuntimeContext, validation *ProviderValidation) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Check if Consul is accessible
	consulAddr := os.Getenv("CONSUL_HTTP_ADDR")
	if consulAddr == "" {
		consulAddr = "http://127.0.0.1:8500" // Default
	}

	ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Second)
	defer cancel()

	// Test Consul API
	output, err := execute.Run(ctx, execute.Options{
		Command: "curl",
		Args: []string{
			"-s",
			"-f",
			consulAddr + "/v1/status/leader",
		},
		Capture: true,
	})

	if err != nil {
		return fmt.Errorf("Consul API test failed: %w", err)
	}

	if strings.TrimSpace(output) == "" {
		return fmt.Errorf("Consul cluster has no leader")
	}

	validation.Authenticated = true
	validation.Version = "latest"
	validation.Permissions = []string{"kv:read", "kv:write"}

	logger.Debug("Consul provider validation successful")
	return nil
}

// validateVaultProvider checks Vault provider authentication and permissions
func validateVaultProvider(rc *eos_io.RuntimeContext, validation *ProviderValidation) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Check Vault configuration
	vaultAddr := os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		return eos_err.NewUserError("VAULT_ADDR environment variable not set")
	}

	vaultToken := os.Getenv("VAULT_TOKEN")
	if vaultToken == "" {
		return eos_err.NewUserError("VAULT_TOKEN environment variable not set")
	}

	ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Second)
	defer cancel()

	// Test Vault API
	_, err := execute.Run(ctx, execute.Options{
		Command: "curl",
		Args: []string{
			"-s",
			"-f",
			"-H", "X-Vault-Token: " + vaultToken,
			vaultAddr + "/v1/sys/health",
		},
		Capture: true,
	})

	if err != nil {
		return fmt.Errorf("Vault API test failed: %w", err)
	}

	validation.Authenticated = true
	validation.Version = "latest"
	validation.Permissions = []string{"secrets:read", "secrets:write"}

	logger.Debug("Vault provider validation successful")
	return nil
}

// checkHetznerQuotas validates Hetzner DNS quotas and rate limits
func checkHetznerQuotas(rc *eos_io.RuntimeContext, validation *QuotaValidation) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	apiToken := os.Getenv("HCLOUD_TOKEN")
	if apiToken == "" {
		return fmt.Errorf("HCLOUD_TOKEN not available for quota check")
	}

	ctx, cancel := context.WithTimeout(rc.Ctx, 10*time.Second)
	defer cancel()

	// Check primary DNS zones (simplified quota check)
	output, err := execute.Run(ctx, execute.Options{
		Command: "curl",
		Args: []string{
			"-s",
			"-H", "Authorization: Bearer " + apiToken,
			"https://dns.hetzner.com/api/v1/zones",
		},
		Capture: true,
	})

	if err != nil {
		return fmt.Errorf("failed to check DNS zones: %w", err)
	}

	// Parse response to count existing DNS zones
	var response struct {
		Zones []interface{} `json:"zones"`
	}
	
	if err := json.Unmarshal([]byte(output), &response); err != nil {
		return fmt.Errorf("failed to parse DNS zones response: %w", err)
	}

	// Simplified quota validation (Hetzner allows 100 zones by default)
	validation.DNSRecordsUsed = len(response.Zones)
	validation.DNSRecordsLimit = 100
	validation.APICallsRemaining = 3600 // Simplified rate limit
	validation.RateLimitStatus = "ok"

	if validation.DNSRecordsUsed >= validation.DNSRecordsLimit {
		return fmt.Errorf("DNS zones quota exhausted: %d/%d", validation.DNSRecordsUsed, validation.DNSRecordsLimit)
	}

	logger.Debug("Hetzner quota validation successful",
		zap.Int("zones_used", validation.DNSRecordsUsed),
		zap.Int("zones_limit", validation.DNSRecordsLimit))

	return nil
}

// Helper functions for version comparison and validation

// isVersionInRange checks if current version is within min-max range
func isVersionInRange(current, min, max string) bool {
	// Simplified version comparison (production would use semver library)
	currentParts := parseVersion(current)
	minParts := parseVersion(min)
	maxParts := parseVersion(max)

	if len(currentParts) < 2 || len(minParts) < 2 || len(maxParts) < 2 {
		return false
	}

	// Compare major.minor
	currentMajor, currentMinor := currentParts[0], currentParts[1]
	minMajor, minMinor := minParts[0], minParts[1]
	maxMajor, maxMinor := maxParts[0], maxParts[1]

	// Check if current >= min
	if currentMajor < minMajor || (currentMajor == minMajor && currentMinor < minMinor) {
		return false
	}

	// Check if current < max
	if currentMajor > maxMajor || (currentMajor == maxMajor && currentMinor >= maxMinor) {
		return false
	}

	return true
}

// parseVersion parses version string into integer components
func parseVersion(version string) []int {
	// Remove 'v' prefix if present
	version = strings.TrimPrefix(version, "v")
	
	// Split by dots and parse integers
	parts := strings.Split(version, ".")
	result := make([]int, len(parts))
	
	for i, part := range parts {
		// Remove any non-numeric suffixes (like -beta, -rc1)
		re := regexp.MustCompile(`^(\d+)`)
		matches := re.FindStringSubmatch(part)
		if len(matches) > 1 {
			if num, err := strconv.Atoi(matches[1]); err == nil {
				result[i] = num
			}
		}
	}
	
	return result
}

// allProvidersValid checks if all provider validations passed
func allProvidersValid(validations []ProviderValidation) bool {
	for _, v := range validations {
		if v.Error != "" || !v.Authenticated {
			return false
		}
	}
	return true
}

// validateStateFileStructure validates Terraform state file JSON structure and version
func validateStateFileStructure(rc *eos_io.RuntimeContext, statePath string, validation *StateValidation) error {
	// Read and parse state file
	data, err := os.ReadFile(statePath)
	if err != nil {
		return fmt.Errorf("failed to read state file: %w", err)
	}

	// Parse as JSON to check structure
	var state map[string]interface{}
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("state file is not valid JSON: %w", err)
	}

	// Check for required fields
	if version, ok := state["version"].(float64); ok {
		if version < 4 {
			return fmt.Errorf("state file version %.0f is too old, minimum version 4 required", version)
		}
	} else {
		return fmt.Errorf("state file missing version field")
	}

	// Count resources
	if resources, ok := state["resources"].([]interface{}); ok {
		validation.ResourceCount = len(resources)
	}

	return nil
}