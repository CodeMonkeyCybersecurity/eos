// pkg/vault/config_validator.go

package vault

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ConfigValidationResult contains configuration validation results
type ConfigValidationResult struct {
	Valid       bool     `json:"valid"`
	Errors      []string `json:"errors,omitempty"`
	Warnings    []string `json:"warnings,omitempty"`
	Suggestions []string `json:"suggestions,omitempty"`
	Method      string   `json:"method"` // "vault-binary" or "manual-parser"
}

// ValidateConfigWithFallback validates Vault configuration using vault binary, falls back to manual parsing
// This implements the P0 requirement from the audit: config validation with manual fallback
func ValidateConfigWithFallback(rc *eos_io.RuntimeContext, configPath string) (*ConfigValidationResult, error) {
	log := otelzap.Ctx(rc.Ctx)
	log.Info(" Validating Vault configuration", zap.String("config", configPath))

	result := &ConfigValidationResult{
		Valid:       true,
		Errors:      []string{},
		Warnings:    []string{},
		Suggestions: []string{},
	}

	// ASSESS: Check if config file exists and is readable
	if err := assessConfigFile(rc, configPath, result); err != nil {
		return result, err
	}

	// INTERVENE: Try vault binary validation first
	if vaultBinaryValidation(rc, configPath, result) {
		log.Info(" Configuration validated using vault binary")
		return result, nil
	}

	// FALLBACK: Manual HCL parsing if vault binary unavailable/fails
	log.Warn("Vault binary validation unavailable, using manual HCL parser")
	if err := manualConfigValidation(rc, configPath, result); err != nil {
		return result, err
	}

	// EVALUATE: Final validation status
	if len(result.Errors) > 0 {
		result.Valid = false
		log.Error(" Configuration validation failed",
			zap.Int("errors", len(result.Errors)),
			zap.Strings("error_list", result.Errors))
	} else {
		log.Info(" Configuration validated using manual parser",
			zap.Int("warnings", len(result.Warnings)))
	}

	return result, nil
}

// assessConfigFile performs basic file checks before validation
func assessConfigFile(rc *eos_io.RuntimeContext, configPath string, result *ConfigValidationResult) error {
	log := otelzap.Ctx(rc.Ctx)

	// Check file exists
	info, err := os.Stat(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			result.Valid = false
			result.Errors = append(result.Errors, fmt.Sprintf("config file not found: %s", configPath))
			return fmt.Errorf("config file not found: %w", err)
		}
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("cannot access config file: %v", err))
		return fmt.Errorf("cannot access config: %w", err)
	}

	// Check file is not empty
	if info.Size() == 0 {
		result.Valid = false
		result.Errors = append(result.Errors, "config file is empty")
		return fmt.Errorf("config file is empty")
	}

	// Check file permissions (should not be world-writable)
	if info.Mode().Perm()&0002 != 0 {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("config file is world-writable (%o) - security risk", info.Mode().Perm()))
	}

	log.Debug("Config file assessment passed",
		zap.String("path", configPath),
		zap.Int64("size", info.Size()),
		zap.String("mode", info.Mode().String()))

	return nil
}

// vaultBinaryValidation attempts to validate using vault binary
// Returns true if validation succeeded, false if unavailable or failed
func vaultBinaryValidation(rc *eos_io.RuntimeContext, configPath string, result *ConfigValidationResult) bool {
	log := otelzap.Ctx(rc.Ctx)

	// Check if vault binary is available
	vaultPath, err := exec.LookPath("vault")
	if err != nil {
		log.Debug("Vault binary not found in PATH, will use manual validation")
		return false
	}

	log.Debug("Found vault binary", zap.String("path", vaultPath))

	// Try to run vault validate
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: vaultPath,
		Args:    []string{"operator", "validate", "-config", configPath},
		Capture: true,
		Timeout: 5000, // 5 second timeout
	})

	if err != nil {
		// Check if it's a "command not found" error (old Vault version)
		if strings.Contains(output, "No such command") || strings.Contains(output, "unknown command") {
			log.Debug("vault operator validate not available (old version?), using manual validation")
			return false
		}

		// Validation failed - this is a real error
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("vault validate failed: %s", output))
		result.Method = "vault-binary"
		log.Warn("Vault binary validation failed", zap.String("output", output))
		return true // We did run validation, it just failed
	}

	// Validation succeeded
	result.Method = "vault-binary"
	log.Debug("Vault binary validation succeeded", zap.String("output", output))
	return true
}

// manualConfigValidation performs manual HCL parsing and semantic validation
func manualConfigValidation(rc *eos_io.RuntimeContext, configPath string, result *ConfigValidationResult) error {
	log := otelzap.Ctx(rc.Ctx)
	result.Method = "manual-parser"

	// Read config file
	content, err := os.ReadFile(configPath)
	if err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("failed to read config: %v", err))
		return fmt.Errorf("read config: %w", err)
	}

	// Parse HCL syntax
	parser := hclparse.NewParser()
	_, diags := parser.ParseHCL(content, configPath)
	if diags.HasErrors() {
		result.Valid = false
		for _, diag := range diags {
			result.Errors = append(result.Errors, diag.Error())
		}
		log.Error("HCL syntax validation failed", zap.Int("errors", len(diags.Errs())))
		return nil // Return nil to allow semantic checks to proceed if needed
	}

	log.Debug("HCL syntax validation passed")

	// Perform semantic validation
	validateSemantics(rc, string(content), result)

	return nil
}

// validateSemantics performs semantic validation of Vault config
func validateSemantics(rc *eos_io.RuntimeContext, content string, result *ConfigValidationResult) {
	log := otelzap.Ctx(rc.Ctx)

	// Required blocks
	requiredBlocks := map[string]string{
		"listener": "Vault requires at least one listener block",
		"storage":  "Vault requires a storage backend configuration",
	}

	for block, message := range requiredBlocks {
		if !strings.Contains(content, block) {
			result.Errors = append(result.Errors, message)
		}
	}

	// Required top-level attributes
	requiredAttrs := map[string]string{
		"api_addr": "api_addr is required for HA and agent communication",
	}

	for attr, message := range requiredAttrs {
		if !strings.Contains(content, attr) {
			result.Warnings = append(result.Warnings, message)
		}
	}

	// Check for common misconfigurations
	checkCommonMisconfigurations(rc, content, result)

	// Check TLS configuration if present
	if strings.Contains(content, "tls_cert_file") || strings.Contains(content, "tls_key_file") {
		validateTLSConfig(rc, content, result)
	}

	// Check storage backend specific issues
	validateStorageBackend(rc, content, result)

	log.Debug("Semantic validation completed",
		zap.Int("errors", len(result.Errors)),
		zap.Int("warnings", len(result.Warnings)))
}

// checkCommonMisconfigurations checks for common Vault config mistakes
func checkCommonMisconfigurations(_ *eos_io.RuntimeContext, content string, result *ConfigValidationResult) {
	// Check for legacy port 8200 (should be 8179 in Eos)
	if strings.Contains(content, ":8200") {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("Using legacy port 8200, Eos standard is %s", shared.VaultDefaultPort))
		result.Suggestions = append(result.Suggestions,
			"Run 'eos update vault' to migrate to new port configuration")
	}

	// Check for tls_disable = "true" (string instead of bool)
	if strings.Contains(content, `tls_disable = "true"`) || strings.Contains(content, `tls_disable = "false"`) {
		result.Warnings = append(result.Warnings,
			"tls_disable should be boolean (true/false) not string (\"true\"/\"false\")")
	}

	// Check for insecure configurations
	if strings.Contains(content, "tls_disable = true") || strings.Contains(content, "tls_disable=true") {
		result.Warnings = append(result.Warnings,
			"TLS is disabled - this is insecure for production use")
		result.Suggestions = append(result.Suggestions,
			"Enable TLS with 'eos create vault --tls'")
	}

	// Check for disable_mlock = false on systems where it might fail
	if strings.Contains(content, "disable_mlock = false") || !strings.Contains(content, "disable_mlock") {
		result.Suggestions = append(result.Suggestions,
			"Ensure CAP_IPC_LOCK capability is granted in systemd service if disable_mlock = false")
	}

	// Check for empty ui config
	if strings.Contains(content, "ui = true") {
		result.Suggestions = append(result.Suggestions,
			fmt.Sprintf("UI enabled - accessible at %s/ui", shared.GetVaultAddr()))
	}
}

// validateTLSConfig validates TLS-specific configuration
func validateTLSConfig(rc *eos_io.RuntimeContext, content string, result *ConfigValidationResult) {
	log := otelzap.Ctx(rc.Ctx)

	hasCert := strings.Contains(content, "tls_cert_file")
	hasKey := strings.Contains(content, "tls_key_file")

	if hasCert && !hasKey {
		result.Errors = append(result.Errors, "tls_cert_file specified but tls_key_file is missing")
	}
	if hasKey && !hasCert {
		result.Errors = append(result.Errors, "tls_key_file specified but tls_cert_file is missing")
	}

	// Extract and verify TLS file paths exist
	if hasCert && hasKey {
		// Simple regex-like extraction (not perfect but good enough for validation)
		certPath := extractConfigValue(content, "tls_cert_file")
		keyPath := extractConfigValue(content, "tls_key_file")

		// CRITICAL: Check for empty string paths (historical regression protection)
		if certPath == "" {
			result.Errors = append(result.Errors,
				"tls_cert_file is set to empty string - this will cause Vault to crash on startup")
		}
		if keyPath == "" {
			result.Errors = append(result.Errors,
				"tls_key_file is set to empty string - this will cause Vault to crash on startup")
		}

		if certPath != "" {
			if _, err := os.Stat(certPath); err != nil {
				result.Warnings = append(result.Warnings,
					fmt.Sprintf("TLS cert file may not exist: %s", certPath))
			} else {
				log.Debug("TLS cert file exists", zap.String("path", certPath))
			}
		}

		if keyPath != "" {
			if info, err := os.Stat(keyPath); err != nil {
				result.Warnings = append(result.Warnings,
					fmt.Sprintf("TLS key file may not exist: %s", keyPath))
			} else {
				// Check key file permissions (should be 0600)
				if info.Mode().Perm() != 0600 {
					result.Warnings = append(result.Warnings,
						fmt.Sprintf("TLS key file has insecure permissions %o (should be 0600): %s",
							info.Mode().Perm(), keyPath))
				}
				log.Debug("TLS key file exists", zap.String("path", keyPath))
			}
		}
	}
}

// validateStorageBackend performs storage-backend specific validation
func validateStorageBackend(_ *eos_io.RuntimeContext, content string, result *ConfigValidationResult) {
	// Check for file storage backend
	if strings.Contains(content, `storage "file"`) {
		if !strings.Contains(content, "path") {
			result.Errors = append(result.Errors, "file storage backend requires 'path' attribute")
		}

		// Extract path and check it exists
		path := extractConfigValue(content, "path")
		if path != "" {
			if info, err := os.Stat(path); err != nil {
				result.Warnings = append(result.Warnings,
					fmt.Sprintf("Storage path does not exist (will be created on start): %s", path))
			} else if !info.IsDir() {
				result.Errors = append(result.Errors,
					fmt.Sprintf("Storage path exists but is not a directory: %s", path))
			}
		}
	}

	// Check for Consul storage backend
	if strings.Contains(content, `storage "consul"`) {
		if !strings.Contains(content, "address") {
			result.Warnings = append(result.Warnings,
				"consul storage backend should specify 'address' (defaults to localhost:8500)")
		}

		result.Suggestions = append(result.Suggestions,
			"Ensure Consul agent is running before starting Vault")
	}

	// Check for integrated storage (Raft)
	if strings.Contains(content, `storage "raft"`) {
		requiredRaftAttrs := []string{"path", "node_id"}
		for _, attr := range requiredRaftAttrs {
			if !strings.Contains(content, attr) {
				result.Errors = append(result.Errors,
					fmt.Sprintf("raft storage backend requires '%s' attribute", attr))
			}
		}

		result.Suggestions = append(result.Suggestions,
			"Raft storage requires cluster_addr for HA - ensure it's configured")
	}
}

// extractConfigValue extracts a simple key = "value" from HCL content
// This is a basic implementation - doesn't handle all HCL cases
func extractConfigValue(content, key string) string {
	// Look for: key = "value" or key="value"
	searchPatterns := []string{
		fmt.Sprintf(`%s = "`, key),
		fmt.Sprintf(`%s="`, key),
	}

	for _, pattern := range searchPatterns {
		idx := strings.Index(content, pattern)
		if idx == -1 {
			continue
		}

		// Find the closing quote
		start := idx + len(pattern)
		end := strings.Index(content[start:], `"`)
		if end == -1 {
			continue
		}

		return content[start : start+end]
	}

	return ""
}

// ValidateConfigBeforeStart is a convenience function for pre-flight validation
// Called before starting Vault service to catch config errors early
func ValidateConfigBeforeStart(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info(" Pre-flight configuration validation")

	result, err := ValidateConfigWithFallback(rc, shared.VaultConfigPath)
	if err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	// Log all warnings and suggestions
	for _, warning := range result.Warnings {
		log.Warn("Configuration warning", zap.String("warning", warning))
	}
	for _, suggestion := range result.Suggestions {
		log.Info("💡 Suggestion", zap.String("suggestion", suggestion))
	}

	// Fail if there are errors
	if !result.Valid {
		log.Error(" Configuration validation failed",
			zap.Strings("errors", result.Errors))
		return fmt.Errorf("configuration invalid: %s", strings.Join(result.Errors, "; "))
	}

	log.Info(" Pre-flight validation passed", zap.String("method", result.Method))
	return nil
}
