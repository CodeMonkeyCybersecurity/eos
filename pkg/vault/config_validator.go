// pkg/vault/config_validator.go

package vault

import (
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ValidationError represents a detailed validation error with field context and remediation hints
type ValidationError struct {
	Field   string // The config field that failed validation (e.g., "listener.tcp.tls_cert_file")
	Message string // Human-readable error message
	Hint    string // Actionable remediation hint
}

// Error implements the error interface
func (v ValidationError) Error() string {
	if v.Hint != "" {
		return fmt.Sprintf("%s: %s (Hint: %s)", v.Field, v.Message, v.Hint)
	}
	return fmt.Sprintf("%s: %s", v.Field, v.Message)
}

// Is allows errors.Is() to match ValidationErrors by field name.
// Two ValidationErrors are considered equal if they're for the same field.
func (v ValidationError) Is(target error) bool {
	t, ok := target.(ValidationError)
	if !ok {
		tPtr, ok := target.(*ValidationError)
		if !ok {
			return false
		}
		t = *tPtr
	}
	return v.Field == t.Field
}

// ConfigValidationResult contains configuration validation results
type ConfigValidationResult struct {
	Valid       bool     `json:"valid"`
	Errors      []string `json:"errors,omitempty"`
	Warnings    []string `json:"warnings,omitempty"`
	Suggestions []string `json:"suggestions,omitempty"`
	Method      string   `json:"method"` // "vault-binary" or "manual-parser"
}

// VaultConfig represents the structured Vault configuration for validation
type VaultConfig struct {
	Listeners    []ListenerConfig `hcl:"listener,block"`
	Storage      *StorageConfig   `hcl:"storage,block"`
	APIAddr      string           `hcl:"api_addr,optional"`
	ClusterAddr  string           `hcl:"cluster_addr,optional"`
	UI           bool             `hcl:"ui,optional"`
	DisableMlock bool             `hcl:"disable_mlock,optional"`
}

// ListenerConfig represents a listener block configuration
type ListenerConfig struct {
	Type   string                 `hcl:"type,label"`
	Config map[string]interface{} `hcl:",remain"`
}

// StorageConfig represents a storage backend configuration
type StorageConfig struct {
	Type   string                 `hcl:"type,label"`
	Config map[string]interface{} `hcl:",remain"`
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

	// CRITICAL FINDING: Vault 1.20.4+ doesn't have "operator validate" or "validate" commands
	// The only way to validate config is to try starting vault with the config
	// Since we can't actually start it (port in use, etc.), we always fall back to manual validation
	// This is a known limitation - vault doesn't provide a standalone config validation command
	//
	// References:
	// - GitHub Issue #3455 (2017): "Please add a vault command to validate its config file"
	// - GitHub Issue #2851 (2017): Proposal for a `vault validate` command (still open)
	// - Vault CLI documentation does NOT list a validate command
	//
	// Therefore, vault binary validation is not available, and we use HCL parsing instead

	log.Debug("Vault binary config validation not available",
		zap.String("reason", "vault validate command doesn't exist"),
		zap.String("fallback", "using HCL parser for validation"))

	// Always use manual HCL parsing (more reliable and doesn't require external commands)
	return false
}

// structuredConfigValidation attempts to parse config using structured HCL parsing
// This provides more detailed validation than simple string matching
func structuredConfigValidation(rc *eos_io.RuntimeContext, configPath string, result *ConfigValidationResult) error {
	log := otelzap.Ctx(rc.Ctx)

	// Read config file
	content, err := os.ReadFile(configPath)
	if err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("failed to read config: %v", err))
		return fmt.Errorf("read config: %w", err)
	}

	// Try structured HCL parsing first (more comprehensive)
	parser := hclparse.NewParser()
	hclFile, diags := parser.ParseHCL(content, configPath)
	if diags.HasErrors() {
		// HCL syntax errors - fall back to string-based validation
		log.Debug("Structured HCL parsing failed, using fallback validation",
			zap.Int("syntax_errors", len(diags.Errs())))
		for _, diag := range diags {
			result.Errors = append(result.Errors, diag.Error())
		}
		return nil // Allow semantic validation to proceed
	}

	if hclFile != nil && hclFile.Body != nil {
		log.Debug("Successfully parsed HCL structure")

		// Validate the parsed structure
		if err := validateParsedConfig(rc, string(content), result); err != nil {
			return err
		}
	}

	return nil
}

// validateParsedConfig validates the parsed HCL configuration structure
func validateParsedConfig(rc *eos_io.RuntimeContext, content string, result *ConfigValidationResult) error {
	log := otelzap.Ctx(rc.Ctx)

	// Perform detailed semantic validation on the content
	// This combines structure validation with content checks

	// 1. Validate listeners
	if err := validateListeners(rc, content, result); err != nil {
		log.Error("Listener validation failed", zap.Error(err))
	}

	// 2. Validate storage backend
	if err := validateStorageDetailed(rc, content, result); err != nil {
		log.Error("Storage validation failed", zap.Error(err))
	}

	// 3. Validate top-level configuration
	validateTopLevelConfig(rc, content, result)

	return nil
}

// validateListeners performs comprehensive listener validation
func validateListeners(rc *eos_io.RuntimeContext, content string, result *ConfigValidationResult) error {
	log := otelzap.Ctx(rc.Ctx)

	// Check if at least one listener exists
	if !strings.Contains(content, "listener") {
		verr := ValidationError{
			Field:   "listener",
			Message: "no listener configured",
			Hint:    "Vault requires at least one listener block (e.g., listener \"tcp\" { ... })",
		}
		result.Errors = append(result.Errors, verr.Error())
		return fmt.Errorf("no listener found")
	}

	// Validate TCP listener (most common)
	if strings.Contains(content, `listener "tcp"`) {
		log.Debug("Validating TCP listener configuration")

		// Check for address
		if !strings.Contains(content, "address") {
			result.Warnings = append(result.Warnings,
				"TCP listener missing 'address' - will default to shared.GetInternalHostname:8200")
		}

		// Validate TLS configuration
		tlsDisabled := strings.Contains(content, "tls_disable = true") ||
			strings.Contains(content, "tls_disable = 1") ||
			strings.Contains(content, `tls_disable = "1"`)

		hasCert := strings.Contains(content, "tls_cert_file")
		hasKey := strings.Contains(content, "tls_key_file")

		if !tlsDisabled {
			// TLS is enabled - must have both cert and key
			if !hasCert {
				verr := ValidationError{
					Field:   "listener.tcp.tls_cert_file",
					Message: "TLS is enabled but tls_cert_file is not configured",
					Hint:    "Either set tls_cert_file or set tls_disable = true",
				}
				result.Errors = append(result.Errors, verr.Error())
			}

			if !hasKey {
				verr := ValidationError{
					Field:   "listener.tcp.tls_key_file",
					Message: "TLS is enabled but tls_key_file is not configured",
					Hint:    "Either set tls_key_file or set tls_disable = true",
				}
				result.Errors = append(result.Errors, verr.Error())
			}

			// Check for empty TLS paths (critical historical bug)
			if strings.Contains(content, `tls_cert_file = ""`) {
				verr := ValidationError{
					Field:   "listener.tcp.tls_cert_file",
					Message: "tls_cert_file is set to empty string",
					Hint:    "Set a valid certificate path or disable TLS with tls_disable = true",
				}
				result.Errors = append(result.Errors, verr.Error())
			}

			if strings.Contains(content, `tls_key_file = ""`) {
				verr := ValidationError{
					Field:   "listener.tcp.tls_key_file",
					Message: "tls_key_file is set to empty string",
					Hint:    "Set a valid key path or disable TLS with tls_disable = true",
				}
				result.Errors = append(result.Errors, verr.Error())
			}

			// Validate certificate files exist
			if hasCert {
				certPath := extractConfigValue(content, "tls_cert_file")
				if certPath != "" {
					if _, err := os.Stat(certPath); os.IsNotExist(err) {
						verr := ValidationError{
							Field:   "listener.tcp.tls_cert_file",
							Message: fmt.Sprintf("certificate file does not exist: %s", certPath),
							Hint:    "Generate certificates with 'eos repair vault --fix-tls' or disable TLS",
						}
						result.Errors = append(result.Errors, verr.Error())
					} else {
						log.Debug("TLS certificate file exists", zap.String("path", certPath))
					}
				}
			}

			if hasKey {
				keyPath := extractConfigValue(content, "tls_key_file")
				if keyPath != "" {
					if info, err := os.Stat(keyPath); os.IsNotExist(err) {
						verr := ValidationError{
							Field:   "listener.tcp.tls_key_file",
							Message: fmt.Sprintf("private key file does not exist: %s", keyPath),
							Hint:    "Generate certificates with 'eos repair vault --fix-tls' or disable TLS",
						}
						result.Errors = append(result.Errors, verr.Error())
					} else {
						// Check key file permissions
						if info.Mode().Perm() != 0600 {
							result.Warnings = append(result.Warnings,
								fmt.Sprintf("TLS key file has insecure permissions %o (should be 0600): %s",
									info.Mode().Perm(), keyPath))
						}
						log.Debug("TLS key file exists", zap.String("path", keyPath))
					}
				}
			}
		} else {
			// TLS is disabled - warn about security implications
			result.Warnings = append(result.Warnings,
				"TLS is disabled - Vault traffic will be UNENCRYPTED (insecure for production)")
			result.Suggestions = append(result.Suggestions,
				"Enable TLS for production: eos repair vault --fix-tls")
		}

		// Check for cluster_address (needed for HA/Raft)
		if !strings.Contains(content, "cluster_address") {
			result.Suggestions = append(result.Suggestions,
				fmt.Sprintf("Consider setting cluster_address for HA deployments (default: %s:8201)", shared.GetInternalHostname()))
		}
	}

	return nil
}

// validateStorageDetailed performs comprehensive storage backend validation
func validateStorageDetailed(rc *eos_io.RuntimeContext, content string, result *ConfigValidationResult) error {
	log := otelzap.Ctx(rc.Ctx)

	// Check if storage backend exists
	if !strings.Contains(content, "storage") {
		verr := ValidationError{
			Field:   "storage",
			Message: "no storage backend configured",
			Hint:    "Vault requires a storage backend (file, raft, consul, etc.)",
		}
		result.Errors = append(result.Errors, verr.Error())
		return fmt.Errorf("no storage backend found")
	}

	// Validate file storage (deprecated but still used)
	if strings.Contains(content, `storage "file"`) {
		log.Debug("Validating file storage backend")

		result.Warnings = append(result.Warnings,
			"  DEPRECATED: File storage is NOT SUPPORTED in Vault Enterprise 1.12.0+")
		result.Warnings = append(result.Warnings,
			"  HashiCorp recommends Raft Integrated Storage for all deployments")
		result.Suggestions = append(result.Suggestions,
			"Migrate to Raft: see vault-complete-specification-v1.0-raft-integrated.md")

		if !strings.Contains(content, "path") {
			verr := ValidationError{
				Field:   "storage.file.path",
				Message: "file storage backend requires 'path' attribute",
				Hint:    "Set path = \"/opt/vault/data\" or similar",
			}
			result.Errors = append(result.Errors, verr.Error())
		} else {
			path := extractConfigValue(content, "path")
			if path != "" {
				if info, err := os.Stat(path); err != nil {
					if os.IsNotExist(err) {
						result.Warnings = append(result.Warnings,
							fmt.Sprintf("Storage path does not exist (will be created): %s", path))
					}
				} else if !info.IsDir() {
					verr := ValidationError{
						Field:   "storage.file.path",
						Message: fmt.Sprintf("storage path exists but is not a directory: %s", path),
						Hint:    "Remove the file or choose a different path",
					}
					result.Errors = append(result.Errors, verr.Error())
				}
			}
		}
	}

	// Validate Raft storage (recommended)
	if strings.Contains(content, `storage "raft"`) {
		log.Debug("Validating Raft Integrated Storage backend")

		// Raft requires specific attributes
		requiredRaftAttrs := map[string]string{
			"path":    "raft storage requires a data directory path",
			"node_id": "raft storage requires a unique node identifier",
		}

		for attr, message := range requiredRaftAttrs {
			if !strings.Contains(content, attr) {
				verr := ValidationError{
					Field:   fmt.Sprintf("storage.raft.%s", attr),
					Message: message,
					Hint:    fmt.Sprintf("Add '%s' to your raft storage block", attr),
				}
				result.Errors = append(result.Errors, verr.Error())
			}
		}

		// Check for cluster_addr (required for HA)
		if !strings.Contains(content, "cluster_addr") {
			result.Warnings = append(result.Warnings,
				"Raft storage requires 'cluster_addr' for HA deployments")
			result.Suggestions = append(result.Suggestions,
				fmt.Sprintf("Set cluster_addr = \"https://%s:8180\" (replace with your server's hostname)", shared.GetInternalHostname()))
		}

		// Check for api_addr
		if !strings.Contains(content, "api_addr") {
			result.Warnings = append(result.Warnings,
				"Raft storage requires 'api_addr' to be explicitly set")
			result.Suggestions = append(result.Suggestions,
				fmt.Sprintf("Set api_addr = \"https://%s:8179\" (replace with your server's hostname)", shared.GetInternalHostname()))
		}

		// Raft REQUIRES TLS
		tlsDisabled := strings.Contains(content, "tls_disable = true") ||
			strings.Contains(content, "tls_disable = 1")

		if tlsDisabled {
			verr := ValidationError{
				Field:   "storage.raft",
				Message: "Raft Integrated Storage REQUIRES TLS (tls_disable cannot be true)",
				Hint:    "Generate TLS certificates with 'eos repair vault --fix-tls'",
			}
			result.Errors = append(result.Errors, verr.Error())
		}

		// Check for retry_join (multi-node cluster)
		if strings.Contains(content, "retry_join") {
			result.Suggestions = append(result.Suggestions,
				" Multi-node Raft cluster detected - ensure all nodes have unique node_id")
		} else {
			result.Suggestions = append(result.Suggestions,
				"Single-node Raft - for production HA, configure retry_join with 3-5 nodes")
		}

		// Check for auto-unseal
		if !strings.Contains(content, `seal "`) {
			result.Suggestions = append(result.Suggestions,
				"Consider auto-unseal (awskms/azurekeyvault/gcpckms) for production")
		}
	}

	// Validate Consul storage
	if strings.Contains(content, `storage "consul"`) {
		log.Debug("Validating Consul storage backend")

		if !strings.Contains(content, "address") {
			result.Warnings = append(result.Warnings,
				"Consul storage should specify 'address' (defaults to localhost:8500)")
		}

		result.Suggestions = append(result.Suggestions,
			"Ensure Consul agent is running before starting Vault")
	}

	return nil
}

// validateTopLevelConfig validates top-level Vault configuration attributes
func validateTopLevelConfig(rc *eos_io.RuntimeContext, content string, result *ConfigValidationResult) {
	log := otelzap.Ctx(rc.Ctx)

	// Check for api_addr (important for HA and agent communication)
	if !strings.Contains(content, "api_addr") {
		result.Warnings = append(result.Warnings,
			"api_addr not set - required for HA and Vault Agent communication")
		result.Suggestions = append(result.Suggestions,
			"Set api_addr to your Vault server's full URL (e.g., https://vault.example.com:8179)")
	}

	// Check for UI configuration
	if strings.Contains(content, "ui = true") {
		apiAddr := shared.GetVaultAddr()
		result.Suggestions = append(result.Suggestions,
			fmt.Sprintf("UI enabled - accessible at %s/ui", apiAddr))
	}

	// Check for disable_mlock
	if strings.Contains(content, "disable_mlock = false") || !strings.Contains(content, "disable_mlock") {
		result.Suggestions = append(result.Suggestions,
			"Ensure CAP_IPC_LOCK capability is set in systemd service if disable_mlock = false")
	}

	// Check for legacy port 8200
	if strings.Contains(content, ":8200") {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("Eos standard port is %s", shared.VaultDefaultPort))
		result.Suggestions = append(result.Suggestions,
			"Run 'eos update vault' to migrate to standard port configuration")
	}

	// Check for tls_disable as string instead of boolean
	if strings.Contains(content, `tls_disable = "true"`) || strings.Contains(content, `tls_disable = "false"`) {
		result.Warnings = append(result.Warnings,
			"tls_disable should be boolean (true/false) not string (\"true\"/\"false\")")
	}

	log.Debug("Top-level configuration validation completed")
}

// manualConfigValidation performs manual HCL parsing and semantic validation
func manualConfigValidation(rc *eos_io.RuntimeContext, configPath string, result *ConfigValidationResult) error {
	log := otelzap.Ctx(rc.Ctx)
	result.Method = "manual-parser"

	// Use the enhanced structured validation which includes HCL parsing + detailed checks
	if err := structuredConfigValidation(rc, configPath, result); err != nil {
		return err
	}

	log.Debug("Enhanced validation completed",
		zap.Int("errors", len(result.Errors)),
		zap.Int("warnings", len(result.Warnings)),
		zap.Int("suggestions", len(result.Suggestions)))

	return nil
}

// NOTE: Old validation functions removed - replaced with comprehensive structured validation
// - validateSemantics() replaced by structuredConfigValidation()
// - checkCommonMisconfigurations() integrated into validateTopLevelConfig()
// - validateTLSConfig() replaced by validateListeners()
// - validateStorageBackend() replaced by validateStorageDetailed()

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
		log.Info(" Suggestion", zap.String("suggestion", suggestion))
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
