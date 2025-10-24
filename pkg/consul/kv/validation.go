// pkg/consul/kv/validation.go
//
// Consul KV Validation - Prevent Secrets Storage
//
// This module provides validation to prevent accidental storage of secrets
// in Consul KV. Secrets belong in Vault, not Consul KV.
//
// Design Principles:
// - Detect secret-like keys (password, token, key, secret, etc.)
// - Detect secret-like values (high entropy, base64, hex patterns)
// - Provide clear error messages with remediation
// - Fail fast - prevent secrets at write time
//
// Security Rationale:
// - Consul KV is for configuration, not secrets
// - Secrets need rotation, audit trails, encryption at rest (Vault provides)
// - Consul KV has different access controls than Vault
// - Separation of concerns: config vs secrets

package kv

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
)

// Secret-like key patterns (case-insensitive)
var secretKeyPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)password`),
	regexp.MustCompile(`(?i)passwd`),
	regexp.MustCompile(`(?i)secret`),
	regexp.MustCompile(`(?i)token`),
	regexp.MustCompile(`(?i)api[_-]?key`),
	regexp.MustCompile(`(?i)private[_-]?key`),
	regexp.MustCompile(`(?i)priv[_-]?key`),
	regexp.MustCompile(`(?i)jwt[_-]?secret`),
	regexp.MustCompile(`(?i)encryption[_-]?key`),
	regexp.MustCompile(`(?i)master[_-]?key`),
	regexp.MustCompile(`(?i)client[_-]?secret`),
	regexp.MustCompile(`(?i)access[_-]?token`),
	regexp.MustCompile(`(?i)refresh[_-]?token`),
	regexp.MustCompile(`(?i)bearer[_-]?token`),
	regexp.MustCompile(`(?i)session[_-]?key`),
	regexp.MustCompile(`(?i)auth[_-]?key`),
	regexp.MustCompile(`(?i)credential`),
	regexp.MustCompile(`(?i)cert[_-]?key`),
	regexp.MustCompile(`(?i)tls[_-]?key`),
	regexp.MustCompile(`(?i)ssl[_-]?key`),
}

// Allowed key exceptions (these are OK even if they match patterns)
var allowedKeyExceptions = []string{
	"log_level",            // Common config key
	"token_ttl",            // TTL configuration, not the token itself
	"password_policy",      // Policy definition, not password
	"secret_backend",       // Backend name, not secret
	"api_key_rotation",     // Rotation policy, not key
	"token_renewal_period", // Renewal config, not token
	"password_min_length",  // Password policy, not password
	"key_rotation_period",  // Rotation period, not key
}

// ValidateKeyNotSecret checks if a key path looks like it might store a secret
//
// Returns error if key appears to be secret-related.
// Use this before writing to Consul KV to prevent accidental secret storage.
//
// Example:
//
//	if err := kv.ValidateKeyNotSecret("config/myservice/database_password"); err != nil {
//	    // ERROR: Key looks like a secret
//	    // Store in Vault instead: vault kv put secret/myservice/database_password value=...
//	}
func ValidateKeyNotSecret(key string) error {
	// Extract the final path component for validation
	parts := strings.Split(key, "/")
	if len(parts) == 0 {
		return nil
	}
	finalKey := strings.ToLower(parts[len(parts)-1])

	// Check if it's an allowed exception first
	for _, exception := range allowedKeyExceptions {
		if strings.Contains(finalKey, exception) {
			return nil
		}
	}

	// Check against secret patterns
	for _, pattern := range secretKeyPatterns {
		if pattern.MatchString(finalKey) {
			return fmt.Errorf(
				"key '%s' looks like a secret (matched pattern: %s)\n"+
					"SECURITY: Secrets must be stored in Vault, not Consul KV\n"+
					"Fix: Use 'vault kv put secret/%s value=...' instead\n"+
					"Consul KV is for non-sensitive configuration only",
				key, pattern.String(), extractServiceFromPath(key))
		}
	}

	return nil
}

// ValidateValueNotSecret checks if a value looks like secret data
//
// Detects:
// - High entropy strings (likely random tokens/passwords)
// - Base64-encoded data (often used for secrets)
// - Long hexadecimal strings (API keys, tokens)
// - JWT tokens
// - Common secret prefixes (sk_, pk_, ghp_, etc.)
//
// Example:
//
//	if err := kv.ValidateValueNotSecret("config/service/endpoint", "https://api.example.com"); err != nil {
//	    // ERROR: Value looks like a secret
//	}
func ValidateValueNotSecret(key string, value string) error {
	// Skip validation for empty values
	if value == "" {
		return nil
	}

	// Skip validation for obviously safe values
	if isSafeValue(value) {
		return nil
	}

	// Check for common secret prefixes
	if hasSecretPrefix(value) {
		return fmt.Errorf(
			"value for key '%s' has a secret-like prefix\n"+
				"SECURITY: Detected common secret prefix pattern\n"+
				"Fix: Store in Vault instead: vault kv put secret/%s",
			key, extractServiceFromPath(key))
	}

	// Check for JWT tokens
	if isJWT(value) {
		return fmt.Errorf(
			"value for key '%s' looks like a JWT token\n"+
				"SECURITY: JWT tokens are secrets and must be stored in Vault\n"+
				"Fix: Store in Vault instead: vault kv put secret/%s",
			key, extractServiceFromPath(key))
	}

	// Check for base64-encoded data (potential secret)
	if isBase64Secret(value) {
		return fmt.Errorf(
			"value for key '%s' looks like base64-encoded secret data\n"+
				"SECURITY: Base64-encoded secrets must be stored in Vault\n"+
				"Fix: Store in Vault instead: vault kv put secret/%s",
			key, extractServiceFromPath(key))
	}

	// Check for long hex strings (API keys, tokens)
	if isHexSecret(value) {
		return fmt.Errorf(
			"value for key '%s' looks like a hexadecimal secret (API key/token)\n"+
				"SECURITY: API keys and tokens must be stored in Vault\n"+
				"Fix: Store in Vault instead: vault kv put secret/%s",
			key, extractServiceFromPath(key))
	}

	// Check entropy (high randomness = likely secret)
	if hasHighEntropy(value) {
		return fmt.Errorf(
			"value for key '%s' has high entropy (likely a random secret)\n"+
				"SECURITY: Random secrets must be stored in Vault\n"+
				"Fix: Store in Vault instead: vault kv put secret/%s\n"+
				"Note: If this is legitimate config, file an issue to add exception",
			key, extractServiceFromPath(key))
	}

	return nil
}

// isSafeValue checks if a value is obviously safe (not a secret)
func isSafeValue(value string) bool {
	// Short values are usually safe
	if len(value) < 8 {
		return true
	}

	// Common safe patterns
	safePatterns := []string{
		"true", "false", // Booleans
		"enabled", "disabled", // Feature flags
		"http://", "https://", // URLs (endpoints are OK in Consul KV)
		"info", "debug", "warn", "error", // Log levels
		"/", // Paths
		"localhost", "127.0.0.1", // Local addresses
	}

	valueLower := strings.ToLower(value)
	for _, pattern := range safePatterns {
		if strings.Contains(valueLower, pattern) {
			return true
		}
	}

	// Numeric values are safe
	if isNumeric(value) {
		return true
	}

	// Simple duration strings are safe (1h, 30s, etc.)
	if isDuration(value) {
		return true
	}

	return false
}

// hasSecretPrefix checks for common secret prefixes
func hasSecretPrefix(value string) bool {
	secretPrefixes := []string{
		"sk_",       // Stripe secret keys
		"pk_",       // Stripe publishable keys (still sensitive)
		"ghp_",      // GitHub personal access tokens
		"gho_",      // GitHub OAuth tokens
		"ghs_",      // GitHub server-to-server tokens
		"github_pat_", // GitHub fine-grained PATs
		"glpat-",    // GitLab personal access tokens
		"xoxb-",     // Slack bot tokens
		"xoxp-",     // Slack user tokens
		"SG.",       // SendGrid API keys
		"key-",      // Generic API key prefix
		"Bearer ",   // Bearer tokens
		"Basic ",    // Basic auth
		"AKIA",      // AWS access key ID
		"ASIA",      // AWS temporary access key ID
	}

	for _, prefix := range secretPrefixes {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}

	return false
}

// isJWT checks if value looks like a JWT token
func isJWT(value string) bool {
	// JWT format: header.payload.signature (3 base64 parts separated by dots)
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return false
	}

	// Each part should be base64url-encoded (alphanumeric + - _)
	jwtPartPattern := regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	for _, part := range parts {
		if !jwtPartPattern.MatchString(part) {
			return false
		}
		// JWT parts are typically >10 chars
		if len(part) < 10 {
			return false
		}
	}

	return true
}

// isBase64Secret checks if value is base64-encoded and long enough to be a secret
func isBase64Secret(value string) bool {
	// Must be long enough to be interesting
	if len(value) < 16 {
		return false
	}

	// Must be valid base64
	_, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		_, err = base64.URLEncoding.DecodeString(value)
		if err != nil {
			return false
		}
	}

	// Base64 strings with high entropy are likely secrets
	// (vs base64-encoded config which tends to be readable text)
	return hasHighEntropy(value)
}

// isHexSecret checks if value is a long hexadecimal string (API keys, tokens)
func isHexSecret(value string) bool {
	// Must be long enough (32+ chars = 16+ bytes)
	if len(value) < 32 {
		return false
	}

	// Must be all hex characters
	hexPattern := regexp.MustCompile(`^[0-9a-fA-F]+$`)
	return hexPattern.MatchString(value)
}

// hasHighEntropy calculates Shannon entropy to detect random secrets
func hasHighEntropy(value string) bool {
	// Must be long enough to calculate meaningful entropy
	if len(value) < 20 {
		return false
	}

	// Calculate Shannon entropy
	entropy := calculateEntropy(value)

	// Threshold for high entropy (typical secrets are >4.5 bits/char)
	// English text is ~4.0-4.2, random base64 is ~6.0
	const entropyThreshold = 4.8

	return entropy > entropyThreshold
}

// calculateEntropy computes Shannon entropy (bits per character)
func calculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	// Count character frequencies
	freq := make(map[rune]int)
	for _, c := range s {
		freq[c]++
	}

	// Calculate entropy: H = -Σ(p * log2(p))
	var entropy float64
	length := float64(len(s))
	for _, count := range freq {
		p := float64(count) / length
		if p > 0 {
			entropy -= p * log2(p)
		}
	}

	return entropy
}

// log2 computes log base 2
func log2(x float64) float64 {
	if x <= 0 {
		return 0
	}
	// log2(x) = ln(x) / ln(2)
	return 0.693147180559945309417232121458 // ln(2)
}

// isNumeric checks if string is numeric (port numbers, counts, etc.)
func isNumeric(value string) bool {
	numericPattern := regexp.MustCompile(`^-?\d+(\.\d+)?$`)
	return numericPattern.MatchString(value)
}

// isDuration checks if string is a duration (1h, 30s, etc.)
func isDuration(value string) bool {
	durationPattern := regexp.MustCompile(`^\d+(\.\d+)?(ns|us|µs|ms|s|m|h)$`)
	return durationPattern.MatchString(value)
}

// extractServiceFromPath extracts service name from Consul KV path
//
// Example:
//
//	config/bionicgpt/feature_flags/enable_rag → bionicgpt
//	config/eos/log-level → eos
func extractServiceFromPath(path string) string {
	parts := strings.Split(path, "/")

	// config/[service]/...
	if len(parts) >= 2 && parts[0] == "config" {
		return parts[1]
	}

	// Fallback: return first component
	if len(parts) > 0 {
		return parts[0]
	}

	return "service"
}

// ValidateConfig validates a complete configuration map before storage
//
// Checks all keys and values for secret-like patterns.
//
// Example:
//
//	config := map[string]string{
//	    "port":     "8080",
//	    "endpoint": "https://api.example.com",
//	    "password": "secret123", // ERROR - will be caught
//	}
//	if err := kv.ValidateConfig("myservice", config); err != nil {
//	    return err
//	}
func ValidateConfig(service string, config map[string]string) error {
	for key, value := range config {
		fullKey := ConfigPath(service, "", key)

		if err := ValidateKeyNotSecret(fullKey); err != nil {
			return err
		}

		if err := ValidateValueNotSecret(fullKey, value); err != nil {
			return err
		}
	}

	return nil
}
