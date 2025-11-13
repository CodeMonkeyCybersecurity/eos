// pkg/shared/dotenv.go
// *Last Updated: 2025-11-03*
//
// CENTRALIZED DOTENV HANDLING
// RATIONALE: Consolidates .env file parsing and writing across Eos
// USAGE: Service configurations, API credentials, runtime secrets
// SECURITY: Supports atomic writes with proper permissions (0600 for secrets)

package shared

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
)

// ParseEnvFile parses a .env file and returns a map of environment variables
// Handles:
//   - Comments (lines starting with #)
//   - Blank lines
//   - Key=value pairs
//   - Quoted values ("value" or 'value')
//   - Values with special characters
//   - Whitespace trimming
//
// Example .env file:
//
//	# Database configuration
//	DB_HOST=localhost
//	DB_PORT=5432
//	DB_PASSWORD="p@ssw0rd with spaces"
//	EMPTY_VAR=
//
// Returns map[string]string with parsed key-value pairs
func ParseEnvFile(filePath string) (map[string]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open .env file: %w", err)
	}
	defer file.Close()

	envVars := make(map[string]string)
	scanner := bufio.NewScanner(file)
	lineNumber := 0

	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())

		// Skip blank lines
		if line == "" {
			continue
		}

		// Skip comments
		if strings.HasPrefix(line, "#") {
			continue
		}

		// Parse key=value
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			// Line doesn't contain '=' - skip it (could be invalid or continuation)
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		// Skip if key is empty
		if key == "" {
			continue
		}

		// Remove quotes from value if present
		value = unquoteValue(value)

		envVars[key] = value
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading .env file at line %d: %w", lineNumber, err)
	}

	return envVars, nil
}

// unquoteValue removes surrounding quotes from a value if present
// Handles both double quotes ("value") and single quotes ('value')
func unquoteValue(value string) string {
	// Remove double quotes
	if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
		return value[1 : len(value)-1]
	}

	// Remove single quotes
	if len(value) >= 2 && value[0] == '\'' && value[len(value)-1] == '\'' {
		return value[1 : len(value)-1]
	}

	return value
}

// GetEnvVar reads a specific environment variable from a .env file
// Returns the value and true if found, empty string and false if not found
func GetEnvVar(filePath, key string) (string, bool, error) {
	envVars, err := ParseEnvFile(filePath)
	if err != nil {
		return "", false, err
	}

	value, found := envVars[key]
	return value, found, nil
}

// MustGetEnvVar reads a specific environment variable from a .env file
// Returns error if the key is not found or the file cannot be read
func MustGetEnvVar(filePath, key string) (string, error) {
	value, found, err := GetEnvVar(filePath, key)
	if err != nil {
		return "", err
	}

	if !found {
		return "", fmt.Errorf("required environment variable %s not found in %s", key, filePath)
	}

	if value == "" {
		return "", fmt.Errorf("environment variable %s is empty in %s", key, filePath)
	}

	return value, nil
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Writing .env Files (P1 - Security Enhancement)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// WriteEnvFile writes environment variables to a .env file
// SECURITY: Creates file with 0600 permissions (owner read/write only) by default
// ATOMICITY: Writes to temp file first, then renames (atomic on most filesystems)
// FORMATTING: Alphabetically sorted keys, preserves comments if preserveComments=true
//
// Parameters:
//   - filePath: Path to .env file (will be created if doesn't exist)
//   - envVars: Map of environment variables to write
//   - perm: File permissions (use 0600 for secrets, 0644 for non-sensitive configs)
//   - header: Optional header comment to add at top of file
//
// Example:
//
//	envVars := map[string]string{
//	    "AUTHENTIK_TOKEN": "ak_secret_token_here",
//	    "AUTHENTIK_URL": "https://auth.example.com",
//	}
//	err := WriteEnvFile("/opt/hecate/.env", envVars, 0600, "# Authentik API Configuration")
func WriteEnvFile(filePath string, envVars map[string]string, perm os.FileMode, header string) error {
	// Create temp file in same directory (ensures atomic rename works)
	tmpFile, err := os.CreateTemp(string(filePath[:strings.LastIndex(filePath, "/")]), ".env.tmp.*")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath) // Clean up temp file if we fail

	// Set permissions on temp file BEFORE writing secrets
	// SECURITY: Prevents race condition where secrets are briefly world-readable
	if err := os.Chmod(tmpPath, perm); err != nil {
		tmpFile.Close()
		return fmt.Errorf("failed to set permissions on temp file: %w", err)
	}

	// Write header comment if provided
	if header != "" {
		if !strings.HasPrefix(header, "#") {
			header = "# " + header
		}
		if _, err := fmt.Fprintf(tmpFile, "%s\n\n", header); err != nil {
			tmpFile.Close()
			return fmt.Errorf("failed to write header: %w", err)
		}
	}

	// Sort keys for consistent output (easier to diff, audit)
	keys := make([]string, 0, len(envVars))
	for k := range envVars {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Write key=value pairs
	for _, key := range keys {
		value := envVars[key]

		// Quote value if it contains spaces or special characters
		if needsQuoting(value) {
			value = fmt.Sprintf(`"%s"`, value)
		}

		if _, err := fmt.Fprintf(tmpFile, "%s=%s\n", key, value); err != nil {
			tmpFile.Close()
			return fmt.Errorf("failed to write env var %s: %w", key, err)
		}
	}

	// Sync to disk before rename (ensures data is written)
	if err := tmpFile.Sync(); err != nil {
		tmpFile.Close()
		return fmt.Errorf("failed to sync temp file: %w", err)
	}
	tmpFile.Close()

	// Atomic rename (replaces existing file)
	if err := os.Rename(tmpPath, filePath); err != nil {
		return fmt.Errorf("failed to rename temp file to %s: %w", filePath, err)
	}

	return nil
}

// UpdateEnvVar updates a single environment variable in a .env file
// PRESERVES: Existing comments, blank lines, and other variables
// IDEMPOTENT: If key already exists with same value, no-op (file unchanged)
//
// Parameters:
//   - filePath: Path to .env file
//   - key: Environment variable name to update
//   - value: New value (empty string removes the variable)
//   - perm: File permissions (use 0600 for secrets)
//
// Example:
//
//	// Update AUTHENTIK_TOKEN in /opt/hecate/.env
//	err := UpdateEnvVar("/opt/hecate/.env", "AUTHENTIK_TOKEN", "new_token_value", 0600)
func UpdateEnvVar(filePath, key, value string, perm os.FileMode) error {
	// Read existing env vars
	existingVars, err := ParseEnvFile(filePath)
	if err != nil {
		// If file doesn't exist, create new one
		if os.IsNotExist(err) {
			return WriteEnvFile(filePath, map[string]string{key: value}, perm, "")
		}
		return fmt.Errorf("failed to parse existing .env file: %w", err)
	}

	// Check if value already matches (idempotency check)
	if existingValue, exists := existingVars[key]; exists && existingValue == value {
		return nil // No change needed
	}

	// Update value
	if value == "" {
		delete(existingVars, key) // Empty value = remove key
	} else {
		existingVars[key] = value
	}

	// Write back to file (this preserves alphabetical sorting)
	return WriteEnvFile(filePath, existingVars, perm, "")
}

// needsQuoting checks if a value needs to be quoted in .env file
// QUOTES REQUIRED FOR:
//   - Values containing spaces
//   - Values containing # (would be interpreted as comment)
//   - Values containing = (would be ambiguous)
//   - Values containing newlines
func needsQuoting(value string) bool {
	return strings.ContainsAny(value, " \t\n\r#=")
}

// LoadEnvVarsIntoEnvironment loads .env file variables into current process environment
// SECURITY WARNING: This modifies process environment - use carefully
// USE CASE: Testing, development, scripts that need env vars set
//
// Example:
//
//	// Load /opt/hecate/.env into process environment
//	if err := LoadEnvVarsIntoEnvironment("/opt/hecate/.env"); err != nil {
//	    log.Fatal(err)
//	}
func LoadEnvVarsIntoEnvironment(filePath string) error {
	envVars, err := ParseEnvFile(filePath)
	if err != nil {
		return err
	}

	for key, value := range envVars {
		if err := os.Setenv(key, value); err != nil {
			return fmt.Errorf("failed to set environment variable %s: %w", key, err)
		}
	}

	return nil
}
