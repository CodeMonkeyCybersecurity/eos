// pkg/shared/dotenv.go
// *Last Updated: 2025-10-28*

package shared

import (
	"bufio"
	"fmt"
	"os"
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
