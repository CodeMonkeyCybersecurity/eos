package vault

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// SecureFilePermissions defines the secure permissions for token files
const SecureFilePermissions = 0600 // Owner read/write only

// ValidateTokenFilePermissions checks if a token file has secure permissions
func ValidateTokenFilePermissions(rc *eos_io.RuntimeContext, filePath string) error {
	log := otelzap.Ctx(rc.Ctx)

	// Check if file exists
	info, err := os.Stat(filePath)
	if os.IsNotExist(err) {
		// File doesn't exist - this is okay
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to stat token file %s: %w", filePath, err)
	}

	// Check permissions
	perms := info.Mode().Perm()
	if perms != SecureFilePermissions {
		log.Warn(" Token file has insecure permissions",
			zap.String("file", filePath),
			zap.String("current_perms", fmt.Sprintf("%o", perms)),
			zap.String("required_perms", fmt.Sprintf("%o", SecureFilePermissions)),
		)
		return fmt.Errorf("token file %s has insecure permissions %o, should be %o",
			filePath, perms, SecureFilePermissions)
	}

	// Check for setuid/setgid bits (security risk)
	if info.Mode()&os.ModeSetuid != 0 || info.Mode()&os.ModeSetgid != 0 {
		return fmt.Errorf("token file %s has setuid/setgid bits set - security risk", filePath)
	}

	log.Debug(" Token file permissions are secure", zap.String("file", filePath))
	return nil
}

// SecureWriteTokenFile writes a token to a file with secure permissions
func SecureWriteTokenFile(rc *eos_io.RuntimeContext, filePath, token string) error {
	log := otelzap.Ctx(rc.Ctx)

	// Ensure parent directory exists
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create token directory %s: %w", dir, err)
	}

	// Write file with secure permissions
	if err := os.WriteFile(filePath, []byte(token), SecureFilePermissions); err != nil {
		return fmt.Errorf("failed to write token file %s: %w", filePath, err)
	}

	// Double-check permissions were set correctly
	if err := ValidateTokenFilePermissions(rc, filePath); err != nil {
		// If validation fails, remove the file to prevent security risk
		if err := os.Remove(filePath); err != nil {
			log.Warn("Failed to remove insecure token file", zap.String("file", filePath), zap.Error(err))
		}
		return fmt.Errorf("token file written with insecure permissions: %w", err)
	}

	log.Info(" Token file written securely",
		zap.String("file", filePath),
		zap.String("permissions", fmt.Sprintf("%o", SecureFilePermissions)),
	)
	return nil
}

// SecureReadTokenFile reads a token file with permission validation
func SecureReadTokenFile(rc *eos_io.RuntimeContext, filePath string) (string, error) {
	log := otelzap.Ctx(rc.Ctx)

	// Validate permissions before reading
	if err := ValidateTokenFilePermissions(rc, filePath); err != nil {
		log.Warn("🚨 Refusing to read token file with insecure permissions",
			zap.String("file", filePath),
			zap.Error(err),
		)
		return "", fmt.Errorf("token file security validation failed: %w", err)
	}

	// Read the file
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to read token file %s: %w", filePath, err)
	}

	token := trimWhitespace(string(data))

	// Basic token format validation (Vault tokens start with hvs. or s.)
	if token != "" && !isValidVaultTokenFormat(token) {
		log.Warn("🚨 Token file contains invalid format", zap.String("file", filePath))
		return "", fmt.Errorf("token file %s contains invalid token format", filePath)
	}

	log.Debug(" Token file read successfully", zap.String("file", filePath))
	return token, nil
}

// isValidVaultTokenFormat performs basic validation of vault token format
func isValidVaultTokenFormat(token string) bool {
	token = trimWhitespace(token)

	// Vault tokens typically start with hvs. (new format) or s. (legacy)
	// or are UUIDs for older versions
	if len(token) < 8 {
		return false
	}

	// Check for valid characters first (alphanumeric plus allowed punctuation)
	for _, char := range token {
		if (char < 'a' || char > 'z') &&
			(char < 'A' || char > 'Z') &&
			(char < '0' || char > '9') &&
			char != '.' && char != '-' && char != '_' {
			return false
		}
	}

	// New Vault service tokens start with hvs.
	if len(token) > 4 && token[:4] == "hvs." {
		return len(token) >= 8
	}

	// Legacy service tokens start with s.
	if len(token) > 2 && token[:2] == "s." {
		return len(token) >= 8
	}

	// UUID format (legacy) - 36 characters with hyphens
	if len(token) == 36 && token[8] == '-' && token[13] == '-' && token[18] == '-' && token[23] == '-' {
		return true
	}

	return len(token) >= 8
}

// trimWhitespace removes leading/trailing whitespace and newlines
func trimWhitespace(s string) string {
	// Remove common whitespace characters
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t' || s[0] == '\n' || s[0] == '\r') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t' || s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}
