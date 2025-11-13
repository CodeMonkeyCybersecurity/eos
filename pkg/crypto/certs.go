/* pkg/crypto/certs.go */

package crypto

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
)

// EnsureCertificates securely checks if certificate files exist for the given domain,
// and if not, calls an external command (like certbot) to obtain them.
// All inputs are validated to prevent command injection attacks.
func EnsureCertificates(appName, baseDomain, email string) error {
	// SECURITY: Validate all inputs before any processing
	if err := ValidateAllCertificateInputs(appName, baseDomain, email); err != nil {
		return fmt.Errorf("certificate input validation failed: %w", err)
	}

	// Additional sanitization as defense-in-depth
	appName = SanitizeInputForCommand(appName)
	baseDomain = SanitizeInputForCommand(baseDomain)
	email = SanitizeInputForCommand(email)

	// Re-validate after sanitization to ensure nothing malicious got through
	if err := ValidateAllCertificateInputs(appName, baseDomain, email); err != nil {
		return fmt.Errorf("post-sanitization validation failed: %w", err)
	}

	certDir := "certs"

	// Construct the fully qualified domain name using validated inputs
	fqdn := fmt.Sprintf("%s.%s", appName, baseDomain)

	// Use secure file path construction
	privKey := filepath.Join(certDir, fmt.Sprintf("%s.privkey.pem", fqdn))
	fullChain := filepath.Join(certDir, fmt.Sprintf("%s.fullchain.pem", fqdn))

	// Validate that the constructed file paths are safe
	if err := validateFilePath(privKey); err != nil {
		return fmt.Errorf("invalid private key path: %w", err)
	}
	if err := validateFilePath(fullChain); err != nil {
		return fmt.Errorf("invalid fullchain path: %w", err)
	}

	// Check if the private key exists
	if _, err := os.Stat(privKey); os.IsNotExist(err) {
		// Use secure command execution with timeout and validation
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()

		// Execute certbot with validated parameters using our secure execute package
		args := []string{
			"certonly",
			"--standalone",
			"--preferred-challenges", "http",
			"-d", fqdn,
			"-m", email,
			"--agree-tos",
			"--non-interactive",
		}

		// Log the command being executed (but not the email for privacy)
		if err := execute.RunSimple(ctx, "certbot", args...); err != nil {
			return fmt.Errorf("failed to generate certificate for domain %s: %w", fqdn, err)
		}

		// In production, you would move or copy the generated certificates to certDir
		// For now, we assume certbot places them in the correct location

	} else if _, err := os.Stat(fullChain); os.IsNotExist(err) {
		// If the private key exists but the fullchain is missing, return an error
		return fmt.Errorf("fullchain certificate missing for domain %s", fqdn)
	}

	// If both files exist, no action is needed
	return nil
}

// validateFilePath ensures file paths are safe and don't contain path traversal
func validateFilePath(path string) error {
	// Check for path traversal attempts
	if filepath.IsAbs(path) {
		return fmt.Errorf("absolute paths not allowed: %s", path)
	}

	// Check for .. elements which indicate path traversal
	if strings.Contains(path, "..") {
		return fmt.Errorf("path contains traversal elements: %s", path)
	}

	// Clean the path and check if it's trying to escape
	cleanPath := filepath.Clean(path)

	// If the clean path starts with .. or contains .., it's trying to escape
	if strings.HasPrefix(cleanPath, "..") || strings.Contains(cleanPath, "/..") {
		return fmt.Errorf("path contains traversal elements: %s", path)
	}

	// Additional check for dangerous paths
	dangerousPaths := []string{"/etc/", "/var/", "/usr/", "/home/", "/root/", "/tmp/"}
	for _, dangerous := range dangerousPaths {
		if strings.Contains(strings.ToLower(cleanPath), dangerous) {
			return fmt.Errorf("path accesses restricted directory: %s", path)
		}
	}

	return nil
}
