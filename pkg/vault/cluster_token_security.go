// pkg/vault/cluster_token_security.go
//
// SECURITY: Secure token file management for Vault cluster operations
//
// This package provides secure token handling for Vault cluster operations that
// require shell command execution (Raft, Autopilot, snapshots). Instead of passing
// tokens via environment variables (visible in ps/proc), we use temporary files
// with restricted permissions.
//
// THREAT MODEL:
// - Attack: Token scraping from process list (ps auxe | grep VAULT_TOKEN)
// - Attack: Token theft from /proc/<pid>/environ
// - Attack: Token exposure in core dumps
// - Mitigation: Use VAULT_TOKEN_FILE with 0400 permissions, immediate cleanup
//
// COMPLIANCE:
// - NIST 800-53 SC-12 (Cryptographic Key Establishment)
// - NIST 800-53 AC-3 (Access Enforcement)
// - PCI-DSS 3.2.1 (Do not store sensitive authentication data after authorization)
//
// Code Monkey Cybersecurity - "Cybersecurity. With humans."
//
// Last Updated: 2025-01-27

package vault

import (
    "fmt"
    "os"

    "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
    "github.com/uptrace/opentelemetry-go-extra/otelzap"
    "go.uber.org/zap"
)

// TempTokenFilePerm is the permission for temporary token files (owner-read-only)
// RATIONALE: Token files must only be readable by the process owner
// SECURITY: Prevents token theft by other users on the same system
// THREAT MODEL: Mitigates privilege escalation via token file access
const TempTokenFilePerm = 0400 // r--------

// createTemporaryTokenFile creates a temporary file containing the Vault token
// with secure permissions (0400 - owner-read-only).
//
// The file is created with an unpredictable name in the system temp directory
// and must be explicitly deleted by the caller using defer os.Remove().
//
// SECURITY RATIONALE:
//   - Environment variables are visible via ps auxe and /proc/<pid>/environ
//   - Temporary files with 0400 perms are only readable by the process owner
//   - Unpredictable filename prevents guessing attacks
//   - Immediate cleanup via defer limits exposure window
//
// Example usage:
//
//	tokenFile, err := createTemporaryTokenFile(rc, token)
//	if err != nil {
//	    return fmt.Errorf("failed to create token file: %w", err)
//	}
//	defer os.Remove(tokenFile.Name())  // CRITICAL: Always cleanup
//
//	cmd := exec.CommandContext(rc.Ctx, "vault", args...)
//	cmd.Env = append(cmd.Env,
//	    fmt.Sprintf("VAULT_ADDR=%s", shared.GetVaultAddr()),
//	    fmt.Sprintf("VAULT_TOKEN_FILE=%s", tokenFile.Name()),  // Secure
//	)
//
// Parameters:
//   - rc: RuntimeContext for logging and telemetry
//   - token: Vault token to write (root token, admin token, etc.)
//
// Returns:
//   - *os.File: Closed file handle (for name retrieval and cleanup)
//   - error: If file creation, chmod, write, or close fails
//
// COMPLIANCE:
//   - NIST 800-53 SC-12: Cryptographic keys established and managed securely
//   - PCI-DSS 3.2.1: Sensitive authentication data not stored after authorization
func createTemporaryTokenFile(rc *eos_io.RuntimeContext, token string) (*os.File, error) {
	log := otelzap.Ctx(rc.Ctx)

	// SECURITY: Create temp file with unpredictable name
	// Pattern: vault-token-<random> (Go stdlib uses cryptographically random suffix)
	tokenFile, err := os.CreateTemp("", "vault-token-*")
	if err != nil {
		log.Error("Failed to create temporary token file",
			zap.Error(err),
			zap.String("reason", "os.CreateTemp failed"))
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}

	// SECURITY: Set owner-read-only permissions BEFORE writing token
	// This prevents race condition where file is readable during write
	if err := tokenFile.Chmod(TempTokenFilePerm); err != nil {
		// Cleanup on error
		_ = tokenFile.Close()
		_ = os.Remove(tokenFile.Name())

		log.Error("Failed to set token file permissions",
			zap.Error(err),
			zap.String("file", tokenFile.Name()),
			zap.String("target_perms", "0400"))
		return nil, fmt.Errorf("failed to set permissions: %w", err)
	}

	// Write token to file
	if _, err := tokenFile.WriteString(token); err != nil {
		// Cleanup on error
		_ = tokenFile.Close()
		_ = os.Remove(tokenFile.Name())

		log.Error("Failed to write token to file",
			zap.Error(err),
			zap.String("file", tokenFile.Name()))
		return nil, fmt.Errorf("failed to write token: %w", err)
	}

	// Close file (Vault CLI reads from closed file via VAULT_TOKEN_FILE)
	if err := tokenFile.Close(); err != nil {
		// Still need to cleanup even if close fails
		_ = os.Remove(tokenFile.Name())

		log.Error("Failed to close token file",
			zap.Error(err),
			zap.String("file", tokenFile.Name()))
		return nil, fmt.Errorf("failed to close token file: %w", err)
	}

	log.Debug("Created temporary token file",
		zap.String("file", tokenFile.Name()),
		zap.String("permissions", "0400"),
		zap.String("cleanup", "caller must defer os.Remove()"))

	return tokenFile, nil
}
