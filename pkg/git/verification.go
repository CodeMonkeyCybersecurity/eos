// pkg/git/verification.go
//
// Git remote and commit verification - security-critical code
// Protects against supply chain attacks and malicious code injection

package git

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/constants"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// VerificationResult contains the results of git verification checks
type VerificationResult struct {
	RemoteVerified    bool
	RemoteURL         string
	IsTrusted         bool
	SignatureVerified bool
	SignatureValid    bool
	SignerInfo        string
	Warnings          []string
}

// VerifyTrustedRemote verifies that the git remote is in the trusted whitelist
// SECURITY CRITICAL: This prevents pulling code from malicious repositories
func VerifyTrustedRemote(rc *eos_io.RuntimeContext, repoDir string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Verifying git remote is trusted")

	// Get current remote URL
	cmd := exec.Command("git", "-C", repoDir, "remote", "get-url", "origin")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to get git remote URL: %w\n"+
			"Repository: %s\n"+
			"Fix: Verify git repository is properly configured",
			err, repoDir)
	}

	remoteURL := strings.TrimSpace(string(output))

	// Check against trusted whitelist
	if !constants.IsTrustedRemote(remoteURL) {
		logger.Error("SECURITY: Untrusted git remote detected",
			zap.String("remote", remoteURL),
			zap.Strings("trusted_remotes", constants.TrustedRemotes))

		return fmt.Errorf("SECURITY VIOLATION: Git remote is not in trusted whitelist\n"+
			"Current remote: %s\n"+
			"Trusted remotes:\n"+
			"  - %s\n"+
			"  - %s\n\n"+
			"DANGER: An attacker may have modified your git configuration!\n\n"+
			"Fix (if you trust this is safe):\n"+
			"  cd %s\n"+
			"  git remote set-url origin %s\n\n"+
			"If you did not make this change, your system may be compromised.\n"+
			"Report to: security@cybermonkey.net.au",
			remoteURL,
			constants.PrimaryRemoteHTTPS,
			constants.PrimaryRemoteSSH,
			repoDir,
			constants.PrimaryRemoteHTTPS)
	}

	logger.Info("Git remote verified as trusted",
		zap.String("remote", remoteURL))

	return nil
}

// VerifyCommitSignature verifies the GPG signature of a git commit
// Returns error if signature is required and missing/invalid
// Returns nil with warning if signature not required but missing
func VerifyCommitSignature(rc *eos_io.RuntimeContext, repoDir, commitHash string) (*VerificationResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	settings := constants.DefaultGPGSettings

	result := &VerificationResult{
		SignatureVerified: false,
		SignatureValid:    false,
	}

	logger.Debug("Checking GPG signature for commit",
		zap.String("commit", commitHash[:8]))

	// Try to verify commit signature
	cmd := exec.Command("git", "-C", repoDir, "verify-commit", commitHash)
	output, err := cmd.CombinedOutput()
	outputStr := strings.TrimSpace(string(output))

	if err != nil {
		// Signature verification failed or commit not signed
		result.SignatureVerified = true  // We attempted verification
		result.SignatureValid = false

		if strings.Contains(outputStr, "no signature found") {
			// Commit is not signed
			if settings.RequireSignatures {
				logger.Error("SECURITY: Commit is not GPG signed (required)",
					zap.String("commit", commitHash[:8]))
				return result, fmt.Errorf("SECURITY: Commit %s is not GPG signed\n"+
					"GPG signatures are required for security.\n"+
					"This commit cannot be trusted.",
					commitHash[:8])
			}

			if settings.WarnIfNotSigned {
				warning := fmt.Sprintf("Commit %s is not GPG signed", commitHash[:8])
				result.Warnings = append(result.Warnings, warning)
				logger.Warn("SECURITY WARNING: Commit not GPG signed",
					zap.String("commit", commitHash[:8]),
					zap.String("note", "GPG signatures provide cryptographic proof of authenticity"))
			}

			return result, nil  // Warn but allow
		}

		// Signature exists but is invalid
		logger.Error("SECURITY: GPG signature verification failed",
			zap.String("commit", commitHash[:8]),
			zap.String("error", outputStr))

		return result, fmt.Errorf("SECURITY: GPG signature invalid for commit %s\n"+
			"Output: %s\n\n"+
			"This could indicate:\n"+
			"  - Commit was tampered with\n"+
			"  - Signature key is not in your GPG keyring\n"+
			"  - Signature was made with expired key\n\n"+
			"Fix: Import trusted GPG keys:\n"+
			"  gpg --keyserver keys.openpgp.org --recv-keys <key-id>",
			commitHash[:8], outputStr)
	}

	// Signature verification succeeded
	result.SignatureVerified = true
	result.SignatureValid = true

	// Extract signer information
	if strings.Contains(outputStr, "Good signature from") {
		lines := strings.Split(outputStr, "\n")
		for _, line := range lines {
			if strings.Contains(line, "Good signature from") {
				result.SignerInfo = strings.TrimSpace(line)
				break
			}
		}
	}

	logger.Info("GPG signature verified successfully",
		zap.String("commit", commitHash[:8]),
		zap.String("signer", result.SignerInfo))

	// If we have a trusted keys list, verify signer is trusted
	if len(settings.TrustedKeys) > 0 {
		// Extract key ID from signature
		keyIDCmd := exec.Command("git", "-C", repoDir, "log", "--format=%GK", "-1", commitHash)
		keyIDOutput, err := keyIDCmd.Output()
		if err != nil {
			logger.Warn("Could not extract signing key ID", zap.Error(err))
			return result, nil
		}

		keyID := strings.TrimSpace(string(keyIDOutput))

		// Check if key is in trusted list
		keyTrusted := false
		for _, trustedKey := range settings.TrustedKeys {
			if strings.Contains(keyID, trustedKey) || strings.Contains(trustedKey, keyID) {
				keyTrusted = true
				break
			}
		}

		if !keyTrusted {
			logger.Warn("SECURITY: Commit signed by untrusted key",
				zap.String("commit", commitHash[:8]),
				zap.String("key_id", keyID),
				zap.Strings("trusted_keys", settings.TrustedKeys))

			warning := fmt.Sprintf("Commit signed by untrusted key: %s", keyID)
			result.Warnings = append(result.Warnings, warning)
		}
	}

	return result, nil
}

// VerifyCommitChain verifies signatures for a range of commits
// Useful for verifying all commits since last update
func VerifyCommitChain(rc *eos_io.RuntimeContext, repoDir, fromCommit, toCommit string) ([]*VerificationResult, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Verifying commit chain",
		zap.String("from", fromCommit[:8]),
		zap.String("to", toCommit[:8]))

	// Get list of commits in range
	cmd := exec.Command("git", "-C", repoDir, "rev-list", fmt.Sprintf("%s..%s", fromCommit, toCommit))
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get commit list: %w", err)
	}

	commits := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(commits) == 0 || (len(commits) == 1 && commits[0] == "") {
		logger.Info("No commits to verify (already up-to-date)")
		return nil, nil
	}

	results := make([]*VerificationResult, 0, len(commits))
	unsignedCount := 0
	invalidCount := 0

	for _, commit := range commits {
		if commit == "" {
			continue
		}

		result, err := VerifyCommitSignature(rc, repoDir, commit)
		if err != nil {
			logger.Warn("Commit signature verification failed",
				zap.String("commit", commit[:8]),
				zap.Error(err))
			invalidCount++
		} else if result != nil {
			if !result.SignatureValid {
				unsignedCount++
			}
			results = append(results, result)
		}
	}

	logger.Info("Commit chain verification complete",
		zap.Int("total_commits", len(commits)),
		zap.Int("signed", len(commits)-unsignedCount-invalidCount),
		zap.Int("unsigned", unsignedCount),
		zap.Int("invalid", invalidCount))

	if invalidCount > 0 && constants.DefaultGPGSettings.RequireSignatures {
		return results, fmt.Errorf("%d commits have invalid signatures", invalidCount)
	}

	return results, nil
}
