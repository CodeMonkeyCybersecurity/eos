// pkg/git/credentials.go
//
// Git credential management for HTTPS remotes.
// Ensures git operations don't block on interactive credential prompts.
// Guides users through credential setup when credentials are missing.

package git

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CredentialStatus describes the state of git credential configuration.
type CredentialStatus struct {
	// HelperConfigured is true if credential.helper is set in git config.
	HelperConfigured bool
	// HelperName is the name of the configured helper (e.g., "store", "cache").
	HelperName string
	// CredentialsAvailable is true if credentials are stored for the remote host.
	CredentialsAvailable bool
	// RemoteRequiresAuth is true if the remote URL uses HTTPS (needs credentials).
	RemoteRequiresAuth bool
	// RemoteURL is the resolved remote URL for the repository.
	RemoteURL string
}

// CheckCredentials checks if git credentials are configured for the remote
// in the given repository. Returns a CredentialStatus and a user-friendly
// error if credentials are missing for an HTTPS remote.
//
// This function does NOT prompt the user. It only diagnoses.
func CheckCredentials(rc *eos_io.RuntimeContext, repoDir string) (*CredentialStatus, error) {
	logger := otelzap.Ctx(rc.Ctx)
	status := &CredentialStatus{}

	// Get remote URL
	remoteCmd := exec.Command("git", "-C", repoDir, "remote", "get-url", "origin")
	remoteOutput, err := remoteCmd.Output()
	if err != nil {
		return status, fmt.Errorf("failed to get remote URL: %w", err)
	}
	remoteURL := strings.TrimSpace(string(remoteOutput))
	status.RemoteURL = remoteURL

	// SSH remotes don't need credential.helper - they use SSH keys
	if strings.HasPrefix(remoteURL, "git@") || strings.HasPrefix(remoteURL, "ssh://") {
		logger.Debug("SSH remote detected, credential helper not needed",
			zap.String("remote", remoteURL))
		status.RemoteRequiresAuth = false
		return status, nil
	}

	// HTTPS remotes need credential configuration
	if strings.HasPrefix(remoteURL, "https://") || strings.HasPrefix(remoteURL, "http://") {
		status.RemoteRequiresAuth = true
	} else {
		// Unknown scheme - assume no auth needed
		return status, nil
	}

	// Check if credential.helper is configured (any scope)
	helperCmd := exec.Command("git", "-C", repoDir, "config", "credential.helper")
	helperOutput, err := helperCmd.Output()
	if err == nil {
		helper := strings.TrimSpace(string(helperOutput))
		if helper != "" {
			status.HelperConfigured = true
			status.HelperName = helper
			logger.Debug("Credential helper configured",
				zap.String("helper", helper))
		}
	}

	// If credential.helper is "store", check if credentials file exists
	if status.HelperConfigured && strings.Contains(status.HelperName, "store") {
		status.CredentialsAvailable = credentialStoreHasHost(remoteURL)
	}

	// If credential.helper is configured (even without confirming stored creds),
	// assume it will handle auth (could be cache, osxkeychain, manager, etc.)
	if status.HelperConfigured {
		status.CredentialsAvailable = true
	}

	if !status.HelperConfigured {
		logger.Warn("No credential helper configured for HTTPS remote",
			zap.String("remote", remoteURL))
	}

	return status, nil
}

// credentialStoreHasHost checks if ~/.git-credentials contains an entry
// for the host in the given remote URL. Also checks /root/.git-credentials
// when running as root.
func credentialStoreHasHost(remoteURL string) bool {
	// Extract host from URL
	host := extractHost(remoteURL)
	if host == "" {
		return false
	}

	// Check common credential store locations
	paths := []string{}

	if home, err := os.UserHomeDir(); err == nil {
		paths = append(paths, home+"/.git-credentials")
	}

	// Also check root's credentials when running as root
	if os.Getuid() == 0 {
		paths = append(paths, "/root/.git-credentials")
	}

	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if strings.Contains(string(data), host) {
			return true
		}
	}

	return false
}

// extractHost extracts the hostname from a remote URL.
func extractHost(remoteURL string) string {
	// Strip scheme
	url := remoteURL
	for _, scheme := range []string{"https://", "http://"} {
		if strings.HasPrefix(url, scheme) {
			url = strings.TrimPrefix(url, scheme)
			break
		}
	}

	// Take everything before the first /
	if idx := strings.Index(url, "/"); idx > 0 {
		return url[:idx]
	}
	return url
}

// EnsureCredentials checks if credentials are configured for the repository's
// HTTPS remote. If not, returns an actionable error with setup instructions.
//
// This is designed to be called BEFORE git pull to prevent the process from
// hanging on an interactive credential prompt.
func EnsureCredentials(rc *eos_io.RuntimeContext, repoDir string) error {
	logger := otelzap.Ctx(rc.Ctx)

	status, err := CheckCredentials(rc, repoDir)
	if err != nil {
		return fmt.Errorf("failed to check credentials: %w", err)
	}

	// No auth needed (SSH or non-HTTPS remote)
	if !status.RemoteRequiresAuth {
		return nil
	}

	// Credentials are configured - proceed
	if status.HelperConfigured {
		logger.Debug("Credentials configured",
			zap.String("helper", status.HelperName),
			zap.Bool("credentials_available", status.CredentialsAvailable))
		return nil
	}

	remoteURL := status.RemoteURL
	host := extractHost(remoteURL)

	logger.Warn("No credential helper configured for HTTPS remote",
		zap.String("remote", remoteURL),
		zap.String("host", host))

	return fmt.Errorf("git credentials not configured for HTTPS remote %s: "+
		"run 'sudo git config --global credential.helper store' and configure a token at https://%s/-/user/settings/applications, "+
		"or switch to SSH with 'sudo git remote set-url origin ssh://git@%s:9001/cybermonkey/eos.git' in %s",
		remoteURL, host, host, repoDir)
}

// IsInteractive returns true if stdin is connected to a terminal (TTY).
// Used to decide whether git should be allowed to prompt for credentials.
func IsInteractive() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	// If stdin is a character device (not a pipe/file), it's a TTY
	return fi.Mode()&os.ModeCharDevice != 0
}

// GitPullEnv returns environment variables for git pull commands.
// When running non-interactively (no TTY), sets GIT_TERMINAL_PROMPT=0
// to prevent git from hanging on credential prompts.
// When running interactively, allows git to prompt normally.
func GitPullEnv() []string {
	if !IsInteractive() {
		return []string{"GIT_TERMINAL_PROMPT=0"}
	}
	return nil
}
