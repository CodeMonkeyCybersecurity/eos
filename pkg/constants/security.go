// Package constants provides security-critical constants for Eos, including
// trusted git remote definitions, GPG verification settings, and URL parsing.
// CRITICAL: These constants protect against supply chain attacks.
package constants

import (
	"net/url"
	"strings"
)

// TrustedGitRemotes defines the only acceptable git remote URLs for eos updates
// SECURITY: Only these remotes are trusted for self-update operations
// Any other remote will be REJECTED to prevent malicious code injection

// TrustedHosts lists the hostnames trusted to serve Eos source code.
// SECURITY CRITICAL: Only modify this list after security review.
// Matching is case-insensitive and ignores port numbers so that
// ssh://git@gitea.cybermonkey.sh:9001/... and https://gitea.cybermonkey.sh/...
// both resolve to the same trusted host.
var TrustedHosts = []string{
	"github.com",
	"gitea.cybermonkey.sh",
}

// TrustedRepoPaths lists the allowed org/repo path suffixes.
// The comparison strips a trailing ".git" and is case-insensitive.
var TrustedRepoPaths = []string{
	"codemonkeycybersecurity/eos",
	"cybermonkey/eos",
}

// PrimaryRemoteHTTPS is the canonical Gitea HTTPS remote.
const PrimaryRemoteHTTPS = "https://gitea.cybermonkey.sh/cybermonkey/eos.git"

// PrimaryRemoteSSH is the canonical Gitea SSH remote.
const PrimaryRemoteSSH = "ssh://git@gitea.cybermonkey.sh:9001/cybermonkey/eos.git"

// TrustedRemotes is the explicit whitelist of acceptable git remotes for
// display in error messages. IsTrustedRemote uses host+path matching, so
// this slice is only used for human-readable output.
var TrustedRemotes = []string{
	PrimaryRemoteHTTPS,
	PrimaryRemoteSSH,
	"git@gitea.cybermonkey.sh:cybermonkey/eos.git",
	"https://github.com/CodeMonkeyCybersecurity/eos.git",
	"git@github.com:CodeMonkeyCybersecurity/eos.git",
}

// GPGVerificationSettings controls GPG signature verification
type GPGVerificationSettings struct {
	// RequireSignatures determines if GPG signatures are required
	// Currently set to false for compatibility, but warns if not signed
	RequireSignatures bool

	// TrustedKeys is the list of trusted GPG key fingerprints
	// Empty list means all valid signatures are accepted
	TrustedKeys []string

	// WarnIfNotSigned logs a warning if commit is not signed
	WarnIfNotSigned bool
}

// DefaultGPGSettings are the default GPG verification settings
// SECURITY: Currently warns but doesn't block unsigned commits
// FUTURE: Set RequireSignatures = true once all commits are GPG signed
var DefaultGPGSettings = GPGVerificationSettings{
	RequireSignatures: false,      // Don't block updates for unsigned commits (yet)
	TrustedKeys:       []string{}, // Accept any valid signature
	WarnIfNotSigned:   true,       // Warn users about unsigned commits
}

// NormalizeRemoteURL strips a trailing ".git" suffix and lowercases the
// string so that equivalent remote URLs compare equal.
func NormalizeRemoteURL(raw string) string {
	s := strings.TrimSpace(raw)
	s = strings.TrimSuffix(s, ".git")
	return strings.ToLower(s)
}

// ParseRemoteHostPath extracts the host (without port) and the repo path
// from a git remote URL. Supports HTTPS, SSH (ssh://...) and SCP-style
// (git@host:path) formats.
//
// Returns (host, path, ok). path is returned without a leading "/" and
// without a trailing ".git".
func ParseRemoteHostPath(raw string) (host string, repoPath string, ok bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", false
	}

	// SCP-style: git@host:org/repo.git
	if idx := strings.Index(raw, "@"); idx >= 0 && !strings.Contains(raw, "://") {
		afterAt := raw[idx+1:]
		colonIdx := strings.Index(afterAt, ":")
		if colonIdx < 0 {
			return "", "", false
		}
		host = strings.ToLower(afterAt[:colonIdx])
		repoPath = strings.TrimPrefix(afterAt[colonIdx+1:], "/")
		repoPath = strings.TrimSuffix(repoPath, ".git")
		repoPath = strings.ToLower(repoPath)
		return host, repoPath, true
	}

	// URL-style: https://host/org/repo.git or ssh://git@host:port/org/repo.git
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", "", false
	}

	host = strings.ToLower(u.Hostname()) // strips port
	repoPath = strings.TrimPrefix(u.Path, "/")
	repoPath = strings.TrimSuffix(repoPath, ".git")
	repoPath = strings.ToLower(repoPath)
	return host, repoPath, true
}

// IsTrustedRemote checks if a remote URL resolves to a trusted host
// serving the Eos repository. It matches on host (case-insensitive,
// port-stripped) and repo path (case-insensitive, .git-stripped).
func IsTrustedRemote(remoteURL string) bool {
	normalized := NormalizeRemoteURL(remoteURL)
	for _, trusted := range TrustedRemotes {
		if normalized == NormalizeRemoteURL(trusted) {
			return true
		}
	}

	host, repoPath, ok := ParseRemoteHostPath(remoteURL)
	if !ok {
		return false
	}

	hostTrusted := false
	for _, h := range TrustedHosts {
		if host == strings.ToLower(h) {
			hostTrusted = true
			break
		}
	}
	if !hostTrusted {
		return false
	}

	for _, p := range TrustedRepoPaths {
		if repoPath == strings.ToLower(p) {
			return true
		}
	}
	return false
}
