// pkg/constants/security.go
//
// Security constants for Eos - trusted sources and verification settings
// CRITICAL: These constants protect against supply chain attacks

package constants

import "strings"

// TrustedGitRemotes defines the only acceptable git remote URLs for eos updates
// SECURITY: Only these remotes are trusted for self-update operations
// Any other remote will be REJECTED to prevent malicious code injection
const (
	// PrimaryRemoteHTTPS is the primary HTTPS remote
	PrimaryRemoteHTTPS = "https://github.com/CodeMonkeyCybersecurity/eos.git"

	// PrimaryRemoteSSH is the primary SSH remote
	PrimaryRemoteSSH = "git@github.com:CodeMonkeyCybersecurity/eos.git"
)

// TrustedRemotes is the whitelist of acceptable git remotes
// SECURITY CRITICAL: Only modify this list after security review
var TrustedRemotes = []string{
	PrimaryRemoteHTTPS,
	PrimaryRemoteSSH,
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

// IsTrustedRemote checks if a remote URL is in the trusted whitelist
// NOTE: GitHub URLs are case-insensitive for org/repo names, so we compare
// case-insensitively to accept both "Eos" and "eos" as valid
func IsTrustedRemote(remoteURL string) bool {
	for _, trusted := range TrustedRemotes {
		if strings.EqualFold(remoteURL, trusted) {
			return true
		}
	}
	return false
}
