// pkg/constants/security_test.go
//
// Tests for trusted remote validation - security-critical code.
// Covers: IsTrustedRemote, ParseRemoteHostPath, NormalizeRemoteURL

package constants

import (
	"testing"
)

// --- Unit tests: ParseRemoteHostPath ---

func TestParseRemoteHostPath(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		wantHost string
		wantPath string
		wantOK   bool
	}{
		// HTTPS URLs
		{
			name:     "gitea https with .git",
			raw:      "https://gitea.cybermonkey.sh/cybermonkey/eos.git",
			wantHost: "gitea.cybermonkey.sh",
			wantPath: "cybermonkey/eos",
			wantOK:   true,
		},
		{
			name:     "gitea https without .git",
			raw:      "https://gitea.cybermonkey.sh/cybermonkey/eos",
			wantHost: "gitea.cybermonkey.sh",
			wantPath: "cybermonkey/eos",
			wantOK:   true,
		},
		{
			name:     "github https with .git",
			raw:      "https://github.com/CodeMonkeyCybersecurity/eos.git",
			wantHost: "github.com",
			wantPath: "codemonkeycybersecurity/eos",
			wantOK:   true,
		},
		{
			name:     "github https without .git",
			raw:      "https://github.com/CodeMonkeyCybersecurity/eos",
			wantHost: "github.com",
			wantPath: "codemonkeycybersecurity/eos",
			wantOK:   true,
		},
		{
			name:     "github https mixed case",
			raw:      "https://GitHub.com/CodeMonkeyCybersecurity/Eos.git",
			wantHost: "github.com",
			wantPath: "codemonkeycybersecurity/eos",
			wantOK:   true,
		},

		// SSH URLs (ssh:// scheme)
		{
			name:     "gitea ssh with port",
			raw:      "ssh://git@gitea.cybermonkey.sh:9001/cybermonkey/eos.git",
			wantHost: "gitea.cybermonkey.sh",
			wantPath: "cybermonkey/eos",
			wantOK:   true,
		},
		{
			name:     "gitea ssh without port",
			raw:      "ssh://git@gitea.cybermonkey.sh/cybermonkey/eos.git",
			wantHost: "gitea.cybermonkey.sh",
			wantPath: "cybermonkey/eos",
			wantOK:   true,
		},
		{
			name:     "vhost7 ssh with port",
			raw:      "ssh://git@vhost7:9001/cybermonkey/eos.git",
			wantHost: "vhost7",
			wantPath: "cybermonkey/eos",
			wantOK:   true,
		},

		// SCP-style (git@host:path)
		{
			name:     "github scp style",
			raw:      "git@github.com:CodeMonkeyCybersecurity/eos.git",
			wantHost: "github.com",
			wantPath: "codemonkeycybersecurity/eos",
			wantOK:   true,
		},
		{
			name:     "gitea scp style",
			raw:      "git@gitea.cybermonkey.sh:cybermonkey/eos.git",
			wantHost: "gitea.cybermonkey.sh",
			wantPath: "cybermonkey/eos",
			wantOK:   true,
		},
		{
			name:     "scp style without .git",
			raw:      "git@github.com:CodeMonkeyCybersecurity/eos",
			wantHost: "github.com",
			wantPath: "codemonkeycybersecurity/eos",
			wantOK:   true,
		},

		// Edge cases
		{
			name:   "empty string",
			raw:    "",
			wantOK: false,
		},
		{
			name:   "whitespace only",
			raw:    "   ",
			wantOK: false,
		},
		{
			name:     "trailing whitespace",
			raw:      "  https://github.com/CodeMonkeyCybersecurity/eos.git  ",
			wantHost: "github.com",
			wantPath: "codemonkeycybersecurity/eos",
			wantOK:   true,
		},
		{
			name:   "bare path (no scheme, no @)",
			raw:    "/cybermonkey/eos.git",
			wantOK: false,
		},
		{
			name:   "scp style missing colon",
			raw:    "git@github.com/CodeMonkeyCybersecurity/eos.git",
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, path, ok := ParseRemoteHostPath(tt.raw)
			if ok != tt.wantOK {
				t.Fatalf("ParseRemoteHostPath(%q) ok = %v, want %v", tt.raw, ok, tt.wantOK)
			}
			if !tt.wantOK {
				return
			}
			if host != tt.wantHost {
				t.Errorf("host = %q, want %q", host, tt.wantHost)
			}
			if path != tt.wantPath {
				t.Errorf("path = %q, want %q", path, tt.wantPath)
			}
		})
	}
}

// --- Unit tests: NormalizeRemoteURL ---

func TestNormalizeRemoteURL(t *testing.T) {
	tests := []struct {
		raw  string
		want string
	}{
		{"https://GitHub.com/Org/Repo.git", "https://github.com/org/repo"},
		{"https://github.com/org/repo", "https://github.com/org/repo"},
		{"  https://github.com/org/repo.git  ", "https://github.com/org/repo"},
		{"git@github.com:Org/Repo.git", "git@github.com:org/repo"},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			got := NormalizeRemoteURL(tt.raw)
			if got != tt.want {
				t.Errorf("NormalizeRemoteURL(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

// --- Unit tests: IsTrustedRemote ---

func TestIsTrustedRemote(t *testing.T) {
	tests := []struct {
		name    string
		remote  string
		trusted bool
	}{
		// Gitea HTTPS (canonical)
		{"gitea https canonical", "https://gitea.cybermonkey.sh/cybermonkey/eos.git", true},
		{"gitea https no .git", "https://gitea.cybermonkey.sh/cybermonkey/eos", true},
		{"gitea https mixed case", "https://Gitea.Cybermonkey.SH/Cybermonkey/Eos.git", true},

		// Gitea SSH
		{"gitea ssh with port", "ssh://git@gitea.cybermonkey.sh:9001/cybermonkey/eos.git", true},
		{"gitea ssh no port", "ssh://git@gitea.cybermonkey.sh/cybermonkey/eos.git", true},
		{"gitea scp style", "git@gitea.cybermonkey.sh:cybermonkey/eos.git", true},

		// GitHub HTTPS
		{"github https canonical", "https://github.com/CodeMonkeyCybersecurity/eos.git", true},
		{"github https no .git", "https://github.com/CodeMonkeyCybersecurity/eos", true},
		{"github https lowercase", "https://github.com/codemonkeycybersecurity/eos.git", true},

		// GitHub SSH
		{"github scp style", "git@github.com:CodeMonkeyCybersecurity/eos.git", true},
		{"github scp lowercase", "git@github.com:codemonkeycybersecurity/eos.git", true},

		// Untrusted - wrong host
		{"untrusted host", "https://evil.com/cybermonkey/eos.git", false},
		{"untrusted host gitlab", "https://gitlab.com/cybermonkey/eos.git", false},
		{"attacker typosquat", "https://gitea.cybermonkey.sh.evil.com/cybermonkey/eos.git", false},

		// Untrusted - wrong path
		{"wrong org on github", "https://github.com/evil/eos.git", false},
		{"wrong repo on github", "https://github.com/CodeMonkeyCybersecurity/noteos.git", false},
		{"wrong org on gitea", "https://gitea.cybermonkey.sh/evil/eos.git", false},
		{"wrong repo on gitea", "https://gitea.cybermonkey.sh/cybermonkey/backdoor.git", false},

		// Untrusted - garbage
		{"empty", "", false},
		{"random text", "not-a-url", false},
		{"path only", "/cybermonkey/eos.git", false},
		{"local bare path not explicitly trusted", "/tmp/eos-origin.git", false},

		// vhost7 internal hostname - untrusted by default
		{"vhost7 internal", "ssh://git@vhost7:9001/cybermonkey/eos.git", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsTrustedRemote(tt.remote)
			if got != tt.trusted {
				t.Errorf("IsTrustedRemote(%q) = %v, want %v", tt.remote, got, tt.trusted)
			}
		})
	}
}

func TestIsTrustedRemote_ExactWhitelistSupportsLocalPaths(t *testing.T) {
	original := append([]string(nil), TrustedRemotes...)
	TrustedRemotes = append(TrustedRemotes, "/tmp/eos-origin.git")
	t.Cleanup(func() { TrustedRemotes = original })

	if !IsTrustedRemote("/tmp/eos-origin.git") {
		t.Fatal("expected exact TrustedRemotes whitelist entry to be trusted")
	}
}

// --- Security tests ---

func TestIsTrustedRemote_SecurityAttacks(t *testing.T) {
	attacks := []struct {
		name   string
		remote string
	}{
		{"path traversal", "https://gitea.cybermonkey.sh/../../../etc/passwd"},
		{"null byte", "https://gitea.cybermonkey.sh/cybermonkey/eos\x00.git"},
		{"unicode homoglyph", "https://gite\u0430.cybermonkey.sh/cybermonkey/eos.git"}, // Cyrillic 'a'
		{"subdomain attack", "https://evil.gitea.cybermonkey.sh/cybermonkey/eos.git"},
		{"port confusion", "https://gitea.cybermonkey.sh:443/cybermonkey/eos.git"},
	}

	// Expected results: most are false (attack blocked), but some are
	// legitimately trusted (port confusion = same host with explicit port).
	// %65 = 'e', so %65os == eos; url.Parse decodes it. This is correct
	// behavior since git would fetch the same repo. Not an attack vector.
	expectedTrusted := map[string]bool{
		"port confusion": true, // trusted host, port stripped by url.Hostname()
	}

	for _, tt := range attacks {
		t.Run(tt.name, func(t *testing.T) {
			got := IsTrustedRemote(tt.remote)
			want := expectedTrusted[tt.name]
			if got != want {
				if want {
					t.Errorf("IsTrustedRemote(%q) = false, but should be trusted", tt.remote)
				} else {
					t.Errorf("SECURITY: IsTrustedRemote(%q) = true, want false (attack vector)", tt.remote)
				}
			}
		})
	}
}

// --- Integration-style: verify the actual constants are self-consistent ---

func TestTrustedRemotesListedInConstants(t *testing.T) {
	// Every entry in TrustedRemotes should pass IsTrustedRemote
	for _, remote := range TrustedRemotes {
		if !IsTrustedRemote(remote) {
			t.Errorf("TrustedRemotes entry %q does not pass IsTrustedRemote", remote)
		}
	}
}

func TestPrimaryRemotesAreTrusted(t *testing.T) {
	if !IsTrustedRemote(PrimaryRemoteHTTPS) {
		t.Errorf("PrimaryRemoteHTTPS %q is not trusted", PrimaryRemoteHTTPS)
	}
	if !IsTrustedRemote(PrimaryRemoteSSH) {
		t.Errorf("PrimaryRemoteSSH %q is not trusted", PrimaryRemoteSSH)
	}
}

func TestTrustedHostsNotEmpty(t *testing.T) {
	if len(TrustedHosts) == 0 {
		t.Fatal("TrustedHosts is empty - no hosts would be trusted")
	}
}

func TestTrustedRepoPathsNotEmpty(t *testing.T) {
	if len(TrustedRepoPaths) == 0 {
		t.Fatal("TrustedRepoPaths is empty - no repos would be trusted")
	}
}

// --- Benchmark ---

func BenchmarkIsTrustedRemote_Trusted(b *testing.B) {
	for b.Loop() {
		IsTrustedRemote("https://gitea.cybermonkey.sh/cybermonkey/eos.git")
	}
}

func BenchmarkIsTrustedRemote_Untrusted(b *testing.B) {
	for b.Loop() {
		IsTrustedRemote("https://evil.com/malicious/repo.git")
	}
}

func BenchmarkParseRemoteHostPath_HTTPS(b *testing.B) {
	for b.Loop() {
		ParseRemoteHostPath("https://gitea.cybermonkey.sh/cybermonkey/eos.git")
	}
}

func BenchmarkParseRemoteHostPath_SCP(b *testing.B) {
	for b.Loop() {
		ParseRemoteHostPath("git@github.com:CodeMonkeyCybersecurity/eos.git")
	}
}
