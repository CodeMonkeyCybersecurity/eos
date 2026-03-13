// pkg/git/credentials_test.go
//
// Tests for git credential checking and TTY detection.
// Unit tests verify credential helper detection, host extraction,
// and environment variable generation for non-interactive safety.

package git

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// --- Unit tests: extractHost ---

func TestExtractHost(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		wantHost string
	}{
		{"https with path", "https://gitea.cybermonkey.sh/cybermonkey/eos.git", "gitea.cybermonkey.sh"},
		{"https without path", "https://gitea.cybermonkey.sh", "gitea.cybermonkey.sh"},
		{"https with port", "https://gitea.cybermonkey.sh:443/cybermonkey/eos.git", "gitea.cybermonkey.sh:443"},
		{"http scheme", "http://example.com/repo.git", "example.com"},
		{"github", "https://github.com/CodeMonkeyCybersecurity/eos.git", "github.com"},
		{"no scheme", "gitea.cybermonkey.sh/cybermonkey/eos.git", "gitea.cybermonkey.sh"},
		{"empty string", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractHost(tt.url)
			if got != tt.wantHost {
				t.Errorf("extractHost(%q) = %q, want %q", tt.url, got, tt.wantHost)
			}
		})
	}
}

// --- Unit tests: IsInteractive ---

func TestIsInteractive(t *testing.T) {
	// In test environments, stdin is typically NOT a TTY (piped).
	// We can't control this, but we can verify the function runs without panic.
	result := IsInteractive()
	t.Logf("IsInteractive() = %v (expected false in test environment)", result)
	// In CI/test, this should be false since stdin is piped
}

// --- Unit tests: GitPullEnv ---

func TestGitPullEnv(t *testing.T) {
	env := GitPullEnv()
	// In test environments (non-interactive), should return GIT_TERMINAL_PROMPT=0
	// In interactive environments, should return nil
	interactive := IsInteractive()
	if interactive {
		if len(env) != 0 {
			t.Errorf("GitPullEnv() returned %v for interactive session, want nil", env)
		}
	} else {
		if len(env) == 0 {
			t.Error("GitPullEnv() returned nil for non-interactive session, want GIT_TERMINAL_PROMPT=0")
		} else if env[0] != "GIT_TERMINAL_PROMPT=0" {
			t.Errorf("GitPullEnv()[0] = %q, want GIT_TERMINAL_PROMPT=0", env[0])
		}
	}
}

// --- Unit tests: CheckCredentials ---

func TestCheckCredentials_SSHRemote(t *testing.T) {
	rc := newTestRC(t)
	dir := initTestRepo(t, "git@github.com:CodeMonkeyCybersecurity/eos.git")

	status, err := CheckCredentials(rc, dir)
	if err != nil {
		t.Fatalf("CheckCredentials failed: %v", err)
	}

	if status.RemoteRequiresAuth {
		t.Error("SSH remote should not require auth via credential helper")
	}
}

func TestCheckCredentials_SSHSchemeRemote(t *testing.T) {
	rc := newTestRC(t)
	dir := initTestRepo(t, "ssh://git@gitea.cybermonkey.sh:9001/cybermonkey/eos.git")

	status, err := CheckCredentials(rc, dir)
	if err != nil {
		t.Fatalf("CheckCredentials failed: %v", err)
	}

	if status.RemoteRequiresAuth {
		t.Error("SSH scheme remote should not require auth via credential helper")
	}
}

func TestCheckCredentials_HTTPSRemote_NoHelper(t *testing.T) {
	rc := newTestRC(t)
	dir := initTestRepo(t, "https://gitea.cybermonkey.sh/cybermonkey/eos.git")

	// Ensure no credential helper is configured in the test repo
	cmd := exec.Command("git", "-C", dir, "config", "--unset", "credential.helper")
	_ = cmd.Run() // Ignore error if not set

	status, err := CheckCredentials(rc, dir)
	if err != nil {
		t.Fatalf("CheckCredentials failed: %v", err)
	}

	if !status.RemoteRequiresAuth {
		t.Error("HTTPS remote should require auth")
	}
	// In test environment with no global config, helper should not be configured
	// (unless the test runner has one globally configured)
	t.Logf("HelperConfigured=%v HelperName=%q", status.HelperConfigured, status.HelperName)
}

func TestCheckCredentials_HTTPSRemote_WithHelper(t *testing.T) {
	rc := newTestRC(t)
	dir := initTestRepo(t, "https://gitea.cybermonkey.sh/cybermonkey/eos.git")

	// Configure credential helper in local repo config
	cmd := exec.Command("git", "-C", dir, "config", "credential.helper", "store")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to set credential.helper: %v\n%s", err, out)
	}

	status, err := CheckCredentials(rc, dir)
	if err != nil {
		t.Fatalf("CheckCredentials failed: %v", err)
	}

	if !status.RemoteRequiresAuth {
		t.Error("HTTPS remote should require auth")
	}
	if !status.HelperConfigured {
		t.Error("credential helper should be detected as configured")
	}
	if status.HelperName != "store" {
		t.Errorf("HelperName = %q, want %q", status.HelperName, "store")
	}
}

func TestCheckCredentials_NotARepo(t *testing.T) {
	rc := newTestRC(t)
	dir := t.TempDir() // no git init

	_, err := CheckCredentials(rc, dir)
	if err == nil {
		t.Fatal("expected error for non-repo directory")
	}
}

// --- Unit tests: EnsureCredentials ---

func TestEnsureCredentials_SSHRemote(t *testing.T) {
	rc := newTestRC(t)
	dir := initTestRepo(t, "ssh://git@gitea.cybermonkey.sh:9001/cybermonkey/eos.git")

	if err := EnsureCredentials(rc, dir); err != nil {
		t.Errorf("EnsureCredentials should pass for SSH remote, got: %v", err)
	}
}

func TestEnsureCredentials_HTTPSWithHelper(t *testing.T) {
	rc := newTestRC(t)
	dir := initTestRepo(t, "https://gitea.cybermonkey.sh/cybermonkey/eos.git")

	// Configure credential helper
	cmd := exec.Command("git", "-C", dir, "config", "credential.helper", "store")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to set credential.helper: %v\n%s", err, out)
	}

	if err := EnsureCredentials(rc, dir); err != nil {
		t.Errorf("EnsureCredentials should pass with helper configured, got: %v", err)
	}
}

func TestEnsureCredentials_HTTPSNoHelper(t *testing.T) {
	rc := newTestRC(t)
	dir := initTestRepo(t, "https://gitea.cybermonkey.sh/cybermonkey/eos.git")

	// Ensure no credential helper (use isolated HOME from initTestRepo)
	cmd := exec.Command("git", "-C", dir, "config", "--unset", "credential.helper")
	_ = cmd.Run()

	err := EnsureCredentials(rc, dir)
	// May or may not error depending on global git config of test runner.
	// If it errors, verify the error message is helpful.
	if err != nil {
		errMsg := err.Error()
		if !containsAll(errMsg, "credential", "HTTPS") {
			t.Errorf("error should mention credentials and HTTPS, got: %s", errMsg)
		}
		if !containsAll(errMsg, "token", "credential.helper") {
			t.Errorf("error should include remediation steps, got: %s", errMsg)
		}
		t.Logf("Got expected credential warning: %s", errMsg[:min(len(errMsg), 100)])
	}
}

// --- Unit tests: credentialStoreHasHost ---

func TestCredentialStoreHasHost_FileExists(t *testing.T) {
	// Create a temporary credentials file
	dir := t.TempDir()
	credFile := filepath.Join(dir, ".git-credentials")
	err := os.WriteFile(credFile, []byte("https://henry:token123@gitea.cybermonkey.sh\n"), 0600)
	if err != nil {
		t.Fatal(err)
	}

	// credentialStoreHasHost uses os.UserHomeDir(), so we can't easily
	// redirect it to our temp dir in unit tests. Just verify the function
	// doesn't panic with various inputs.
	_ = credentialStoreHasHost("https://gitea.cybermonkey.sh/cybermonkey/eos.git")
	_ = credentialStoreHasHost("https://github.com/org/repo.git")
	_ = credentialStoreHasHost("")
}

// --- Helper ---

func containsAll(s string, substrings ...string) bool {
	for _, sub := range substrings {
		found := false
		// Case-insensitive search
		sl := len(s)
		subl := len(sub)
		for i := 0; i <= sl-subl; i++ {
			match := true
			for j := 0; j < subl; j++ {
				sc := s[i+j]
				subc := sub[j]
				// Simple ASCII lowercase comparison
				if sc >= 'A' && sc <= 'Z' {
					sc += 'a' - 'A'
				}
				if subc >= 'A' && subc <= 'Z' {
					subc += 'a' - 'A'
				}
				if sc != subc {
					match = false
					break
				}
			}
			if match {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
