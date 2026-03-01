// pkg/git/verification_test.go
//
// Tests for git remote verification and commit signature checks.
// Unit tests verify the wiring between pkg/constants and pkg/git.

package git

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"go.uber.org/zap/zaptest"
)

// newTestRC creates a minimal RuntimeContext for tests.
func newTestRC(t *testing.T) *eos_io.RuntimeContext {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return &eos_io.RuntimeContext{
		Ctx:        ctx,
		Log:        zaptest.NewLogger(t),
		Timestamp:  time.Now(),
		Component:  "test",
		Command:    "test",
		Attributes: make(map[string]string),
	}
}

// initTestRepo creates a temporary git repository with a given remote URL.
func initTestRepo(t *testing.T, remoteURL string) string {
	t.Helper()
	dir := t.TempDir()

	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(),
			"GIT_CONFIG_NOSYSTEM=1",
			"HOME="+dir,
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, out)
		}
	}

	run("init")
	run("config", "user.email", "test@example.com")
	run("config", "user.name", "Test")
	run("remote", "add", "origin", remoteURL)

	// Create initial commit so HEAD exists
	readme := filepath.Join(dir, "README.md")
	if err := os.WriteFile(readme, []byte("test"), 0644); err != nil {
		t.Fatal(err)
	}
	run("add", "README.md")
	run("commit", "-m", "init")

	return dir
}

// --- Unit tests: VerifyTrustedRemote ---

func TestVerifyTrustedRemote_GiteaHTTPS(t *testing.T) {
	rc := newTestRC(t)
	dir := initTestRepo(t, "https://gitea.cybermonkey.sh/cybermonkey/eos.git")

	if err := VerifyTrustedRemote(rc, dir); err != nil {
		t.Errorf("expected trusted, got error: %v", err)
	}
}

func TestVerifyTrustedRemote_GiteaSSH(t *testing.T) {
	rc := newTestRC(t)
	dir := initTestRepo(t, "ssh://git@gitea.cybermonkey.sh:9001/cybermonkey/eos.git")

	if err := VerifyTrustedRemote(rc, dir); err != nil {
		t.Errorf("expected trusted, got error: %v", err)
	}
}

func TestVerifyTrustedRemote_GitHubHTTPS(t *testing.T) {
	rc := newTestRC(t)
	dir := initTestRepo(t, "https://github.com/CodeMonkeyCybersecurity/eos.git")

	if err := VerifyTrustedRemote(rc, dir); err != nil {
		t.Errorf("expected trusted, got error: %v", err)
	}
}

func TestVerifyTrustedRemote_GitHubSCP(t *testing.T) {
	rc := newTestRC(t)
	dir := initTestRepo(t, "git@github.com:CodeMonkeyCybersecurity/eos.git")

	if err := VerifyTrustedRemote(rc, dir); err != nil {
		t.Errorf("expected trusted, got error: %v", err)
	}
}

func TestVerifyTrustedRemote_Untrusted(t *testing.T) {
	rc := newTestRC(t)
	dir := initTestRepo(t, "https://evil.com/malicious/eos.git")

	err := VerifyTrustedRemote(rc, dir)
	if err == nil {
		t.Fatal("expected error for untrusted remote, got nil")
	}

	errMsg := err.Error()
	if !strings.Contains(errMsg, "SECURITY VIOLATION") {
		t.Errorf("error should mention SECURITY VIOLATION, got: %s", errMsg)
	}
	if !strings.Contains(errMsg, "evil.com") {
		t.Errorf("error should show the untrusted remote URL, got: %s", errMsg)
	}
	// Verify error suggests the canonical Gitea remote, not GitHub
	if !strings.Contains(errMsg, "gitea.cybermonkey.sh") {
		t.Errorf("error remediation should suggest gitea.cybermonkey.sh, got: %s", errMsg)
	}
}

func TestVerifyTrustedRemote_NotARepo(t *testing.T) {
	rc := newTestRC(t)
	dir := t.TempDir() // no git init

	err := VerifyTrustedRemote(rc, dir)
	if err == nil {
		t.Fatal("expected error for non-repo directory")
	}
	if !strings.Contains(err.Error(), "failed to get git remote") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestVerifyTrustedRemote_WithoutDotGit(t *testing.T) {
	rc := newTestRC(t)
	// Remote URL without .git suffix should still be trusted
	dir := initTestRepo(t, "https://gitea.cybermonkey.sh/cybermonkey/eos")

	if err := VerifyTrustedRemote(rc, dir); err != nil {
		t.Errorf("expected trusted (no .git suffix), got error: %v", err)
	}
}

// --- Integration tests: CheckRepositoryState + VerifyTrustedRemote ---

func TestCheckRepositoryState_WithTrustedRemote(t *testing.T) {
	rc := newTestRC(t)
	dir := initTestRepo(t, "https://gitea.cybermonkey.sh/cybermonkey/eos.git")

	state, err := CheckRepositoryState(rc, dir)
	if err != nil {
		t.Fatalf("CheckRepositoryState failed: %v", err)
	}

	if !state.IsRepository {
		t.Error("expected IsRepository=true")
	}
	if state.RemoteURL != "https://gitea.cybermonkey.sh/cybermonkey/eos.git" {
		t.Errorf("unexpected remote: %s", state.RemoteURL)
	}
	if state.CurrentCommit == "" {
		t.Error("expected non-empty CurrentCommit")
	}

	// Now verify the remote is trusted
	if err := VerifyTrustedRemote(rc, dir); err != nil {
		t.Errorf("expected trusted remote, got: %v", err)
	}
}

// --- Table test for all known real remotes ---

func TestVerifyTrustedRemote_AllKnownRemotes(t *testing.T) {
	knownTrusted := []string{
		"https://gitea.cybermonkey.sh/cybermonkey/eos.git",
		"https://gitea.cybermonkey.sh/cybermonkey/eos",
		"ssh://git@gitea.cybermonkey.sh:9001/cybermonkey/eos.git",
		"ssh://git@gitea.cybermonkey.sh/cybermonkey/eos.git",
		"git@gitea.cybermonkey.sh:cybermonkey/eos.git",
		"https://github.com/CodeMonkeyCybersecurity/eos.git",
		"https://github.com/CodeMonkeyCybersecurity/eos",
		"git@github.com:CodeMonkeyCybersecurity/eos.git",
	}

	rc := newTestRC(t)
	for _, remote := range knownTrusted {
		t.Run(remote, func(t *testing.T) {
			dir := initTestRepo(t, remote)
			if err := VerifyTrustedRemote(rc, dir); err != nil {
				t.Errorf("expected trusted for %q, got error: %v", remote, err)
			}
		})
	}
}
