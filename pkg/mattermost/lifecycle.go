// pkg/mattermost/lifecycle.go

package mattermost

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/container"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/git"
	cerr "github.com/cockroachdb/errors"
	"go.uber.org/zap"
)

const (
	repoURL     = "https://github.com/mattermost/docker"
	cloneTarget = "/opt/mattermost-docker"
	envFile     = ".env"
)

// OrchestrateMattermostInstall performs the full setup process for Mattermost.
func OrchestrateMattermostInstall(rc *eos_io.RuntimeContext) error {
	log := rc.Log.With(zap.String("component", "mattermost"))

	log.Info("📥 Cloning Mattermost Docker repo")
	if _, err := os.Stat(filepath.Join(cloneTarget, ".git")); os.IsNotExist(err) {
		if err := git.Clone(repoURL, cloneTarget); err != nil {
			return cerr.Wrap(err, "git clone mattermost repo")
		}
	}

	log.Info("⚙️ Patching .env")
	if err := PatchMattermostEnv(cloneTarget); err != nil {
		return cerr.Wrap(err, "patch .env")
	}

	log.Info("🗂️ Creating dirs and setting permissions")
	if err := SetupMattermostDirs(cloneTarget); err != nil {
		return cerr.Wrap(err, "setup dirs")
	}

	log.Info("🐳 Starting containers")
	if err := container.ComposeUpInDir(rc.Ctx, cloneTarget); err != nil {
		return cerr.Wrap(err, "docker compose up")
	}

	log.Info("✅ Done")
	return nil
}

// SetupMattermostDirs creates necessary volume directories and sets permissions.
func SetupMattermostDirs(cloneDir string) error {
	base := filepath.Join(cloneDir, "volumes", "app", "mattermost")
	for _, sub := range DirNames {
		if err := os.MkdirAll(filepath.Join(base, sub), 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", sub, err)
		}
	}
	if out, err := exec.Command("chown", "-R", "2000:2000", base).CombinedOutput(); err != nil {
		return fmt.Errorf("chown: %v (%s)", err, out)
	}
	return nil
}

func CloneMattermostRepo(targetDir, repoURL string) error {
	// More robust check: path must contain a valid .git directory
	if _, err := os.Stat(filepath.Join(targetDir, ".git")); err == nil {
		return nil // Repo already present
	}

	if err := git.Clone(repoURL, targetDir); err != nil {
		return cerr.Wrap(err, "git clone failed")
	}

	return nil
}
