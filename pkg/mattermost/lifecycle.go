// pkg/mattermost/lifecycle.go

package mattermost

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/container"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/git"
	cerr "github.com/cockroachdb/errors"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

const (
	repoURL       = "https://github.com/mattermost/docker"
	CloneDir      = "/opt/mattermost-tmp"
	MattermostDir = "/opt/mattermost" // <- final destination
	envFile       = ".env"
)

// OrchestrateMattermostInstall performs the full setup process for Mattermost.
func OrchestrateMattermostInstall(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)


	// Clean up any pre-existing temp clone dir
	_ = os.RemoveAll(CloneDir)

	// Step 1: Clone into a temp dir
	log.Info("📥 Cloning Mattermost repo to temp dir", zap.String("dir", CloneDir))
	if err := git.Clone(repoURL, CloneDir); err != nil {
		return cerr.Wrap(err, "git clone to temp dir")
	}

	// Ensure the final destination directory exists
	if err := eos_unix.MkdirP(rc.Ctx, MattermostDir, 0o755); err != nil {
		return cerr.Wrap(err, "create target dir")
	}

	// Step 2: Copy files from temp clone dir into final directory
	if err := eos_unix.CopyR(rc.Ctx, CloneDir, MattermostDir); err != nil {
		return cerr.Wrap(err, "copy mattermost clone into target")
	}

	// Step 3: Continue setup as usual
	log.Info("✅ Cloned and copied Mattermost repo", zap.String("target", MattermostDir))

	// Step 4: Patch and provision
	log.Info("⚙️ Patching .env")
	if err := PatchMattermostEnv(MattermostDir); err != nil {
		return cerr.Wrap(err, "patch .env")
	}

	log.Info("🗂️ Creating dirs and setting permissions")
	if err := SetupMattermostDirs(MattermostDir); err != nil {
		return cerr.Wrap(err, "setup dirs")
	}

	log.Info("🐳 Starting containers")
	if err := container.ComposeUpInDir(rc.Ctx, MattermostDir); err != nil {
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
