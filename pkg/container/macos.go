// pkg/docker/macos.go

package container

import (
	"os"
	"os/exec"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	crerr "github.com/cockroachdb/errors"
	"go.uber.org/zap"
)

func IsDockerRunning() bool {
	cmd := exec.Command("docker", "info")
	return cmd.Run() == nil
}

// CheckAndInstallDockerIfNeeded ensures Docker is installed and running, or prompts the user to install it.
func CheckAndInstallDockerIfNeeded() error {
	log := zap.L()

	// 1. Ensure Homebrew is present
	if !platform.IsCommandAvailable("brew") {
		log.Warn("Homebrew is not installed. Cannot install Docker automatically.")
		return crerr.New("Homebrew is required to install container. Visit https://brew.sh to install it.")
	}

	// 2. Check Docker availability
	if platform.IsCommandAvailable("docker") && IsDockerRunning() {
		log.Info("✅ Docker is installed and running.")
		return nil
	}

	log.Warn("❌ Docker is not installed or not running.")

	// 3. Prompt user for installation
	shouldInstall := interaction.PromptYesNo("Docker Desktop is required but not running. Install it now?", true)
	if !shouldInstall {
		return crerr.WithHint(
			crerr.New("Docker is required but not installed"),
			"Please install Docker Desktop from https://www.container.com/products/docker-desktop or via `brew install --cask docker`.",
		)
	}

	log.Info("📦 Installing Docker Desktop using Homebrew...")
	cmd := exec.Command("brew", "install", "--cask", "docker")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		log.Error("❌ Docker installation failed", zap.Error(err))
		return crerr.WithHint(
			crerr.Wrap(err, "failed to install Docker Desktop via Homebrew"),
			"Try running the installation manually: `brew install --cask docker`",
		)
	}

	// 4. Docker installed, but still needs to be started
	log.Info("✅ Docker Desktop installed successfully.")
	log.Warn("⚠️ Docker Desktop must be started manually to proceed.")

	return crerr.New("Docker is installed but not yet running. Please start Docker Desktop and re-run this command.")
}
