// cmd/create/docker.go

package create

import (
	"fmt"
	"os"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eosio"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/docker"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var CreateDockerCmd = &cobra.Command{
	Use:   "docker",
	Short: "Install Docker and configure it for non-root usage",
	Long:  "Installs Docker CE, sets up repo and user permissions, and verifies with hello-world.",
	RunE: eos.Wrap(func(ctx *eosio.RuntimeContext, cmd *cobra.Command, args []string) error {
		// Assume that 'log' is globally defined or available in context.
		system.RequireRoot()

		zap.L().Info("Uninstalling conflicting Docker packages...")
		docker.UninstallConflictingPackages()

		zap.L().Info("Removing Docker snap package...")
		docker.UninstallSnapDocker()

		zap.L().Info("Updating apt repositories...")
		if err := platform.PackageUpdate(false); err != nil {
			zap.L().Warn("Package update failed", zap.Error(err))
		}

		zap.L().Info("Installing prerequisites and Docker GPG key...")
		docker.InstallPrerequisitesAndGpg()

		addDockerRepo()
		installDocker()
		verifyDockerHelloWorld(true)
		setupDockerNonRoot()
		verifyDockerHelloWorld(false)

		zap.L().Info("✅ Docker installation and post-install steps complete.")
		return nil
	}),
}

func addDockerRepo() {
	arch := system.GetArchitecture()
	codename := system.GetUbuntuCodename()

	repoLine := fmt.Sprintf(
		"deb [arch=%s signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu %s stable\n",
		arch, codename,
	)
	err := os.WriteFile("/etc/apt/sources.list.d/docker.list", []byte(repoLine), 0644)
	if err != nil {
		// zap.L().Fatal will exit the application if repo file writing fails.
		zap.L().Fatal("Error writing Docker repo file", zap.Error(err))
	}
	if err := execute.Execute("apt-get", "update"); err != nil {
		zap.L().Error("Failed to update apt repositories", zap.Error(err))
		return
	}
}

func installDocker() {
	zap.L().Info("Installing Docker engine and components...")
	packages := []string{
		"docker-ce", "docker-ce-cli", "containerd.io",
		"docker-buildx-plugin", "docker-compose-plugin",
	}
	args := append([]string{"apt", "install", "-y"}, packages...)

	if err := execute.Execute(args[0], args[1:]...); err != nil {
		zap.L().Error("Docker installation failed", zap.Error(err))
	}
}

func verifyDockerHelloWorld(useSudo bool) {
	cmd := []string{"docker", "run", "hello-world"}
	if useSudo {
		cmd = append([]string{}, cmd...)
	}
	if err := execute.Execute(cmd[0], cmd[1:]...); err != nil {
		zap.L().Error("'docker run hello-world' failed", zap.Error(err))
	}
}

func setupDockerNonRoot() {
	if err := execute.Execute("groupadd", "docker"); err != nil {
		zap.L().Warn("groupadd failed", zap.Error(err))
	}

	user := os.Getenv("SUDO_USER")
	if user == "" {
		user = os.Getenv("USER")
	}

	if user == "" || user == "root" {
		zap.L().Warn("No non-root user detected; skipping usermod step.")
	} else {
		if err := execute.Execute("usermod", "-aG", "docker", user); err != nil {
			zap.L().Warn("usermod failed", zap.Error(err))
			return
		}
		// Use structured logging instead of fmt.Sprintf-style formatting.
		zap.L().Info("User has been added to the docker group", zap.String("user", user))
	}
	zap.L().Info("Note: Log out and log back in or run 'newgrp docker' to apply group membership.")
}

func init() {
	CreateCmd.AddCommand(CreateDockerCmd)
}
