// cmd/create/container.go

package create

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/container"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var CreateDockerCmd = &cobra.Command{
	Use:   "docker",
	Short: "Install Docker and configure it for non-root usage",
	Long:  "Installs Docker CE, sets up repo and user permissions, and verifies with hello-world.",
	RunE: eos.Wrap(func(ctx *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		// Assume that 'log' is globally defined or available in context.
		eos_unix.RequireRoot()

		zap.L().Info("Uninstalling conflicting Docker packages...")
		container.UninstallConflictingPackages()

		zap.L().Info("Removing Docker snap package...")
		container.UninstallSnapDocker()

		zap.L().Info("Updating apt repositories...")
		if err := platform.PackageUpdate(false); err != nil {
			zap.L().Warn("Package update failed", zap.Error(err))
		}

		zap.L().Info("Installing prerequisites and Docker GPG key...")
		container.InstallPrerequisitesAndGpg()

		addDockerRepo()
		installDocker()
		verifyDockerHelloWorld()
		setupDockerNonRoot()
		verifyDockerHelloWorld()

		zap.L().Info("✅ Docker installation and post-install steps complete.")
		return nil
	}),
}

func addDockerRepo() {
	arch := eos_unix.GetArchitecture()
	codename := eos_unix.GetUbuntuCodename()

	repoLine := fmt.Sprintf(
		"deb [arch=%s signed-by=/etc/apt/keyrings/container.asc] https://download.container.com/linux/ubuntu %s stable\n",
		arch, codename,
	)
	err := os.WriteFile("/etc/apt/sources.list.d/container.list", []byte(repoLine), 0644)
	if err != nil {
		zap.L().Fatal("Error writing Docker repo file", zap.Error(err))
	}
	if _, err := execute.Run(execute.Options{
		Command: "apt-get",
		Args:    []string{"update"},
	}); err != nil {
		zap.L().Error("Failed to update apt repositories", zap.Error(err))
	}
}

func installDocker() {
	zap.L().Info("Installing Docker engine and components...")
	packages := []string{
		"docker-ce", "docker-ce-cli", "containerd.io",
		"docker-buildx-plugin", "docker-compose-plugin",
	}
	args := append([]string{"install", "-y"}, packages...)

	if _, err := execute.Run(execute.Options{
		Command: "apt",
		Args:    args,
	}); err != nil {
		zap.L().Error("Docker installation failed", zap.Error(err))
	}
}

func verifyDockerHelloWorld() {
	cmd := []string{"docker", "run", "hello-world"}
	if _, err := execute.Run(execute.Options{
		Command: cmd[0],
		Args:    cmd[1:],
	}); err != nil {
		zap.L().Error("'docker run hello-world' failed", zap.Error(err))
	}
}

func setupDockerNonRoot() {
	if _, err := execute.Run(execute.Options{
		Command: "groupadd",
		Args:    []string{"docker"},
	}); err != nil {
		zap.L().Warn("groupadd failed", zap.Error(err))
	}

	user := os.Getenv("SUDO_USER")
	if user == "" {
		user = os.Getenv("USER")
	}

	if user == "" || user == "root" {
		zap.L().Warn("No non-root user detected; skipping usermod step.")
	} else {
		if _, err := execute.Run(execute.Options{
			Command: "usermod",
			Args:    []string{"-aG", "docker", user},
		}); err != nil {
			zap.L().Warn("usermod failed", zap.Error(err))
			return
		}
		zap.L().Info("User has been added to the docker group", zap.String("user", user))
	}

	zap.L().Info("Note: Log out and log back in or run 'newgrp docker' to apply group membership.")
}

func init() {
	CreateCmd.AddCommand(CreateDockerCmd)
}
