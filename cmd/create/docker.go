// cmd/create/docker.go

package create

import (
	"fmt"
	"os"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/docker"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/utils"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var CreateDockerCmd = &cobra.Command{
	Use:   "docker",
	Short: "Install Docker and configure it for non-root usage",
	Long:  "Installs Docker CE, sets up repo and user permissions, and verifies with hello-world.",
	RunE: eos.Wrap(func(ctx *eos.RuntimeContext, cmd *cobra.Command, args []string) error {
		// Assume that 'log' is globally defined or available in context.
		utils.RequireRoot(log)

		log.Info("Uninstalling conflicting Docker packages...")
		docker.UninstallConflictingPackages()

		log.Info("Removing Docker snap package...")
		docker.UninstallSnapDocker()

		log.Info("Updating apt repositories...")
		if err := platform.PackageUpdate(false, log); err != nil {
			log.Warn("Package update failed", zap.Error(err))
		}

		log.Info("Installing prerequisites and Docker GPG key...")
		docker.InstallPrerequisitesAndGpg()

		addDockerRepo(log)
		installDocker(log)
		verifyDockerHelloWorld(log, true)
		setupDockerNonRoot(log)
		verifyDockerHelloWorld(log, false)

		log.Info("✅ Docker installation and post-install steps complete.")
		return nil
	}),
}

func addDockerRepo(log *zap.Logger) {
	arch := utils.GetArchitecture()
	codename := utils.GetUbuntuCodename()

	repoLine := fmt.Sprintf(
		"deb [arch=%s signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu %s stable\n",
		arch, codename,
	)
	err := os.WriteFile("/etc/apt/sources.list.d/docker.list", []byte(repoLine), 0644)
	if err != nil {
		// log.Fatal will exit the application if repo file writing fails.
		log.Fatal("Error writing Docker repo file", zap.Error(err))
	}
	if err := execute.Execute("apt-get", "update"); err != nil {
		log.Error("Failed to update apt repositories", zap.Error(err))
		return
	}
}

func installDocker(log *zap.Logger) {
	log.Info("Installing Docker engine and components...")
	packages := []string{
		"docker-ce", "docker-ce-cli", "containerd.io",
		"docker-buildx-plugin", "docker-compose-plugin",
	}
	args := append([]string{"apt", "install", "-y"}, packages...)

	if err := execute.Execute(args[0], args[1:]...); err != nil {
		log.Error("Docker installation failed", zap.Error(err))
	}
}

func verifyDockerHelloWorld(log *zap.Logger, useSudo bool) {
	cmd := []string{"docker", "run", "hello-world"}
	if useSudo {
		cmd = append([]string{"sudo"}, cmd...)
	}
	if err := execute.Execute(cmd[0], cmd[1:]...); err != nil {
		log.Error("'docker run hello-world' failed", zap.Error(err))
	}
}

func setupDockerNonRoot(log *zap.Logger) {
	if err := execute.Execute("groupadd", "docker"); err != nil {
		log.Warn("groupadd failed", zap.Error(err))
	}

	user := os.Getenv("SUDO_USER")
	if user == "" {
		user = os.Getenv("USER")
	}

	if user == "" || user == "root" {
		log.Warn("No non-root user detected; skipping usermod step.")
	} else {
		if err := execute.Execute("usermod", "-aG", "docker", user); err != nil {
			log.Warn("usermod failed", zap.Error(err))
			return
		}
		// Use structured logging instead of fmt.Sprintf-style formatting.
		log.Info("User has been added to the docker group", zap.String("user", user))
	}
	log.Info("Note: Log out and log back in or run 'newgrp docker' to apply group membership.")
}

func init() {
	CreateCmd.AddCommand(CreateDockerCmd)
}
