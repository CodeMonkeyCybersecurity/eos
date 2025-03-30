// cmd/create/docker.go

package create

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/apt"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/docker"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/utils"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var CreateDockerCmd = &cobra.Command{
	Use:   "docker",
	Short: "Install Docker and configure it for non-root usage",
	Long:  "Installs Docker CE, sets up repo and user permissions, and verifies with hello-world.",
	Run: func(cmd *cobra.Command, args []string) {
		log := logger.GetLogger()
		utils.RequireRoot(log)

		log.Info("Uninstalling conflicting Docker packages...")
		docker.UninstallConflictingPackages()

		log.Info("Removing Docker snap package...")
		docker.UninstallSnapDocker()

		log.Info("Updating apt repositories...")
		apt.Update()

		log.Info("Installing prerequisites and Docker GPG key...")
		docker.InstallPrerequisitesAndGpg()

		addDockerRepo(log)
		installDocker(log)
		verifyDockerHelloWorld(true)
		setupDockerNonRoot(log)
		verifyDockerHelloWorld(false)

		log.Info("✅ Docker installation and post-install steps complete.")
	},
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
		log.Fatal("Error writing Docker repo file", zap.Error(err))
	}
	_ = execute.Execute("apt-get", "update")
}

func installDocker(log *zap.Logger) {
	log.Info("Installing Docker engine and components...")
	packages := []string{
		"docker-ce", "docker-ce-cli", "containerd.io",
		"docker-buildx-plugin", "docker-compose-plugin",
	}
	args := append([]string{"apt-get", "install", "-y"}, packages...)
	_ = execute.Execute(args[0], args[1:]...)
}

func verifyDockerHelloWorld(useSudo bool) {
	cmd := []string{"docker", "run", "hello-world"}
	if useSudo {
		cmd = append([]string{"sudo"}, cmd...)
	}
	_ = execute.Execute(cmd[0], cmd[1:]...)
}

func setupDockerNonRoot(log *zap.Logger) {
	_ = execute.Execute("groupadd", "docker")

	user := os.Getenv("SUDO_USER")
	if user == "" {
		user = os.Getenv("USER")
	}

	if user == "" || user == "root" {
		log.Warn("No non-root user detected; skipping usermod step.")
	} else {
		_ = execute.Execute("usermod", "-aG", "docker", user)
		log.Sugar().Infof("User '%s' has been added to the docker group.", user)
	}
	log.Info("Note: Log out and log back in or run 'newgrp docker' to apply group membership.")
}

func init() {
	CreateCmd.AddCommand(CreateDockerCmd)
}
