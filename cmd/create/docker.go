// cmd/create/container.go

package create

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/container"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var CreateDockerCmd = &cobra.Command{
	Use:   "docker",
	Short: "Install Docker and configure it for non-root usage",
	Long:  "Installs Docker CE, sets up repo and user permissions, and verifies with hello-world.",
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		// Assume that 'log' is globally defined or available in context.
		eos_unix.RequireRoot(rc.Ctx)

		otelzap.Ctx(rc.Ctx).Info("Uninstalling conflicting Docker packages...")
		container.UninstallConflictingPackages(rc)

		otelzap.Ctx(rc.Ctx).Info("Removing Docker snap package...")
		container.UninstallSnapDocker(rc)

		otelzap.Ctx(rc.Ctx).Info("Updating apt repositories...")
		if err := platform.PackageUpdate(rc, false); err != nil {
			otelzap.Ctx(rc.Ctx).Warn("Package update failed", zap.Error(err))
		}

		otelzap.Ctx(rc.Ctx).Info("Installing prerequisites and Docker GPG key...")
		container.InstallPrerequisitesAndGpg(rc)

		addDockerRepo(rc)
		installDocker(rc)
		verifyDockerHelloWorld(rc)
		setupDockerNonRoot(rc)
		verifyDockerHelloWorld(rc)

		otelzap.Ctx(rc.Ctx).Info("✅ Docker installation and post-install steps complete.")
		return nil
	}),
}

func addDockerRepo(rc *eos_io.RuntimeContext) {
	arch := eos_unix.GetArchitecture()
	codename := eos_unix.GetUbuntuCodename(rc)

	repoLine := fmt.Sprintf(
		"deb [arch=%s signed-by=/etc/apt/keyrings/container.asc] https://download.container.com/linux/ubuntu %s stable\n",
		arch, codename,
	)
	err := os.WriteFile("/etc/apt/sources.list.d/container.list", []byte(repoLine), 0644)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Fatal("Error writing Docker repo file", zap.Error(err))
	}
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "apt-get",
		Args:    []string{"update"},
	}); err != nil {
		otelzap.Ctx(rc.Ctx).Error("Failed to update apt repositories", zap.Error(err))
	}
}

func installDocker(rc *eos_io.RuntimeContext) {
	otelzap.Ctx(rc.Ctx).Info("Installing Docker engine and components...")
	packages := []string{
		"docker-ce", "docker-ce-cli", "containerd.io",
		"docker-buildx-plugin", "docker-compose-plugin",
	}
	args := append([]string{"install", "-y"}, packages...)

	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "apt",
		Args:    args,
	}); err != nil {
		otelzap.Ctx(rc.Ctx).Error("Docker installation failed", zap.Error(err))
	}
}

func verifyDockerHelloWorld(rc *eos_io.RuntimeContext) {
	cmd := []string{"docker", "run", "hello-world"}
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: cmd[0],
		Args:    cmd[1:],
	}); err != nil {
		otelzap.Ctx(rc.Ctx).Error("'docker run hello-world' failed", zap.Error(err))
	}
}

func setupDockerNonRoot(rc *eos_io.RuntimeContext) {
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "groupadd",
		Args:    []string{"docker"},
	}); err != nil {
		otelzap.Ctx(rc.Ctx).Warn("groupadd failed", zap.Error(err))
	}

	user := os.Getenv("SUDO_USER")
	if user == "" {
		user = os.Getenv("USER")
	}

	if user == "" || user == "root" {
		otelzap.Ctx(rc.Ctx).Warn("No non-root user detected; skipping usermod step.")
	} else {
		if _, err := execute.Run(rc.Ctx, execute.Options{
			Command: "usermod",
			Args:    []string{"-aG", "docker", user},
		}); err != nil {
			otelzap.Ctx(rc.Ctx).Warn("usermod failed", zap.Error(err))
			return
		}
		otelzap.Ctx(rc.Ctx).Info("User has been added to the docker group", zap.String("user", user))
	}

	otelzap.Ctx(rc.Ctx).Info("Note: Log out and log back in or run 'newgrp docker' to apply group membership.")
}

func init() {
	CreateCmd.AddCommand(CreateDockerCmd)
}
