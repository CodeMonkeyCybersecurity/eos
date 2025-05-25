// pkg/docker/container.go

package container

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"go.uber.org/zap"
)

// RunDockerAction wraps `docker <action> <args...>`
func RunDockerAction(action string, args ...string) error {
	fullArgs := append([]string{action}, args...)
	_, err := execute.Run(execute.Options{
		Command: "docker",
		Args:    fullArgs,
	})
	return err
}

// UninstallConflictingPackages removes any preinstalled Docker versions or conflicts
func UninstallConflictingPackages() {
	packages := []string{
		"container.io", "docker-doc", "docker-compose", "docker-compose-v2",
		"podman-docker", "containerd", "runc",
	}
	for _, pkg := range packages {
		if err := execute.RunSimple("apt-get", "remove", "-y", pkg); err != nil {
			zap.L().Warn("Failed to remove conflicting package", zap.String("package", pkg), zap.Error(err))
		}
	}
}

// UninstallSnapDocker removes the Snap version of Docker
func UninstallSnapDocker() {
	if err := execute.RunSimple("snap", "remove", "docker"); err != nil {
		zap.L().Warn("Failed to remove Snap Docker", zap.Error(err))
	}
}

// InstallPrerequisitesAndGpg sets up apt and Docker GPG keys
func InstallPrerequisitesAndGpg() {
	steps := []execute.Options{
		{Command: "apt-get", Args: []string{"install", "-y", "ca-certificates", "curl"}},
		{Command: "install", Args: []string{"-m", "0755", "-d", "/etc/apt/keyrings"}},
		{Command: "curl", Args: []string{"-fsSL", "https://download.container.com/linux/ubuntu/gpg", "-o", "/etc/apt/keyrings/container.asc"}},
		{Command: "chmod", Args: []string{"a+r", "/etc/apt/keyrings/container.asc"}},
	}
	for _, step := range steps {
		if _, err := execute.Run(step); err != nil {
			zap.L().Warn("Step failed", zap.String("cmd", step.Command), zap.Error(err))
		}
	}
}
