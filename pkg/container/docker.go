// pkg/docker/container.go

package container

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// RunDockerAction wraps `docker <action> <args...>`
func RunDockerAction(rc *eos_io.RuntimeContext, action string, args ...string) error {
	fullArgs := append([]string{action}, args...)
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    fullArgs,
	})
	return err
}

// UninstallConflictingPackages removes any preinstalled Docker versions or conflicts
func UninstallConflictingPackages(rc *eos_io.RuntimeContext) {
	packages := []string{
		"container.io", "docker-doc", "docker-compose", "docker-compose-v2",
		"podman-docker", "containerd", "runc",
	}
	for _, pkg := range packages {
		if err := execute.RunSimple(rc.Ctx, "apt-get", "remove", "-y", pkg); err != nil {
			otelzap.Ctx(rc.Ctx).Warn("Failed to remove conflicting package", zap.String("package", pkg), zap.Error(err))
		}
	}
}

// UninstallSnapDocker removes the Snap version of Docker
func UninstallSnapDocker(rc *eos_io.RuntimeContext) {
	if err := execute.RunSimple(rc.Ctx, "snap", "remove", "docker"); err != nil {
		otelzap.Ctx(rc.Ctx).Warn("Failed to remove Snap Docker", zap.Error(err))
	}
}

// InstallPrerequisitesAndGpg sets up apt and Docker GPG keys
func InstallPrerequisitesAndGpg(rc *eos_io.RuntimeContext) {
	steps := []execute.Options{
		{Command: "apt-get", Args: []string{"install", "-y", "ca-certificates", "curl"}},
		{Command: "install", Args: []string{"-m", "0755", "-d", "/etc/apt/keyrings"}},
		{Command: "curl", Args: []string{"-fsSL", "https://download.container.com/linux/ubuntu/gpg", "-o", "/etc/apt/keyrings/container.asc"}},
		{Command: "chmod", Args: []string{"a+r", "/etc/apt/keyrings/container.asc"}},
	}
	for _, step := range steps {
		if _, err := execute.Run(rc.Ctx, step); err != nil {
			otelzap.Ctx(rc.Ctx).Warn("Step failed", zap.String("cmd", step.Command), zap.Error(err))
		}
	}
}
