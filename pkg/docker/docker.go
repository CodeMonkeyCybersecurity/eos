// pkg/docker/docker.go

package docker

import "github.com/CodeMonkeyCybersecurity/eos/pkg/execute"

// RunDockerAction wraps `docker <action> <args...>`
func RunDockerAction(action string, args ...string) error {
	fullArgs := append([]string{action}, args...)
	return execute.Execute("docker", fullArgs...)
}

// UninstallConflictingPackages removes any preinstalled Docker versions or conflicts
func UninstallConflictingPackages() {
	packages := []string{
		"docker.io", "docker-doc", "docker-compose", "docker-compose-v2",
		"podman-docker", "containerd", "runc",
	}
	for _, pkg := range packages {
		_ = execute.Execute("apt-get", "remove", "-y", pkg)
	}
}

// UninstallSnapDocker removes the Snap version of Docker
func UninstallSnapDocker() {
	_ = execute.Execute("snap", "remove", "docker")
}

// InstallPrerequisitesAndGpg sets up apt and Docker GPG keys
func InstallPrerequisitesAndGpg() {
	_ = execute.Execute("apt-get", "install", "-y", "ca-certificates", "curl")
	_ = execute.Execute("install", "-m", "0755", "-d", "/etc/apt/keyrings")
	_ = execute.Execute("curl", "-fsSL", "https://download.docker.com/linux/ubuntu/gpg", "-o", "/etc/apt/keyrings/docker.asc")
	_ = execute.Execute("chmod", "a+r", "/etc/apt/keyrings/docker.asc")
}
