// cmd/deploy/docker.go

package deploy

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var DockerCmd = &cobra.Command{
	Use:   "docker",
	Short: "Install Docker and configure it for non-root usage",
	Run: func(cmd *cobra.Command, args []string) {
		log := logger.GetLogger()
		requireRoot()

		uninstallConflictingPackages(log)
		uninstallSnapDocker(log)
		updateAptRepos(log)
		installPrerequisitesAndGpg(log)
		addDockerRepo(log)
		installDocker(log)
		verifyDockerHelloWorld(true, log)
		setupDockerNonRoot(log)
		verifyDockerHelloWorld(false, log)

		log.Info("✅ Docker installation and post-install steps complete.")
	},
}

// Helper functions...

func runCommand(cmd []string, check, captureOutput bool, inputText string, log *zap.Logger) (string, error) {
	log.Sugar().Infof("Running: %s", strings.Join(cmd, " "))
	command := exec.Command(cmd[0], cmd[1:]...)

	if inputText != "" {
		command.Stdin = strings.NewReader(inputText)
	}
	var output bytes.Buffer
	if captureOutput {
		command.Stdout = &output
		command.Stderr = &output
	} else {
		command.Stdout = os.Stdout
		command.Stderr = os.Stderr
	}

	err := command.Run()
	if err != nil && check {
		log.Sugar().Errorf("Command failed: %v", err)
		os.Exit(getExitCode(err))
	}
	return output.String(), err
}

func getExitCode(err error) int {
	if exitError, ok := err.(*exec.ExitError); ok {
		if status, ok := exitError.Sys().(syscall.WaitStatus); ok {
			return status.ExitStatus()
		}
	}
	return 1
}

func requireRoot() {
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "❌ This command must be run as root (try sudo).")
		os.Exit(1)
	}
}

func uninstallConflictingPackages(log *zap.Logger) {
	packages := []string{"docker.io", "docker-doc", "docker-compose", "docker-compose-v2", "podman-docker", "containerd", "runc"}
	log.Info("Uninstalling conflicting packages...")
	for _, pkg := range packages {
		_, _ = runCommand([]string{"apt-get", "remove", "-y", pkg}, false, false, "", log)
	}
}

func uninstallSnapDocker(log *zap.Logger) {
	log.Info("Removing Docker installed via Snap...")
	_, _ = runCommand([]string{"snap", "remove", "docker"}, false, false, "", log)
}

func updateAptRepos(log *zap.Logger) {
	log.Info("Updating apt repositories...")
	_, _ = runCommand([]string{"apt", "update"}, true, false, "", log)
	_, _ = runCommand([]string{"apt", "autoremove", "--purge", "-y"}, true, false, "", log)
	_, _ = runCommand([]string{"apt", "autoclean"}, true, false, "", log)
}

func installPrerequisitesAndGpg(log *zap.Logger) {
	log.Info("Installing prerequisites and adding Docker GPG key...")
	_, _ = runCommand([]string{"apt-get", "install", "-y", "ca-certificates", "curl"}, true, false, "", log)
	_, _ = runCommand([]string{"install", "-m", "0755", "-d", "/etc/apt/keyrings"}, true, false, "", log)
	_, _ = runCommand([]string{"curl", "-fsSL", "https://download.docker.com/linux/ubuntu/gpg", "-o", "/etc/apt/keyrings/docker.asc"}, true, false, "", log)
	_, _ = runCommand([]string{"chmod", "a+r", "/etc/apt/keyrings/docker.asc"}, true, false, "", log)
}

func getUbuntuCodename() string {
	file, _ := os.Open("/etc/os-release")
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var codename string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "UBUNTU_CODENAME=") {
			codename = strings.TrimPrefix(line, "UBUNTU_CODENAME=")
			break
		}
		if strings.HasPrefix(line, "VERSION_CODENAME=") && codename == "" {
			codename = strings.TrimPrefix(line, "VERSION_CODENAME=")
		}
	}
	if codename == "" {
		fmt.Fprintln(os.Stderr, "Could not determine Ubuntu codename.")
		os.Exit(1)
	}
	return codename
}

func getArchitecture(log *zap.Logger) string {
	out, _ := runCommand([]string{"dpkg", "--print-architecture"}, true, true, "", log)
	return strings.TrimSpace(out)
}

func addDockerRepo(log *zap.Logger) {
	arch := getArchitecture(log)
	codename := getUbuntuCodename()
	repoLine := fmt.Sprintf("deb [arch=%s signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu %s stable\n", arch, codename)
	err := os.WriteFile("/etc/apt/sources.list.d/docker.list", []byte(repoLine), 0644)
	if err != nil {
		log.Fatal("Error writing Docker repo file", zap.Error(err))
	}
	_, _ = runCommand([]string{"apt-get", "update"}, true, false, "", log)
}

func installDocker(log *zap.Logger) {
	log.Info("Installing Docker engine and components...")
	packages := []string{
		"docker-ce", "docker-ce-cli", "containerd.io",
		"docker-buildx-plugin", "docker-compose-plugin",
	}
	args := append([]string{"apt-get", "install", "-y"}, packages...)
	_, _ = runCommand(args, true, false, "", log)
}

func verifyDockerHelloWorld(useSudo bool, log *zap.Logger) {
	cmd := []string{"docker", "run", "hello-world"}
	if useSudo {
		cmd = append([]string{"sudo"}, cmd...)
	}
	_, _ = runCommand(cmd, true, false, "", log)
}

func setupDockerNonRoot(log *zap.Logger) {
	_, _ = runCommand([]string{"groupadd", "docker"}, false, false, "", log)

	user := os.Getenv("SUDO_USER")
	if user == "" {
		user = os.Getenv("USER")
	}
	if user == "" || user == "root" {
		log.Warn("No non-root user detected; skipping usermod step.")
	} else {
		_, _ = runCommand([]string{"usermod", "-aG", "docker", user}, true, false, "", log)
		log.Sugar().Infof("User '%s' has been added to the docker group.", user)
	}
	log.Info("Note: Log out and log back in or run 'newgrp docker' to apply group membership.")
}
