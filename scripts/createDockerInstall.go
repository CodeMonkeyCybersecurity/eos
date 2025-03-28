package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

func runCommand(cmd []string, check bool, captureOutput bool, inputText string) (string, error) {
	fmt.Printf("Running: %s\n", strings.Join(cmd, " "))
	var command *exec.Cmd
	// If the command is a single string and shell execution is desired, you might use "sh -c" (not needed here).
	command = exec.Command(cmd[0], cmd[1:]...)

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
	if err != nil {
		// Log the error even if check is false.
		log.Printf("Command failed: %v\n", err)
		if check {
			os.Exit(getExitCode(err))
		}
	}
	return output.String(), err
}

// getExitCode extracts the exit code from the error.
func getExitCode(err error) int {
	if exitError, ok := err.(*exec.ExitError); ok {
		// The following works on Unix platforms.
		if status, ok := exitError.Sys().(syscall.WaitStatus); ok {
			return status.ExitStatus()
		}
	}
	return 1
}

func requireRoot() {
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "This script must be run as root (try sudo).")
		os.Exit(1)
	}
}

func uninstallConflictingPackages() {
	packages := []string{
		"docker.io", "docker-doc", "docker-compose", "docker-compose-v2",
		"podman-docker", "containerd", "runc",
	}
	fmt.Println("\nUninstalling conflicting packages...")
	for _, pkg := range packages {
		// Ignore errors if package is not installed.
		_, _ = runCommand([]string{"apt-get", "remove", "-y", pkg}, false, false, "")
	}
}

func uninstallSnapDocker() {
	fmt.Println("\nUninstalling Docker if installed via snap...")
	_, _ = runCommand([]string{"snap", "remove", "docker"}, false, false, "")
}

func updateAptRepos() {
	fmt.Println("\nUpdating apt repositories and cleaning up...")
	_, _ = runCommand([]string{"apt", "update"}, true, false, "")
	_, _ = runCommand([]string{"apt", "autoremove", "--purge", "-y"}, true, false, "")
	_, _ = runCommand([]string{"apt", "autoclean"}, true, false, "")
}

func installPrerequisitesAndGpg() {
	fmt.Println("\nInstalling prerequisites and adding Docker's official GPG key...")
	_, _ = runCommand([]string{"apt-get", "update"}, true, false, "")
	_, _ = runCommand([]string{"apt-get", "install", "-y", "ca-certificates", "curl"}, true, false, "")
	// Create directory /etc/apt/keyrings with mode 0755
	_, _ = runCommand([]string{"install", "-m", "0755", "-d", "/etc/apt/keyrings"}, true, false, "")
	_, _ = runCommand([]string{"curl", "-fsSL", "https://download.docker.com/linux/ubuntu/gpg", "-o", "/etc/apt/keyrings/docker.asc"}, true, false, "")
	_, _ = runCommand([]string{"chmod", "a+r", "/etc/apt/keyrings/docker.asc"}, true, false, "")
}

func getUbuntuCodename() string {
	file, err := os.Open("/etc/os-release")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading /etc/os-release: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var codename string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "UBUNTU_CODENAME=") {
			codename = strings.Trim(strings.SplitN(line, "=", 2)[1], `"`)
			break
		}
		if strings.HasPrefix(line, "VERSION_CODENAME=") && codename == "" {
			codename = strings.Trim(strings.SplitN(line, "=", 2)[1], `"`)
		}
	}
	if codename == "" {
		fmt.Fprintln(os.Stderr, "Could not determine Ubuntu codename.")
		os.Exit(1)
	}
	return codename
}

func getArchitecture() string {
	output, err := runCommand([]string{"dpkg", "--print-architecture"}, true, true, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting architecture: %v\n", err)
		os.Exit(1)
	}
	return strings.TrimSpace(output)
}

func addDockerRepo() {
	fmt.Println("\nAdding Docker repository to Apt sources...")
	arch := getArchitecture()
	codename := getUbuntuCodename()
	repoLine := fmt.Sprintf("deb [arch=%s signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu %s stable\n", arch, codename)
	repoFile := "/etc/apt/sources.list.d/docker.list"
	err := ioutil.WriteFile(repoFile, []byte(repoLine), 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error writing repository file: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Repository added to %s\n", repoFile)
	_, _ = runCommand([]string{"apt-get", "update"}, true, false, "")
}

func installDocker() {
	fmt.Println("\nInstalling the latest Docker packages...")
	packages := []string{
		"docker-ce", "docker-ce-cli", "containerd.io",
		"docker-buildx-plugin", "docker-compose-plugin",
	}
	args := append([]string{"apt-get", "install", "-y"}, packages...)
	_, _ = runCommand(args, true, false, "")
}

func verifyDockerHelloWorld(useSudo bool) {
	fmt.Println("\nVerifying Docker installation by running hello-world...")
	cmd := []string{"docker", "run", "hello-world"}
	if useSudo {
		cmd = append([]string{"sudo"}, cmd...)
	}
	_, _ = runCommand(cmd, true, false, "")
}

func setupDockerNonRoot() {
	fmt.Println("\nRunning Linux post-installation steps to allow Docker as a non-root user...")
	// Try to add the docker group (ignore if it already exists)
	_, _ = runCommand([]string{"groupadd", "docker"}, false, false, "")
	// Determine the non-root user.
	user := os.Getenv("SUDO_USER")
	if user == "" {
		user = os.Getenv("USER")
	}
	if user == "" || user == "root" {
		fmt.Fprintln(os.Stderr, "No non-root user detected; skipping usermod step.")
	} else {
		_, _ = runCommand([]string{"usermod", "-aG", "docker", user}, true, false, "")
		fmt.Printf("User '%s' has been added to the docker group.\n", user)
	}
	fmt.Println("Note: To apply the new group membership, please log out and log back in (or run 'newgrp docker').")
}

func main() {
	requireRoot()

	uninstallConflictingPackages()
	uninstallSnapDocker()
	updateAptRepos()
	installPrerequisitesAndGpg()
	addDockerRepo()
	installDocker()
	verifyDockerHelloWorld(true)
	setupDockerNonRoot()
	// Try to verify Docker without sudo.
	verifyDockerHelloWorld(false)

	fmt.Println("\nDocker installation and post-installation steps complete.")
}
