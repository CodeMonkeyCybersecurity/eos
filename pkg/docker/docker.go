// pkg/docker/docker.go

package docker

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"go.uber.org/zap"
	"gopkg.in/yaml.v2"

	"eos/pkg/config"
	"eos/pkg/execute"
	"eos/pkg/logger"
)

var log = logger.L()

//
//---------------------------- STOP FUNCTIONS ---------------------------- //
//

// StopContainersBySubstring stops all containers whose names contain the given substring.
func StopContainersBySubstring(substring string) error {
	// Run "docker ps" with a filter for the substring.
	out, err := exec.Command("docker", "ps", "--filter", "name="+substring, "--format", "{{.Names}}").Output()
	if err != nil {
		return fmt.Errorf("failed to check container status: %w", err)
	}

	outputStr := strings.TrimSpace(string(out))
	if outputStr == "" {
		log.Info("No containers found matching substring", zap.String("substring", substring))
		return nil
	}

	// Split the output by newline to get each container name.
	containerNames := strings.Split(outputStr, "\n")
	for _, name := range containerNames {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		log.Info("Stopping container", zap.String("container", name))
		stopCmd := exec.Command("docker", "stop", name)
		if output, err := stopCmd.CombinedOutput(); err != nil {
			log.Error("Failed to stop container", zap.String("container", name), zap.Error(err), zap.String("output", string(output)))
		} else {
			log.Info("Container stopped successfully", zap.String("container", name))
		}
	}
	return nil
}

// StopContainer checks if a container with the given name is running, and stops it if it is.
func StopContainer(containerName string) error {
	// Run "docker ps" to check if the container is running.
	out, err := exec.Command("docker", "ps", "--filter", "name="+containerName, "--format", "{{.Names}}").Output()
	if err != nil {
		return fmt.Errorf("failed to check container status: %w", err)
	}

	containerNames := strings.TrimSpace(string(out))
	if containerNames == "" {
		// Container is not running.
		log.Info("Container not running", zap.String("container", containerName))
		return nil
	}

	log.Info("Container is running; stopping container", zap.String("container", containerName))
	// Run "docker stop" on the container.
	stopCmd := exec.Command("docker", "stop", containerName)
	if output, err := stopCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to stop container %s: %s: %w", containerName, string(output), err)
	}

	log.Info("Container stopped successfully", zap.String("container", containerName))
	return nil
}

//
//---------------------------- STOP / START FUNCTIONS ---------------------------- //
//

// StopContainers stops the specified Docker containers.
func StopContainers(containers []string) error {
	args := append([]string{"stop"}, containers...)
	if err := execute.Execute("docker", args...); err != nil {
		return fmt.Errorf("failed to stop containers %v: %w", containers, err)
	}

	log.Info("Containers stopped successfully", zap.Any("containers", containers))
	return nil
}

//
//---------------------------- CONTAINER FUNCTIONS ---------------------------- //
//

// RemoveContainers removes the specified Docker containers.
func RemoveContainers(containers []string) error {
	args := append([]string{"rm"}, containers...)
	if err := execute.Execute("docker", args...); err != nil {
		return fmt.Errorf("failed to remove containers %v: %w", containers, err)
	}
	log.Info("Containers removed successfully", zap.Any("containers", containers))
	return nil
}

//
//---------------------------- IMAGE FUNCTIONS ---------------------------- //
//

// RemoveImages removes the specified Docker images.
// It logs a warning if an image cannot be removed, but continues with the others.
func RemoveImages(images []string) error {
	for _, image := range images {
		if err := execute.Execute("docker", "rmi", image); err != nil {
			log.Warn("Failed to remove image (it might be used elsewhere)", zap.String("image", image), zap.Error(err))
		} else {
			log.Info("Image removed successfully", zap.String("image", image))
		}
	}
	return nil
}

//
//---------------------------- VOLUME FUNCTIONS ---------------------------- //
//

// RemoveVolumes removes the specified Docker volumes.
func RemoveVolumes(volumes []string) error {
	for _, volume := range volumes {
		//  the docker volume rm command.
		if err := execute.Execute("docker", "volume", "rm", volume); err != nil {
			log.Warn("failed to remove volume", zap.String("volume", volume), zap.Error(err))
		} else {
			log.Info("Volume removed successfully", zap.String("volume", volume))
		}
	}
	return nil
}

// BackupVolume backs up a single Docker volume by running a temporary Alpine container.
// It returns the full path to the backup file.
func BackupVolume(volumeName, backupDir string) (string, error) {
	timestamp := time.Now().Format("20060102_150405")
	backupFile := fmt.Sprintf("%s_%s.tar.gz", timestamp, volumeName)

	cmd := []string{
		"run", "--rm",
		"-v", fmt.Sprintf("%s:/volume", volumeName),
		"-v", fmt.Sprintf("%s:/backup", backupDir),
		"alpine",
		"tar", "czf", fmt.Sprintf("/backup/%s", backupFile),
		"-C", "/volume", ".",
	}

	if err := execute.Execute("docker", append([]string{}, cmd...)...); err != nil {
		return "", fmt.Errorf("failed to backup volume %s: %w", volumeName, err)
	}

	return filepath.Join(backupDir, backupFile), nil
}

// BackupVolumes backs up all provided volumes to the specified backupDir.
// It returns a map with volume names as keys and their backup file paths as values.
// If any backup fails, it logs the error but continues processing the remaining volumes.
func BackupVolumes(volumes []string, backupDir string) (map[string]string, error) {
	backupResults := make(map[string]string)

	// Ensure backup directory exists
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return backupResults, fmt.Errorf("failed to create backup directory %s: %w", backupDir, err)
	}

	for _, vol := range volumes {
		log.Info("Backing up volume", zap.String("volume", vol))
		backupFile, err := BackupVolume(vol, backupDir)
		if err != nil {
			log.Error("Error backing up volume", zap.String("volume", vol), zap.Error(err))
		} else {
			log.Info("Volume backup completed", zap.String("volume", vol), zap.String("backupFile", backupFile))
			backupResults[vol] = backupFile
		}
	}
	return backupResults, nil
}

//
//---------------------------- NETWORK FUNCTIONS ---------------------------- //
//

// EnsureArachneNetwork checks if the Docker network "arachne-net" exists.
func EnsureArachneNetwork() error {
	cmd := exec.Command("docker", "network", "inspect", config.DockerNetworkName)
	if err := cmd.Run(); err == nil {
		log.Info("Docker network already exists", zap.String("network", config.DockerNetworkName))
		return nil
	}

	createCmd := exec.Command("docker", "network", "create",
		"--driver", "bridge",
		"--subnet", config.DockerIPv4Subnet,
		"--ipv6",
		"--subnet", config.DockerIPv6Subnet,
		config.DockerNetworkName,
	)

	output, err := createCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to create network %s: %v, output: %s", config.DockerNetworkName, err, output)
	}

	log.Info("Created Docker network", zap.String("network", config.DockerNetworkName))
	return nil
}

//
//---------------------------- COMPOSE YML FUNCTIONS ---------------------------- //
//

// RunDockerComposeService starts a specific service from a docker-compose file
func RunDockerComposeAllServices() error {
	dockerComposePath := "docker-compose.yml" // Always use this file.
	log.Info("Starting all Docker services", zap.String("composeFile", dockerComposePath))

	// Build arguments for the compose command.
	args := []string{"-f", dockerComposePath, "up", "-d"}
	cmd, err := GetDockerComposeCmd(args...)
	if err != nil {
		return err
	}

	output, err := cmd.CombinedOutput()
	fmt.Println(string(output)) // Print logs to console

	if err != nil {
		log.Error("Failed to start Docker services", zap.Error(err), zap.String("output", string(output)))
		return fmt.Errorf("docker-compose up failed: %s", output)
	}

	log.Info("All Docker services started successfully")
	return nil
}

// GetDockerComposeCmd returns an *exec.Cmd for running Docker Compose commands.
// It first checks for "docker-compose". If not found, it falls back to "docker compose".
// The provided args should include the subcommands (e.g. "-f", "docker-compose.yaml", "up", "-d").
func GetDockerComposeCmd(args ...string) (*exec.Cmd, error) {
	// Check for the old docker-compose binary.
	if _, err := exec.LookPath("docker-compose"); err == nil {
		return exec.Command("docker-compose", args...), nil
	}
	// Fallback to "docker compose" (as two separate tokens).
	if _, err := exec.LookPath("docker"); err == nil {
		// Prepend "compose" as the first argument.
		newArgs := append([]string{"compose"}, args...)
		return exec.Command("docker", newArgs...), nil
	}
	return nil, fmt.Errorf("neither docker-compose nor docker CLI with compose plugin found in PATH")
}

func FindDockerComposeFile() (string, error) {
	filesToCheck := []string{
		"docker-compose.yaml",
		"docker-compose.yml",
	}

	for _, file := range filesToCheck {
		if _, err := os.Stat(file); err == nil {
			// Found a file that exists
			return file, nil
		}
	}
	return "", fmt.Errorf("could not find docker-compose.yaml or docker-compose.yml")
}

// ParseComposeFile reads a docker-compose file and returns container names, images, and volumes.
func ParseComposeFile(composePath string) ([]string, []string, []string, error) {
	data, err := os.ReadFile(composePath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read compose file: %w", err)
	}

	var compose config.ComposeFile
	if err := yaml.Unmarshal(data, &compose); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to unmarshal compose file: %w", err)
	}

	var containers, images, volumes []string

	// Extract container names and images
	for key, svc := range compose.Services {
		if svc.ContainerName != "" {
			containers = append(containers, svc.ContainerName)
		} else {
			containers = append(containers, key)
		}
		if svc.Image != "" {
			images = append(images, svc.Image)
		}
	}

	// Extract volumes
	for volName := range compose.Volumes {
		volumes = append(volumes, volName)
	}

	log.Info("Parsed compose file successfully", zap.String("path", composePath),
		zap.Any("containers", containers), zap.Any("images", images), zap.Any("volumes", volumes))

	return containers, images, volumes, nil
}

// CheckDockerContainers runs "docker ps" and logs its output.
// It returns an error if the command fails.
func CheckDockerContainers() error {
	cmd := exec.Command("docker", "ps")
	output, err := cmd.CombinedOutput()

	fmt.Println(string(output)) // Print logs for visibility

	if err != nil {
		return fmt.Errorf("failed to run docker ps: %v, output: %s", err, output)
	}

	log.Info("Docker ps output", zap.String("output", string(output)))
	return nil
}

// UncommentSegment finds the marker (e.g. "uncomment if using Jenkins behind Hecate")
// in the docker compose file ("docker-compose.yml") and uncomments every line (removes a leading '#')
// until reaching the line that contains "# <- finish". It returns an error if something goes wrong.
func UncommentSegment(segmentComment string) error {
	dockerComposePath := "docker-compose.yml" // Always use this file.

	inputFile, err := os.Open(dockerComposePath)
	if err != nil {
		return fmt.Errorf("failed to open file %s: %w", dockerComposePath, err)
	}
	defer inputFile.Close()

	var lines []string
	scanner := bufio.NewScanner(inputFile)
	uncommenting := false

	for scanner.Scan() {
		line := scanner.Text()

		// If the line contains the start marker, start uncommenting.
		if strings.Contains(line, segmentComment) {
			uncommenting = true
		}

		// If the line contains the finish marker, then do not uncomment it; instead, leave it intact
		// (or you can choose to remove it entirely) and stop uncommenting.
		if uncommenting && strings.Contains(line, "<- finish") {
			lines = append(lines, line) // Append finish marker as is.
			uncommenting = false
			continue // Skip further processing for this line.
		}

		// If we are in uncommenting mode, remove a leading '#' if present.
		if uncommenting {
			// Remove only the first '#' after any leading whitespace.
			// We can use a simple regex here to ensure we preserve indentation and any dash.
			re := regexp.MustCompile(`^(\s*)#\s*(.*)$`)
			if re.MatchString(line) {
				line = re.ReplaceAllString(line, "$1$2")
			}
		}

		lines = append(lines, line)
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading file %s: %w", dockerComposePath, err)
	}

	outputFile, err := os.Create(dockerComposePath)
	if err != nil {
		return fmt.Errorf("failed to open file for writing %s: %w", dockerComposePath, err)
	}
	defer outputFile.Close()

	for _, l := range lines {
		_, _ = fmt.Fprintln(outputFile, l)
	}

	return nil
}
