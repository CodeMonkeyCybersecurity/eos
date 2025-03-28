// pkg/docker/compose.go

package docker

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

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

//
//---------------------------- COMPOSE YML FUNCTIONS ---------------------------- //
//

// RunDockerComposeService starts a specific service from a docker-compose file
// RunDockerComposeAllServices starts a specific service from a docker-compose file.
func RunDockerComposeAllServices(composeFile, service string) error {

	// Build arguments for the compose command.
	args := []string{"-f", composeFile, "up", "-d"}
	cmd, err := GetDockerComposeCmd(args...)
	if err != nil {
		return err
	}

	output, err := cmd.CombinedOutput()
	fmt.Println(string(output)) // Print logs to console

	if err != nil {
		return fmt.Errorf("docker-compose up failed: %s", output)
	}

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

// ParseComposeFile attempts to read and parse the docker-compose file.
// It returns the file contents as a byte slice.
func ParseComposeFile(composePath string) ([]byte, error) {
	data, err := os.ReadFile(composePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", composePath, err)
	}
	return data, nil
}

// ExtractComposeMetadata is a stub function that simulates parsing docker-compose metadata.
// You can replace this with real YAML parsing later.
func ExtractComposeMetadata(data []byte) ([]string, []string, []string) {
	// Example dummy data for testing
	containers := []string{"app", "db"}
	images := []string{"ghcr.io/example/app", "postgres:15-alpine"}
	volumes := []string{"app_data", "db_data"}

	return containers, images, volumes
}
