// pkg/docker/compose.go

package docker

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"go.uber.org/zap"
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
		log.Info("Using legacy docker-compose binary")
		return exec.Command("docker-compose", args...), nil
	}
	// Fallback to "docker compose" (as two separate tokens).
	if _, err := exec.LookPath("docker"); err == nil {
		log.Info("Using docker CLI with compose plugin")
		// Prepend "compose" as the first argument.
		newArgs := append([]string{"compose"}, args...)
		return exec.Command("docker", newArgs...), nil
	}
	log.Error("Neither docker-compose binary nor docker compose plugin found in PATH")
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
func ParseComposeFile() ([]byte, error) {
	composeFile, err := FindDockerComposeFile()
	if err != nil {
		return nil, fmt.Errorf("failed to find docker-compose file: %w", err)
	}
	data, err := os.ReadFile(composeFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read docker-compose file: %w", err)
	}
	return data, nil
}
