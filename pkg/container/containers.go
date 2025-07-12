// pkg/docker/containers.go

package container

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
)

//
//---------------------------- STOP FUNCTIONS ---------------------------- //
//

// validateContainerName validates that a container name/substring is safe for shell commands
func validateContainerName(name string) error {
	if name == "" {
		return fmt.Errorf("container name cannot be empty")
	}
	
	// Check for shell metacharacters that could be used for injection
	// Allow alphanumeric, hyphens, underscores, dots (valid container name chars)
	if matched, _ := regexp.MatchString(`[^a-zA-Z0-9._-]`, name); matched {
		return fmt.Errorf("container name contains forbidden characters")
	}
	
	// Check length to prevent DoS
	if len(name) > 253 {
		return fmt.Errorf("container name too long (max 253 characters)")
	}
	
	return nil
}

func StopContainersBySubstring(rc *eos_io.RuntimeContext, substring string) error {
	// Validate input to prevent command injection
	if err := validateContainerName(substring); err != nil {
		return fmt.Errorf("invalid container substring: %w", err)
	}
	out, err := exec.Command("docker", "ps", "--filter", "name="+substring, "--format", "{{.Names}}").Output()
	if err != nil {
		return fmt.Errorf("failed to check container status: %w", err)
	}

	names := strings.Fields(string(out))
	for _, name := range names {
		if name == "" {
			continue
		}
		err := execute.RunSimple(rc.Ctx, "docker", "stop", name)
		if err != nil {
			fmt.Printf("failed to stop container %s: %v\n", name, err)
		}
	}
	return nil
}

func StopContainer(rc *eos_io.RuntimeContext, containerName string) error {
	// Validate input to prevent command injection
	if err := validateContainerName(containerName); err != nil {
		return fmt.Errorf("invalid container name: %w", err)
	}
	
	out, err := exec.Command("docker", "ps", "--filter", "name="+containerName, "--format", "{{.Names}}").Output()
	if err != nil {
		return fmt.Errorf("failed to check container status: %w", err)
	}

	if strings.TrimSpace(string(out)) == "" {
		return nil
	}

	err = execute.RunSimple(rc.Ctx, "docker", "stop", containerName)
	if err != nil {
		return fmt.Errorf("failed to stop container %s: %w", containerName, err)
	}
	return nil
}

func StopContainers(rc *eos_io.RuntimeContext, containers []string) error {
	args := append([]string{"stop"}, containers...)
	err := execute.RunSimple(rc.Ctx, "docker", args...)
	if err != nil {
		return fmt.Errorf("failed to stop containers %v: %w", containers, err)
	}
	return nil
}

func RemoveContainers(rc *eos_io.RuntimeContext, containers []string) error {
	args := append([]string{"rm"}, containers...)
	err := execute.RunSimple(rc.Ctx, "docker", args...)
	if err != nil {
		return fmt.Errorf("failed to remove containers %v: %w", containers, err)
	}
	return nil
}

func ListDefaultContainers() error {
	cmd := exec.Command("docker", "ps", "--format", "{{.ID}}\t{{.Image}}\t{{.Names}}")
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to list containers: %w", err)
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) == 0 || (len(lines) == 1 && lines[0] == "") {
		fmt.Println("No running containers found.")
		return nil
	}

	for _, line := range lines {
		parts := strings.Split(line, "\t")
		if len(parts) >= 3 {
			fmt.Printf("%s\t%s\t%s\n", parts[0][:12], parts[1], parts[2])
		}
	}
	return nil
}
