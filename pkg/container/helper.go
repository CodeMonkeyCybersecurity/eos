/* pkg/docker/helper.go */

package container

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	cerr "github.com/cockroachdb/errors"
)

// TODO: This package needs major refactoring:
// 1. Replace all fmt.Printf/Println with structured logging using otelzap.Ctx(rc.Ctx)
// 2. Use shared.RunCommand() instead of direct exec.Command usage
// 3. Implement proper Assess → Intervene → Evaluate pattern
// 4. Migrate to shared.ServiceManager for service operations
// 5. Use shared.InstallationChecker for checking if Docker is installed
// 6. Standardize error handling with proper wrapping
//
// MIGRATION IN PROGRESS: See helper_refactored.go for the fully migrated version
// that follows all Eos standards. Once tested, it will replace this implementation.

// DeployCompose performs the following actions:
// 1. Gets the current working directory and uses its base name as the application name.
// 2. Creates a target directory under /opt using the app name.
// 3. Searches for local docker-compose.yml or docker-compose.yaml files and copies them to the target directory.
// 4. Changes the ownership of the target directory to UID/GID 472.
// 5. Runs "docker compose up -d" in the target directory.
func DeployCompose(rc *eos_io.RuntimeContext) error {
	// Get the current working directory.
	currentDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("error getting current directory: %v", err)
	}

	// Use the current directory's base as the application name (e.g., "grafana").
	appDir := filepath.Base(currentDir)

	// Create the target directory under /opt (e.g., /opt/grafana).
	targetDir := filepath.Join("/opt", appDir)
	if err := os.MkdirAll(targetDir, shared.DirPermStandard); err != nil {
		return fmt.Errorf("error creating target directory %s: %v", targetDir, err)
	}

	// Look for docker-compose.yml or docker-compose.yaml in the current directory.
	composeFiles, err := filepath.Glob("docker-compose.yml")
	if err != nil {
		return fmt.Errorf("error globbing docker-compose.yml: %v", err)
	}
	yamlFiles, err := filepath.Glob("docker-compose.yaml")
	if err != nil {
		return fmt.Errorf("error globbing docker-compose.yaml: %v", err)
	}
	composeFiles = append(composeFiles, yamlFiles...)

	if len(composeFiles) == 0 {
		fmt.Println("No docker-compose.yml or docker-compose.yaml file found in the current directory.")
		return nil
	}

	// For each compose file found, copy it to the target directory.
	for _, file := range composeFiles {
		destFile := filepath.Join(targetDir, filepath.Base(file))
		fmt.Printf("Copying %s to %s\n", file, destFile)
		if err := eos_unix.CopyFile(rc.Ctx, file, destFile, 0); err != nil {
			return fmt.Errorf("error copying file %s: %v", file, err)
		}
	}

	// Fix permissions on the target directory so that containers (e.g., Grafana) can write to volumes.
	// The official Grafana Docker image runs as UID/GID 472.
	fmt.Printf("Fixing ownership of %s to UID 472:472\n", targetDir)
	chownCmd := exec.Command("chown", "-R", "472:472", targetDir)
	chownCmd.Stdout = os.Stdout
	chownCmd.Stderr = os.Stderr
	if err := chownCmd.Run(); err != nil {
		return fmt.Errorf("error running chown: %v", err)
	}

	// Run "docker compose up -d" in the target directory.
	fmt.Printf("Running 'docker compose up -d' in %s\n", targetDir)
	dockerCmd := exec.Command("docker", "compose", "up", "-d")
	dockerCmd.Dir = targetDir
	dockerCmd.Stdout = os.Stdout
	dockerCmd.Stderr = os.Stderr
	if err := dockerCmd.Run(); err != nil {
		return fmt.Errorf("error running docker compose: %v", err)
	}

	fmt.Println("Docker compose is now up and running in the new directory.")
	return nil
}

func GenerateServiceDeployment(serviceName, deploymentType, image, configFile string) (*system.ServiceDeployment, error) {
	deployment := &system.ServiceDeployment{
		Name: serviceName,
		Type: deploymentType,
		Resources: system.ResourceRequirements{
			CPU:    500,  // 500 MHz
			Memory: 512,  // 512 MB
			Disk:   1024, // 1 GB
		},
		HealthChecks: []system.HealthCheck{
			{
				Type:     "http",
				Endpoint: "/health",
				Port:     8080,
				Interval: 30 * time.Second,
				Timeout:  5 * time.Second,
				Retries:  3,
			},
		},
		UpdateStrategy: system.UpdateStrategy{
			Type:            "rolling",
			MaxUnavailable:  1,
			MaxSurge:        1,
			ProgressTimeout: 5 * time.Minute,
			RollbackOnError: true,
		},
	}

	switch deploymentType {
	case "nomad":
		deployment.JobSpec = &system.NomadJobSpec{
			ID:          serviceName,
			Name:        serviceName,
			Type:        "service",
			Region:      "global",
			Datacenters: []string{"dc1"},
			Groups: []system.TaskGroup{
				{
					Name:  serviceName,
					Count: 1,
					Tasks: []system.Task{
						{
							Name:   serviceName,
							Driver: "docker",
							Config: map[string]interface{}{
								"image": image,
								"ports": []string{"http"},
							},
							Resources: system.Resources{
								CPU:    500,
								Memory: 512,
								Ports: map[string]int{
									"http": 8080,
								},
							},
						},
					},
				},
			},
		}

	case "docker":
		deployment.DockerConfig = &system.DockerServiceConfig{
			Image: extractImageName(image),
			Tag:   extractImageTag(image),
			Ports: []system.PortMapping{
				{
					HostPort:      8080,
					ContainerPort: 8080,
					Protocol:      "tcp",
				},
			},
			RestartPolicy: "unless-stopped",
		}

	case "systemd":
		deployment.SystemdConfig = &system.SystemdServiceConfig{
			ExecStart: fmt.Sprintf("/usr/bin/%s", serviceName),
			User:      serviceName,
			Group:     serviceName,
			Type:      "simple",
			Restart:   "always",
			WantedBy:  []string{"multi-user.target"},
		}

	default:
		return nil, cerr.New(fmt.Sprintf("unsupported deployment type: %s", deploymentType))
	}

	return deployment, nil
}

func extractImageName(image string) string {
	// Extract image name from full image string (e.g., "nginx:1.20" -> "nginx")
	if idx := strings.LastIndex(image, ":"); idx != -1 {
		return image[:idx]
	}
	return image
}

func extractImageTag(image string) string {
	// Extract tag from full image string (e.g., "nginx:1.20" -> "1.20")
	if idx := strings.LastIndex(image, ":"); idx != -1 {
		return image[idx+1:]
	}
	return "latest"
}
