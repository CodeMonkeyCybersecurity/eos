/* pkg/container/helper_refactored.go */

package container

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// DeployComposeRefactored deploys a Docker Compose application following Assess → Intervene → Evaluate pattern
// This is a fully refactored version that follows all Eos standards
func DeployComposeRefactored(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS - Evaluate current state and requirements
	logger.Info("Assessing Docker Compose deployment requirements")
	
	// Check if Docker is installed and running
	if err := assessDockerInstallation(rc); err != nil {
		return fmt.Errorf("Docker assessment failed: %w", err)
	}
	
	// Get application deployment context
	currentDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current directory: %w", err)
	}
	
	appName := filepath.Base(currentDir)
	targetDir := filepath.Join("/opt", appName)
	
	logger.Info("Deployment context determined",
		zap.String("app_name", appName),
		zap.String("source_dir", currentDir),
		zap.String("target_dir", targetDir))
	
	// Find compose files in current directory
	composeFiles, err := findComposeFiles(rc, currentDir)
	if err != nil {
		return fmt.Errorf("failed to find compose files: %w", err)
	}
	
	if len(composeFiles) == 0 {
		return eos_err.NewUserError("no docker-compose.yml or docker-compose.yaml files found in current directory")
	}
	
	logger.Info("Found compose files",
		zap.Strings("files", composeFiles))
	
	// Check if application is already deployed
	if deployed, err := isAlreadyDeployed(rc, targetDir); err != nil {
		return fmt.Errorf("failed to check deployment status: %w", err)
	} else if deployed {
		logger.Info("Application already deployed, will update",
			zap.String("app", appName),
			zap.String("directory", targetDir))
	}
	
	// INTERVENE - Perform the deployment actions
	logger.Info("Deploying Docker Compose application",
		zap.String("app", appName))
	
	// Create target directory with proper permissions
	if err := eos_unix.MkdirP(rc.Ctx, targetDir, shared.DirPermStandard); err != nil {
		return fmt.Errorf("failed to create target directory: %w", err)
	}
	
	// Copy compose files to target directory
	for _, composeFile := range composeFiles {
		destFile := filepath.Join(targetDir, filepath.Base(composeFile))
		logger.Info("Copying compose file",
			zap.String("source", composeFile),
			zap.String("destination", destFile))
			
		if err := eos_unix.CopyFile(rc.Ctx, composeFile, destFile, 0); err != nil {
			return fmt.Errorf("failed to copy compose file %s: %w", composeFile, err)
		}
	}
	
	// Copy .env file if it exists
	if err := copyEnvFile(rc, currentDir, targetDir); err != nil {
		logger.Debug("No .env file found to copy", zap.Error(err))
	}
	
	// Set ownership for container compatibility (Grafana runs as UID/GID 472)
	logger.Info("Setting directory ownership for container compatibility",
		zap.String("path", targetDir),
		zap.Int("uid", 472),
		zap.Int("gid", 472))
		
	if err := eos_unix.ChownR(rc.Ctx, targetDir, 472, 472); err != nil {
		logger.Warn("Failed to set optimal ownership, containers may have permission issues",
			zap.String("path", targetDir),
			zap.Error(err))
	}
	
	// Run docker compose up
	logger.Info("Starting containers with docker compose")
	if err := runDockerComposeUp(rc, targetDir); err != nil {
		return fmt.Errorf("failed to start containers: %w", err)
	}
	
	// EVALUATE - Verify deployment was successful
	logger.Info("Evaluating Docker Compose deployment success")
	
	// Wait for containers to become healthy
	if err := waitForContainersHealthy(rc, targetDir, 60*time.Second); err != nil {
		return fmt.Errorf("containers failed to become healthy: %w", err)
	}
	
	// Verify all expected containers are running
	if err := verifyContainersRunning(rc, targetDir); err != nil {
		return fmt.Errorf("container verification failed: %w", err)
	}
	
	// Log deployment summary
	if summary, err := getDeploymentSummary(rc, targetDir); err == nil {
		logger.Info("Docker Compose deployment completed successfully",
			zap.String("app", appName),
			zap.String("directory", targetDir),
			zap.Any("summary", summary))
	}
	
	return nil
}

// assessDockerInstallation checks if Docker and Docker Compose are properly installed
func assessDockerInstallation(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Check Docker daemon is installed and running
	logger.Debug("Checking Docker installation")
	
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    []string{"version"},
		Capture: true,
	})
	
	if err != nil {
		return eos_err.NewUserError("Docker is not installed or not running. Please install Docker first")
	}
	
	logger.Debug("Docker is installed",
		zap.String("version_output", output))
	
	// Check if Docker daemon is actually running
	_, err = execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    []string{"ps"},
		Capture: true,
	})
	
	if err != nil {
		return eos_err.NewUserError("Docker daemon is not running. Please start Docker service")
	}
	
	// Check for docker compose (plugin or standalone)
	logger.Debug("Checking Docker Compose availability")
	
	// Try docker compose (plugin)
	_, err = execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    []string{"compose", "version"},
		Capture: true,
	})
	
	if err != nil {
		// Try docker-compose (standalone)
		_, err = execute.Run(rc.Ctx, execute.Options{
			Command: "docker-compose",
			Args:    []string{"version"},
			Capture: true,
		})
		
		if err != nil {
			return eos_err.NewUserError("Docker Compose is not installed. Please install Docker Compose plugin or standalone")
		}
		
		logger.Debug("Using standalone docker-compose")
	} else {
		logger.Debug("Using Docker Compose plugin")
	}
	
	return nil
}

// findComposeFiles finds docker-compose.yml or docker-compose.yaml files
func findComposeFiles(rc *eos_io.RuntimeContext, dir string) ([]string, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	var composeFiles []string
	
	// Check for docker-compose.yml
	ymlPath := filepath.Join(dir, "docker-compose.yml")
	if _, err := os.Stat(ymlPath); err == nil {
		composeFiles = append(composeFiles, ymlPath)
		logger.Debug("Found docker-compose.yml")
	}
	
	// Check for docker-compose.yaml
	yamlPath := filepath.Join(dir, "docker-compose.yaml")
	if _, err := os.Stat(yamlPath); err == nil {
		composeFiles = append(composeFiles, yamlPath)
		logger.Debug("Found docker-compose.yaml")
	}
	
	// Check for docker-compose.override.yml
	overridePath := filepath.Join(dir, "docker-compose.override.yml")
	if _, err := os.Stat(overridePath); err == nil {
		composeFiles = append(composeFiles, overridePath)
		logger.Debug("Found docker-compose.override.yml")
	}
	
	return composeFiles, nil
}

// isAlreadyDeployed checks if the application is already deployed
func isAlreadyDeployed(rc *eos_io.RuntimeContext, targetDir string) (bool, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Check if target directory exists
	if _, err := os.Stat(targetDir); os.IsNotExist(err) {
		return false, nil
	}
	
	// Check if compose file exists in target
	composePath := filepath.Join(targetDir, "docker-compose.yml")
	if _, err := os.Stat(composePath); err == nil {
		logger.Debug("Found existing deployment",
			zap.String("path", composePath))
		return true, nil
	}
	
	return false, nil
}

// copyEnvFile copies .env file if it exists
func copyEnvFile(rc *eos_io.RuntimeContext, sourceDir, targetDir string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	envSource := filepath.Join(sourceDir, ".env")
	if _, err := os.Stat(envSource); os.IsNotExist(err) {
		return fmt.Errorf(".env file not found")
	}
	
	envDest := filepath.Join(targetDir, ".env")
	logger.Info("Copying environment file",
		zap.String("source", envSource),
		zap.String("destination", envDest))
		
	return eos_unix.CopyFile(rc.Ctx, envSource, envDest, 0600)
}

// runDockerComposeUp runs docker compose up -d in the target directory
func runDockerComposeUp(rc *eos_io.RuntimeContext, targetDir string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Determine which compose command to use
	composeCmd := "docker"
	composeArgs := []string{"compose", "up", "-d"}
	
	// Test if docker compose works
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: composeCmd,
		Args:    []string{"compose", "version"},
		Capture: true,
	})
	
	if err != nil {
		// Fall back to docker-compose
		composeCmd = "docker-compose"
		composeArgs = []string{"up", "-d"}
	}
	
	logger.Info("Running docker compose up",
		zap.String("command", composeCmd),
		zap.Strings("args", composeArgs),
		zap.String("directory", targetDir))
	
	// Execute in target directory
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: composeCmd,
		Args:    composeArgs,
		Capture: true,
		Dir:     targetDir,
	})
	
	if err != nil {
		logger.Error("Docker compose up failed",
			zap.Error(err),
			zap.String("output", output))
		return fmt.Errorf("docker compose up failed: %w", err)
	}
	
	logger.Debug("Docker compose up output",
		zap.String("output", output))
		
	return nil
}

// waitForContainersHealthy waits for containers to become healthy
func waitForContainersHealthy(rc *eos_io.RuntimeContext, targetDir string, timeout time.Duration) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Waiting for containers to become healthy",
		zap.Duration("timeout", timeout))
		
	deadline := time.Now().Add(timeout)
	
	for time.Now().Before(deadline) {
		// Check container status
		output, err := execute.Run(rc.Ctx, execute.Options{
			Command: "docker",
			Args:    []string{"compose", "ps", "--format", "json"},
			Capture: true,
			Dir:     targetDir,
		})
		
		if err != nil {
			// Try legacy format
			output, err = execute.Run(rc.Ctx, execute.Options{
				Command: "docker-compose",
				Args:    []string{"ps", "-q"},
				Capture: true,
				Dir:     targetDir,
			})
			
			if err != nil {
				logger.Warn("Failed to check container status",
					zap.Error(err))
				time.Sleep(2 * time.Second)
				continue
			}
		}
		
		// If we got output, containers are at least created
		if output != "" {
			// Check if all containers are running
			if err := checkContainersRunning(rc, targetDir); err == nil {
				logger.Info("All containers are healthy")
				return nil
			}
		}
		
		// Check for context cancellation
		select {
		case <-rc.Ctx.Done():
			return fmt.Errorf("context cancelled while waiting for containers: %w", rc.Ctx.Err())
		case <-time.After(2 * time.Second):
			// Continue checking
		}
	}
	
	return fmt.Errorf("timeout waiting for containers to become healthy")
}

// checkContainersRunning verifies all containers are in running state
func checkContainersRunning(rc *eos_io.RuntimeContext, targetDir string) error {
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    []string{"compose", "ps", "-q"},
		Capture: true,
		Dir:     targetDir,
	})
	
	if err != nil {
		return fmt.Errorf("failed to list containers: %w", err)
	}
	
	containerIDs := strings.Split(strings.TrimSpace(output), "\n")
	if len(containerIDs) == 0 || containerIDs[0] == "" {
		return fmt.Errorf("no containers found")
	}
	
	// Check each container is running
	for _, id := range containerIDs {
		if id == "" {
			continue
		}
		
		status, err := execute.Run(rc.Ctx, execute.Options{
			Command: "docker",
			Args:    []string{"inspect", "-f", "{{.State.Running}}", id},
			Capture: true,
		})
		
		if err != nil || strings.TrimSpace(status) != "true" {
			return fmt.Errorf("container %s is not running", id)
		}
	}
	
	return nil
}

// verifyContainersRunning performs final verification
func verifyContainersRunning(rc *eos_io.RuntimeContext, targetDir string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Verifying container deployment")
	
	// Get container list
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    []string{"compose", "ps"},
		Capture: true,
		Dir:     targetDir,
	})
	
	if err != nil {
		return fmt.Errorf("failed to verify containers: %w", err)
	}
	
	logger.Debug("Container status",
		zap.String("output", output))
		
	// Ensure at least one container is running
	if !strings.Contains(output, "Up") && !strings.Contains(output, "running") {
		return fmt.Errorf("no containers are running")
	}
	
	return nil
}

// getDeploymentSummary returns a summary of the deployment
func getDeploymentSummary(rc *eos_io.RuntimeContext, targetDir string) (map[string]interface{}, error) {
	// Get container count
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    []string{"compose", "ps", "-q"},
		Capture: true,
		Dir:     targetDir,
	})
	
	containerCount := 0
	if err == nil && output != "" {
		containerCount = len(strings.Split(strings.TrimSpace(output), "\n"))
	}
	
	return map[string]interface{}{
		"container_count": containerCount,
		"deployment_dir":  targetDir,
	}, nil
}

// GenerateServiceDeploymentRefactored generates service deployment configuration
func GenerateServiceDeploymentRefactored(rc *eos_io.RuntimeContext, serviceName, deploymentType, image, configFile string) (*system.ServiceDeployment, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Generating service deployment configuration",
		zap.String("service", serviceName),
		zap.String("type", deploymentType),
		zap.String("image", image))
		
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
		return nil, eos_err.NewUserError("unsupported deployment type: %s. Supported types: nomad, docker, systemd", deploymentType)
	}
	
	logger.Debug("Generated deployment configuration",
		zap.Any("deployment", deployment))

	return deployment, nil
}