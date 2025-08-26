// pkg/service_installation/loki.go
package service_installation

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// installLoki installs Loki using Docker Compose
func (sim *ServiceInstallationManager) installLoki(rc *eos_io.RuntimeContext, options *ServiceInstallOptions, result *InstallationResult) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Installing Loki",
		zap.String("version", options.Version),
		zap.String("method", string(options.Method)))

	if options.DryRun {
		result.Success = true
		result.Message = "Dry run completed - Loki would be installed via Docker Compose"
		return nil
	}

	// Set defaults
	if options.Version == "" {
		options.Version = "v3.0.0"
	}

	// Create working directory
	workDir := options.WorkingDirectory
	if workDir == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %w", err)
		}
		workDir = filepath.Join(homeDir, "loki")
	}

	// Step 1: Create directory
	step1 := InstallationStep{
		Name:        "Create Directory",
		Description: fmt.Sprintf("Creating Loki directory at %s", workDir),
		Status:      "running",
	}
	step1Start := time.Now()

	if err := sim.ensureDirectory(workDir); err != nil {
		step1.Status = "failed"
		step1.Error = err.Error()
		step1.Duration = time.Since(step1Start)
		result.Steps = append(result.Steps, step1)
		return fmt.Errorf("failed to create directory: %w", err)
	}

	step1.Status = "completed"
	step1.Duration = time.Since(step1Start)
	result.Steps = append(result.Steps, step1)

	// Step 2: Download docker-compose.yaml
	step2 := InstallationStep{
		Name:        "Download Configuration",
		Description: "Downloading Loki docker-compose configuration",
		Status:      "running",
	}
	step2Start := time.Now()

	composePath := filepath.Join(workDir, "docker-compose.yaml")
	downloadURL := fmt.Sprintf("https://raw.githubusercontent.com/grafana/loki/%s/production/docker-compose.yaml", options.Version)

	if err := sim.runCommand(rc, "Download config", "wget", downloadURL, "-O", composePath); err != nil {
		// Fallback to curl if wget is not available
		if err := sim.runCommand(rc, "Download config", "curl", "-L", downloadURL, "-o", composePath); err != nil {
			step2.Status = "failed"
			step2.Error = err.Error()
			step2.Duration = time.Since(step2Start)
			result.Steps = append(result.Steps, step2)
			return fmt.Errorf("failed to download docker-compose.yaml: %w", err)
		}
	}

	step2.Status = "completed"
	step2.Duration = time.Since(step2Start)
	result.Steps = append(result.Steps, step2)

	// Step 3: Start Loki services
	step3 := InstallationStep{
		Name:        "Start Services",
		Description: "Starting Loki services with Docker Compose",
		Status:      "running",
	}
	step3Start := time.Now()

	// Change to the Loki directory and run docker compose
	cmd := sim.createCommandInDir(workDir, "docker", "compose", "-f", "docker-compose.yaml", "up", "-d")
	if err := cmd.Run(); err != nil {
		// Try docker-compose as fallback
		cmd = sim.createCommandInDir(workDir, "docker-compose", "-f", "docker-compose.yaml", "up", "-d")
		if err := cmd.Run(); err != nil {
			step3.Status = "failed"
			step3.Error = err.Error()
			step3.Duration = time.Since(step3Start)
			result.Steps = append(result.Steps, step3)
			return fmt.Errorf("failed to start Loki services: %w", err)
		}
	}

	step3.Status = "completed"
	step3.Duration = time.Since(step3Start)
	result.Steps = append(result.Steps, step3)

	// Wait for services to be ready
	logger.Info("Waiting for Loki to be ready...")
	time.Sleep(20 * time.Second)

	// Set result
	result.Success = true
	result.Version = options.Version
	result.Port = 3100 // Default Loki port
	result.Message = "Loki installed successfully via Docker Compose"
	result.Endpoints = []string{
		"http://localhost:3100", // Loki API
		"http://localhost:3000", // Grafana (if included in compose)
		"http://localhost:9093", // Alertmanager (if included)
		"http://localhost:9090", // Prometheus (if included)
	}
	result.ConfigFiles = []string{
		composePath,
	}

	logger.Info("Loki installation completed successfully",
		zap.String("working_directory", workDir),
		zap.String("version", options.Version))

	return nil
}

// getLokiStatus retrieves Loki service status
func (sim *ServiceInstallationManager) getLokiStatus(rc *eos_io.RuntimeContext, status *ServiceStatus) (*ServiceStatus, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Look for common Loki installation locations
	homeDir, _ := os.UserHomeDir()
	possibleLocations := []string{
		filepath.Join(homeDir, "loki", "docker-compose.yaml"),
		"/opt/loki/docker-compose.yaml",
		"./docker-compose.yaml",
	}

	var composePath string
	for _, loc := range possibleLocations {
		if _, err := os.Stat(loc); err == nil {
			composePath = loc
			break
		}
	}

	if composePath == "" {
		status.Status = "not_installed"
		return status, nil
	}

	status.Method = MethodCompose
	workDir := filepath.Dir(composePath)

	// Check container status
	cmd := sim.createCommandInDir(workDir, "docker", "compose", "ps", "--format", "json")
	output, err := cmd.Output()
	if err != nil {
		// Try docker-compose as fallback
		cmd = sim.createCommandInDir(workDir, "docker-compose", "ps", "--format", "json")
		output, err = cmd.Output()
	}

	if err == nil && len(output) > 0 {
		status.Status = "running"

		// Try to get Loki version from container
		cmd = sim.createCommandInDir(workDir, "docker", "compose", "exec", "-T", "loki", "loki", "--version")
		if versionOutput, err := cmd.Output(); err == nil {
			status.Version = parseVersionFromOutput(string(versionOutput))
		}
	} else {
		status.Status = "stopped"
	}

	// Health check
	if status.Status == "running" {
		endpoint := "http://localhost:3100/ready"
		if healthCheck, err := sim.PerformHealthCheck(rc, ServiceTypeLoki, endpoint); err == nil {
			status.HealthCheck = healthCheck
		}
	}

	logger.Info("Loki status retrieved",
		zap.String("status", status.Status),
		zap.String("compose_path", composePath))

	return status, nil
}
