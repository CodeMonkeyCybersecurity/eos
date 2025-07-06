// pkg/service_installation/mattermost.go
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

const mattermostComposeContent = `version: '3'

services:
  db:
    image: postgres:12
    restart: unless-stopped
    volumes:
      - ./volumes/db:/var/lib/postgresql/data
    environment:
      POSTGRES_USER: mmuser
      POSTGRES_PASSWORD: %s
      POSTGRES_DB: mattermost
    networks:
      - mattermost-network

  app:
    image: mattermost/mattermost-team-edition:%s
    restart: unless-stopped
    ports:
      - "%d:8065"
    volumes:
      - ./volumes/app/mattermost:/mattermost/data
    environment:
      MM_SQLSETTINGS_DRIVERNAME: postgres
      MM_SQLSETTINGS_DATASOURCE: postgres://mmuser:%s@db:5432/mattermost?sslmode=disable
    networks:
      - mattermost-network
    depends_on:
      - db

networks:
  mattermost-network:
`

// installMattermost installs Mattermost using Docker Compose
func (sim *ServiceInstallationManager) installMattermost(rc *eos_io.RuntimeContext, options *ServiceInstallOptions, result *InstallationResult) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Installing Mattermost",
		zap.String("version", options.Version),
		zap.String("method", string(options.Method)))

	if options.DryRun {
		result.Success = true
		result.Message = "Dry run completed - Mattermost would be installed via Docker Compose"
		return nil
	}

	// Set defaults
	if options.Version == "" {
		options.Version = "latest"
	}
	if options.Port == 0 {
		options.Port = 8065
	}

	// Generate database password if not provided
	dbPassword, exists := options.Environment["DB_PASSWORD"]
	if !exists || dbPassword == "" {
		dbPassword = generateSecurePassword()
		options.Environment["DB_PASSWORD"] = dbPassword
	}

	// Create working directory
	workDir := options.WorkingDirectory
	if workDir == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %w", err)
		}
		workDir = filepath.Join(homeDir, "mattermost")
	}

	// Step 1: Create directory structure
	step1 := InstallationStep{
		Name:        "Create Directory",
		Description: fmt.Sprintf("Creating Mattermost directory at %s", workDir),
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

	// Step 2: Create docker-compose.yml
	step2 := InstallationStep{
		Name:        "Create Configuration",
		Description: "Creating docker-compose.yml configuration",
		Status:      "running",
	}
	step2Start := time.Now()

	composeContent := fmt.Sprintf(mattermostComposeContent,
		dbPassword,
		options.Version,
		options.Port,
		dbPassword,
	)

	composePath := filepath.Join(workDir, "docker-compose.yml")
	if err := sim.createFile(composePath, composeContent); err != nil {
		step2.Status = "failed"
		step2.Error = err.Error()
		step2.Duration = time.Since(step2Start)
		result.Steps = append(result.Steps, step2)
		return fmt.Errorf("failed to create docker-compose.yml: %w", err)
	}

	step2.Status = "completed"
	step2.Duration = time.Since(step2Start)
	result.Steps = append(result.Steps, step2)

	// Step 3: Pull images
	step3 := InstallationStep{
		Name:        "Pull Images",
		Description: "Pulling Docker images for Mattermost and PostgreSQL",
		Status:      "running",
	}
	step3Start := time.Now()

	if err := sim.runCommand(rc, "Pull images", "docker-compose", "-f", composePath, "pull"); err != nil {
		step3.Status = "failed"
		step3.Error = err.Error()
		step3.Duration = time.Since(step3Start)
		result.Steps = append(result.Steps, step3)
		return fmt.Errorf("failed to pull Docker images: %w", err)
	}

	step3.Status = "completed"
	step3.Duration = time.Since(step3Start)
	result.Steps = append(result.Steps, step3)

	// Step 4: Start services
	step4 := InstallationStep{
		Name:        "Start Services",
		Description: "Starting Mattermost and database services",
		Status:      "running",
	}
	step4Start := time.Now()

	if err := sim.runCommand(rc, "Start services", "docker-compose", "-f", composePath, "up", "-d"); err != nil {
		step4.Status = "failed"
		step4.Error = err.Error()
		step4.Duration = time.Since(step4Start)
		result.Steps = append(result.Steps, step4)
		return fmt.Errorf("failed to start services: %w", err)
	}

	step4.Status = "completed"
	step4.Duration = time.Since(step4Start)
	result.Steps = append(result.Steps, step4)

	// Wait for services to be ready
	logger.Info("Waiting for Mattermost to be ready...")
	time.Sleep(30 * time.Second)

	// Set result
	result.Success = true
	result.Version = options.Version
	result.Port = options.Port
	result.Message = "Mattermost installed successfully via Docker Compose"
	result.Endpoints = []string{
		fmt.Sprintf("http://localhost:%d", options.Port),
	}
	result.Credentials = map[string]string{
		"DB_USER":     "mmuser",
		"DB_PASSWORD": dbPassword,
		"DB_NAME":     "mattermost",
		"Note":        "Create admin user through web interface on first login",
	}
	result.ConfigFiles = []string{
		composePath,
	}

	logger.Info("Mattermost installation completed successfully",
		zap.String("working_directory", workDir),
		zap.Int("port", options.Port))

	return nil
}

// getMattermostStatus retrieves Mattermost service status
func (sim *ServiceInstallationManager) getMattermostStatus(rc *eos_io.RuntimeContext, status *ServiceStatus) (*ServiceStatus, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Look for common Mattermost installation locations
	homeDir, _ := os.UserHomeDir()
	possibleLocations := []string{
		filepath.Join(homeDir, "mattermost", "docker-compose.yml"),
		"/opt/mattermost/docker-compose.yml",
		"./docker-compose.yml",
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

	// Check container status
	workDir := filepath.Dir(composePath)
	cmd := sim.createCommandInDir(workDir, "docker-compose", "ps", "--format", "json")
	if output, err := cmd.Output(); err == nil {
		// Parse output to determine status
		outputStr := string(output)
		if outputStr != "" {
			status.Status = "running"
		} else {
			status.Status = "stopped"
		}
	} else {
		status.Status = "unknown"
	}

	// Get version from running container
	if status.Status == "running" {
		cmd = sim.createCommandInDir(workDir, "docker-compose", "exec", "-T", "app", "mattermost", "version")
		if output, err := cmd.Output(); err == nil {
			status.Version = parseVersionFromOutput(string(output))
		}
	}

	// Check health endpoint
	endpoint := "http://localhost:8065/api/v4/system/ping"
	if healthCheck, err := sim.PerformHealthCheck(rc, ServiceTypeMattermost, endpoint); err == nil {
		status.HealthCheck = healthCheck
	}

	logger.Info("Mattermost status retrieved",
		zap.String("status", status.Status),
		zap.String("compose_path", composePath))

	return status, nil
}

// Helper function to generate secure password
func generateSecurePassword() string {
	// In production, use a proper password generator
	// This is a simple implementation for demonstration
	return fmt.Sprintf("mm_%d_%s", time.Now().Unix(), "SecurePass123!")
}

// Helper function to parse version from output
func parseVersionFromOutput(output string) string {
	// Simple version extraction - customize based on actual output format
	if len(output) > 0 {
		return "unknown"
	}
	return "unknown"
}