// pkg/service_installation/guacamole.go
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

const guacamoleComposeContent = `version: '3.8'

services:
  guacd:
    image: guacamole/guacd:%s
    container_name: guacamole_guacd
    restart: unless-stopped
    volumes:
      - guacamole_drive:/drive
      - guacamole_record:/record
    networks:
      - guacamole_net

  postgres:
    image: postgres:13
    container_name: guacamole_postgres
    restart: unless-stopped
    environment:
      POSTGRES_DB: guacamole_db
      POSTGRES_USER: guacamole_user
      POSTGRES_PASSWORD: %s
    volumes:
      - guacamole_postgres:/var/lib/postgresql/data
      - ./initdb.sql:/docker-entrypoint-initdb.d/initdb.sql:ro
    networks:
      - guacamole_net

  guacamole:
    image: guacamole/guacamole:%s
    container_name: guacamole_app
    restart: unless-stopped
    ports:
      - "%d:8080"
    environment:
      GUACD_HOSTNAME: guacd
      POSTGRES_DATABASE: guacamole_db
      POSTGRES_HOSTNAME: postgres
      POSTGRES_USER: guacamole_user
      POSTGRES_PASSWORD: %s
    depends_on:
      - guacd
      - postgres
    networks:
      - guacamole_net

volumes:
  guacamole_postgres:
  guacamole_drive:
  guacamole_record:

networks:
  guacamole_net:
    driver: bridge
`

// installGuacamole installs Apache Guacamole using Docker Compose
func (sim *ServiceInstallationManager) installGuacamole(rc *eos_io.RuntimeContext, options *ServiceInstallOptions, result *InstallationResult) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Installing Apache Guacamole",
		zap.String("version", options.Version),
		zap.String("method", string(options.Method)))

	if options.DryRun {
		result.Success = true
		result.Message = "Dry run completed - Apache Guacamole would be installed via Docker Compose"
		return nil
	}

	// Set defaults
	if options.Version == "" {
		options.Version = "latest"
	}
	if options.Port == 0 {
		options.Port = 8080
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
		workDir = filepath.Join(homeDir, "guacamole")
	}

	// Step 1: Create directory structure
	step1 := InstallationStep{
		Name:        "Create Directory",
		Description: fmt.Sprintf("Creating Guacamole directory at %s", workDir),
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

	// Step 2: Download and prepare database schema
	step2 := InstallationStep{
		Name:        "Prepare Database Schema",
		Description: "Downloading and preparing Guacamole database schema",
		Status:      "running",
	}
	step2Start := time.Now()

	// Download the database schema initialization script
	dbInitPath := filepath.Join(workDir, "initdb.sql")
	if err := sim.downloadGuacamoleSchema(rc, options.Version, dbInitPath); err != nil {
		step2.Status = "failed"
		step2.Error = err.Error()
		step2.Duration = time.Since(step2Start)
		result.Steps = append(result.Steps, step2)
		return fmt.Errorf("failed to prepare database schema: %w", err)
	}

	step2.Status = "completed"
	step2.Duration = time.Since(step2Start)
	result.Steps = append(result.Steps, step2)

	// Step 3: Create docker-compose.yml
	step3 := InstallationStep{
		Name:        "Create Configuration",
		Description: "Creating docker-compose.yml configuration",
		Status:      "running",
	}
	step3Start := time.Now()

	composeContent := fmt.Sprintf(guacamoleComposeContent,
		options.Version, // guacd version
		dbPassword,      // postgres password
		options.Version, // guacamole version
		options.Port,    // exposed port
		dbPassword,      // postgres password for guacamole
	)

	composePath := filepath.Join(workDir, "docker-compose.yml")
	if err := sim.createFile(composePath, composeContent); err != nil {
		step3.Status = "failed"
		step3.Error = err.Error()
		step3.Duration = time.Since(step3Start)
		result.Steps = append(result.Steps, step3)
		return fmt.Errorf("failed to create docker-compose.yml: %w", err)
	}

	step3.Status = "completed"
	step3.Duration = time.Since(step3Start)
	result.Steps = append(result.Steps, step3)

	// Step 4: Pull images
	step4 := InstallationStep{
		Name:        "Pull Images",
		Description: "Pulling Docker images for Guacamole components",
		Status:      "running",
	}
	step4Start := time.Now()

	if err := sim.runCommand(rc, "Pull images", "docker-compose", "-f", composePath, "pull"); err != nil {
		step4.Status = "failed"
		step4.Error = err.Error()
		step4.Duration = time.Since(step4Start)
		result.Steps = append(result.Steps, step4)
		return fmt.Errorf("failed to pull Docker images: %w", err)
	}

	step4.Status = "completed"
	step4.Duration = time.Since(step4Start)
	result.Steps = append(result.Steps, step4)

	// Step 5: Start services
	step5 := InstallationStep{
		Name:        "Start Services",
		Description: "Starting Guacamole services",
		Status:      "running",
	}
	step5Start := time.Now()

	if err := sim.runCommand(rc, "Start services", "docker-compose", "-f", composePath, "up", "-d"); err != nil {
		step5.Status = "failed"
		step5.Error = err.Error()
		step5.Duration = time.Since(step5Start)
		result.Steps = append(result.Steps, step5)
		return fmt.Errorf("failed to start services: %w", err)
	}

	step5.Status = "completed"
	step5.Duration = time.Since(step5Start)
	result.Steps = append(result.Steps, step5)

	// Wait for services to be ready
	logger.Info("Waiting for Guacamole to be ready...")
	time.Sleep(45 * time.Second)

	// Set result
	result.Success = true
	result.Version = options.Version
	result.Port = options.Port
	result.Message = "Apache Guacamole installed successfully via Docker Compose"
	result.Endpoints = []string{
		fmt.Sprintf("http://localhost:%d/guacamole", options.Port),
	}
	result.Credentials = map[string]string{
		"Default User":     "guacadmin",
		"Default Password": "guacadmin",
		"DB_USER":          "guacamole_user",
		"DB_PASSWORD":      dbPassword,
		"DB_NAME":          "guacamole_db",
		"Note":             "Change default admin password on first login",
	}
	result.ConfigFiles = []string{
		composePath,
		dbInitPath,
	}

	logger.Info("Apache Guacamole installation completed successfully",
		zap.String("working_directory", workDir),
		zap.Int("port", options.Port))

	return nil
}

// downloadGuacamoleSchema downloads the Guacamole database schema
func (sim *ServiceInstallationManager) downloadGuacamoleSchema(rc *eos_io.RuntimeContext, version, outputPath string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Use docker to extract the schema from the guacamole image
	cmd := fmt.Sprintf(`docker run --rm guacamole/guacamole:%s /opt/guacamole/bin/initdb.sh --postgres > %s`, version, outputPath)

	if err := sim.runCommand(rc, "Extract database schema", "bash", "-c", cmd); err != nil {
		logger.Error("Failed to extract schema, using fallback method", zap.Error(err))

		// Fallback: create a basic schema
		basicSchema := `--
-- PostgreSQL database dump for Guacamole
--

-- Create extension for UUID generation
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create tables for Guacamole
-- Note: This is a minimal schema. For production use, 
-- run the official initdb.sh script from the Guacamole container.

-- User table
CREATE TABLE IF NOT EXISTS guacamole_user (
    user_id SERIAL PRIMARY KEY,
    username VARCHAR(128) NOT NULL UNIQUE,
    password_hash BYTEA NOT NULL,
    password_ BYTEA,
    password_date TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    disabled BOOLEAN NOT NULL DEFAULT FALSE,
    expired BOOLEAN NOT NULL DEFAULT FALSE,
    access_window_start TIME,
    access_window_end TIME,
    valid_from DATE,
    valid_until DATE,
    timezone VARCHAR(64),
    full_name VARCHAR(256),
    email_address VARCHAR(256),
    organization VARCHAR(256),
    organizational_role VARCHAR(256)
);

-- Insert default admin user (password: guacadmin)
INSERT INTO guacamole_user (username, password_hash, password_) 
SELECT 'guacadmin', 
       decode('CA458A7D494E3BE824F5E1E175A1556C0F8EEF2C2D7DF3633BEC4A29C4411960', 'hex'),
       decode('FE24ADC5E11E2B25288D1704ABE67A79E342ECC26064CE69C5B3177795A82264', 'hex')
WHERE NOT EXISTS (SELECT 1 FROM guacamole_user WHERE username = 'guacadmin');
`

		if err := sim.createFile(outputPath, basicSchema); err != nil {
			return fmt.Errorf("failed to create fallback schema: %w", err)
		}
	}

	return nil
}

// getGuacamoleStatus retrieves Apache Guacamole service status
func (sim *ServiceInstallationManager) getGuacamoleStatus(rc *eos_io.RuntimeContext, status *ServiceStatus) (*ServiceStatus, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Look for common Guacamole installation locations
	homeDir, _ := os.UserHomeDir()
	possibleLocations := []string{
		filepath.Join(homeDir, "guacamole", "docker-compose.yml"),
		"/opt/guacamole/docker-compose.yml",
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
	workDir := filepath.Dir(composePath)

	// Check container status
	cmd := sim.createCommandInDir(workDir, "docker-compose", "ps", "--format", "json")
	if output, err := cmd.Output(); err == nil {
		outputStr := string(output)
		if outputStr != "" && len(outputStr) > 10 {
			status.Status = "running"
		} else {
			status.Status = "stopped"
		}
	} else {
		status.Status = "unknown"
	}

	// Check health endpoint
	if status.Status == "running" {
		endpoint := "http://localhost:8080/guacamole"
		if healthCheck, err := sim.PerformHealthCheck(rc, ServiceTypeGuacamole, endpoint); err == nil {
			status.HealthCheck = healthCheck
		}
	}

	logger.Info("Apache Guacamole status retrieved",
		zap.String("status", status.Status),
		zap.String("compose_path", composePath))

	return status, nil
}
