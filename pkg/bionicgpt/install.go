// Package bionicgpt provides installation logic for BionicGPT
// following the Assess → Intervene → Evaluate pattern.
package bionicgpt

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/environment"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/secrets"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/telemetry"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// NewBionicGPTInstaller creates a new BionicGPT installer
func NewBionicGPTInstaller(rc *eos_io.RuntimeContext, config *InstallConfig) *BionicGPTInstaller {
	// Set defaults
	if config.InstallDir == "" {
		config.InstallDir = DefaultInstallDir
	}
	if config.ComposeFile == "" {
		config.ComposeFile = filepath.Join(config.InstallDir, "docker-compose.yml")
	}
	if config.EnvFile == "" {
		config.EnvFile = filepath.Join(config.InstallDir, ".env")
	}
	if config.Port == 0 {
		config.Port = shared.PortBionicGPT
	}
	if config.PostgresUser == "" {
		config.PostgresUser = DefaultPostgresUser
	}
	if config.PostgresDB == "" {
		config.PostgresDB = DefaultPostgresDB
	}
	if config.AppName == "" {
		config.AppName = DefaultAppName
	}
	if config.LogLevel == "" {
		config.LogLevel = DefaultLogLevel
	}
	if config.Timezone == "" {
		config.Timezone = DefaultTimezone
	}
	if config.AzureAPIVersion == "" {
		config.AzureAPIVersion = DefaultAzureAPIVersion
	}
	if config.EmbeddingsModel == "" {
		config.EmbeddingsModel = DefaultEmbeddingsModel
	}

	// Enable RAG and multi-tenant by default
	if !config.ForceReinstall {
		config.EnableRAG = true
		config.EnableMultiTenant = true
		config.EnableAuditLog = true
	}

	return &BionicGPTInstaller{
		rc:     rc,
		config: config,
	}
}

// Install installs BionicGPT following the Assess → Intervene → Evaluate pattern
func (bgi *BionicGPTInstaller) Install() error {
	ctx, span := telemetry.Start(bgi.rc.Ctx, "bionicgpt.Install")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Starting BionicGPT installation",
		zap.String("install_dir", bgi.config.InstallDir),
		zap.Int("port", bgi.config.Port))

	// ASSESS: Check current state
	state, err := bgi.assessInstallation(ctx)
	if err != nil {
		return fmt.Errorf("failed to assess installation state: %w", err)
	}

	logger.Info("Installation assessment completed",
		zap.Bool("installed", state.Installed),
		zap.Bool("running", state.Running),
		zap.Bool("compose_exists", state.ComposeFileExists),
		zap.Bool("env_exists", state.EnvFileExists))

	// Check if already installed and force not set
	if state.Installed && !bgi.config.ForceReinstall {
		return eos_err.NewUserError(
			"BionicGPT is already installed at %s\n"+
				"Use --force to reinstall",
			bgi.config.InstallDir)
	}

	// INTERVENE: Perform installation
	if err := bgi.performInstallation(ctx); err != nil {
		return fmt.Errorf("installation failed: %w", err)
	}

	// EVALUATE: Verify installation
	if !bgi.config.SkipHealthCheck {
		if err := bgi.verifyInstallation(ctx); err != nil {
			return fmt.Errorf("installation verification failed: %w", err)
		}
	}

	logger.Info("BionicGPT installation completed successfully",
		zap.String("access_url", fmt.Sprintf("http://localhost:%d", bgi.config.Port)))

	return nil
}

// assessInstallation checks the current state of BionicGPT
func (bgi *BionicGPTInstaller) assessInstallation(ctx context.Context) (*InstallState, error) {
	logger := otelzap.Ctx(ctx)
	logger.Debug("Assessing BionicGPT installation state")

	state := &InstallState{
		ContainerIDs:  make(map[string]string),
		HealthStatus:  make(map[string]string),
		VolumesExist:  []string{},
		ExistingPaths: []string{},
	}

	// Check if installation directory exists
	if _, err := os.Stat(bgi.config.InstallDir); err == nil {
		state.ExistingPaths = append(state.ExistingPaths, bgi.config.InstallDir)
		logger.Debug("Installation directory exists", zap.String("dir", bgi.config.InstallDir))
	}

	// Check if compose file exists
	if _, err := os.Stat(bgi.config.ComposeFile); err == nil {
		state.ComposeFileExists = true
		state.ExistingPaths = append(state.ExistingPaths, bgi.config.ComposeFile)
		logger.Debug("Compose file exists", zap.String("file", bgi.config.ComposeFile))
	}

	// Check if env file exists
	if _, err := os.Stat(bgi.config.EnvFile); err == nil {
		state.EnvFileExists = true
		state.ExistingPaths = append(state.ExistingPaths, bgi.config.EnvFile)
		logger.Debug("Environment file exists", zap.String("file", bgi.config.EnvFile))
	}

	// Check if Docker volumes exist
	volumes := []string{VolumePostgresData, VolumeDocuments}
	for _, volumeName := range volumes {
		volumeOutput, err := execute.Run(ctx, execute.Options{
			Command: "docker",
			Args:    []string{"volume", "inspect", volumeName},
			Capture: true,
		})
		if err == nil {
			state.VolumesExist = append(state.VolumesExist, volumeName)
			logger.Debug("Docker volume exists", zap.String("volume", volumeName))
		} else {
			logger.Debug("Docker volume does not exist",
				zap.String("volume", volumeName),
				zap.String("output", volumeOutput))
		}
	}

	// Check if containers exist (running or stopped)
	containers := []string{ContainerApp, ContainerPostgres, ContainerEmbeddings}
	for _, containerName := range containers {
		output, err := execute.Run(ctx, execute.Options{
			Command: "docker",
			Args:    []string{"ps", "-a", "--filter", fmt.Sprintf("name=%s", containerName), "--format", "{{.ID}}\t{{.Status}}"},
			Capture: true,
		})
		if err == nil && output != "" {
			parts := strings.Split(strings.TrimSpace(output), "\t")
			if len(parts) >= 1 {
				state.ContainerIDs[containerName] = parts[0]
				if len(parts) >= 2 {
					state.HealthStatus[containerName] = parts[1]
					if strings.Contains(parts[1], "Up") {
						state.Running = true
					}
				}
				logger.Debug("Container found",
					zap.String("container", containerName),
					zap.String("id", parts[0]))
			}
		}
	}

	// Determine if installation is complete
	state.Installed = len(state.ContainerIDs) > 0 || (state.ComposeFileExists && state.EnvFileExists && len(state.VolumesExist) > 0)

	logger.Info("Assessment complete",
		zap.Bool("installed", state.Installed),
		zap.Bool("running", state.Running),
		zap.Int("volumes_exist", len(state.VolumesExist)),
		zap.Int("existing_paths", len(state.ExistingPaths)),
		zap.Int("containers_found", len(state.ContainerIDs)))

	return state, nil
}

// performInstallation performs the actual installation steps
func (bgi *BionicGPTInstaller) performInstallation(ctx context.Context) error {
	logger := otelzap.Ctx(ctx)

	// Step 1: Check prerequisites
	logger.Info("Checking prerequisites")
	if err := bgi.checkPrerequisites(ctx); err != nil {
		return err
	}

	// Step 2: Discover environment for Vault integration
	logger.Info("Discovering environment")
	envConfig, err := environment.DiscoverEnvironment(bgi.rc)
	if err != nil {
		return fmt.Errorf("failed to discover environment: %w", err)
	}

	// Step 3: Initialize secret manager
	logger.Info("Initializing secret manager")
	secretManager, err := secrets.NewSecretManager(bgi.rc, envConfig)
	if err != nil {
		return fmt.Errorf("failed to initialize secret manager: %w", err)
	}

	// Step 4: Get Azure OpenAI configuration if not provided
	if err := bgi.getAzureConfiguration(ctx); err != nil {
		return err
	}

	// Step 5: Get or generate secrets from Vault
	logger.Info("Managing secrets via Vault")
	requiredSecrets := map[string]secrets.SecretType{
		"postgres_password": secrets.SecretTypePassword,
		"jwt_secret":        secrets.SecretTypeToken,
	}

	// Only manage Azure API key if not provided via flags
	if bgi.config.AzureAPIKey == "" {
		requiredSecrets["azure_api_key"] = secrets.SecretTypeAPIKey
	}

	serviceSecrets, err := secretManager.GetOrGenerateServiceSecrets("bionicgpt", requiredSecrets)
	if err != nil {
		return fmt.Errorf("failed to manage secrets: %w", err)
	}

	// Use secrets from Vault (with type assertions)
	if pw, ok := serviceSecrets.Secrets["postgres_password"].(string); ok {
		bgi.config.PostgresPassword = pw
	}
	if jwt, ok := serviceSecrets.Secrets["jwt_secret"].(string); ok {
		bgi.config.JWTSecret = jwt
	}
	if bgi.config.AzureAPIKey == "" {
		if apiKey, ok := serviceSecrets.Secrets["azure_api_key"].(string); ok {
			bgi.config.AzureAPIKey = apiKey
		}
	}

	logger.Info("Secrets retrieved from Vault",
		zap.String("backend", serviceSecrets.Backend))

	// Step 6: Create installation directory
	logger.Info("Creating installation directory", zap.String("dir", bgi.config.InstallDir))
	logger.Debug("Pre-operation: directory check",
		zap.String("target_dir", bgi.config.InstallDir),
		zap.String("compose_file", bgi.config.ComposeFile),
		zap.String("env_file", bgi.config.EnvFile))

	if err := os.MkdirAll(bgi.config.InstallDir, 0755); err != nil {
		return fmt.Errorf("failed to create installation directory: %w", err)
	}

	// Verify directory was created
	dirInfo, err := os.Stat(bgi.config.InstallDir)
	if err != nil {
		return fmt.Errorf("directory creation verification failed: %w", err)
	}
	logger.Debug("Post-operation: directory created",
		zap.String("path", bgi.config.InstallDir),
		zap.String("permissions", dirInfo.Mode().String()))

	// Step 7: Create .env file
	logger.Info("Creating environment configuration", zap.String("file", bgi.config.EnvFile))
	if err := bgi.createEnvFile(ctx); err != nil {
		return err
	}

	// Step 8: Create docker-compose.yml
	logger.Info("Creating Docker Compose configuration", zap.String("file", bgi.config.ComposeFile))
	logger.Debug("Pre-operation: compose file creation",
		zap.String("install_dir", bgi.config.InstallDir))
	if err := bgi.createComposeFile(ctx); err != nil {
		return err
	}
	logger.Debug("Post-operation: compose file created")

	// Step 9: Pull Docker images
	logger.Info("Pulling Docker images (this may take several minutes)")
	logger.Debug("Pre-operation: docker pull",
		zap.String("compose_file", bgi.config.ComposeFile))
	if err := bgi.pullDockerImages(ctx); err != nil {
		return err
	}
	logger.Debug("Post-operation: images pulled successfully")

	// Step 10: Start the service
	logger.Info("Starting BionicGPT services")
	logger.Debug("Pre-operation: service startup",
		zap.Int("port", bgi.config.Port))
	if err := bgi.startService(ctx); err != nil {
		return err
	}
	logger.Debug("Post-operation: services started successfully")

	return nil
}

// checkPrerequisites verifies that Docker and Docker Compose are installed
func (bgi *BionicGPTInstaller) checkPrerequisites(ctx context.Context) error {
	logger := otelzap.Ctx(ctx)

	// Check Docker
	logger.Debug("Checking for Docker")
	dockerVersion, err := execute.Run(ctx, execute.Options{
		Command: "docker",
		Args:    []string{"--version"},
		Capture: true,
	})
	if err != nil {
		return eos_err.NewUserError(
			"Docker is not installed\n" +
				"Please install Docker: https://docs.docker.com/get-docker/")
	}
	logger.Info("Docker is available", zap.String("version", strings.TrimSpace(dockerVersion)))

	// Check Docker Compose
	logger.Debug("Checking for Docker Compose")
	composeVersion, err := execute.Run(ctx, execute.Options{
		Command: "docker",
		Args:    []string{"compose", "version"},
		Capture: true,
	})
	if err != nil {
		return eos_err.NewUserError(
			"Docker Compose is not installed\n" +
				"Please install Docker Compose: https://docs.docker.com/compose/install/")
	}
	logger.Info("Docker Compose is available", zap.String("version", strings.TrimSpace(composeVersion)))

	// Check if Docker daemon is running
	logger.Debug("Checking if Docker daemon is running")
	_, err = execute.Run(ctx, execute.Options{
		Command: "docker",
		Args:    []string{"ps"},
		Capture: true,
	})
	if err != nil {
		return eos_err.NewUserError(
			"Docker daemon is not running\n" +
				"Please start Docker: sudo systemctl start docker")
	}
	logger.Debug("Docker daemon is running")

	// Check if port is available
	logger.Debug("Checking port availability", zap.Int("port", bgi.config.Port))
	output, err := execute.Run(ctx, execute.Options{
		Command: "sh",
		Args:    []string{"-c", fmt.Sprintf("ss -tuln | grep ':%d ' || true", bgi.config.Port)},
		Capture: true,
	})
	if err == nil && strings.TrimSpace(output) != "" {
		logger.Warn("Port is already in use",
			zap.Int("port", bgi.config.Port),
			zap.String("output", output))

		// Check if it's our own container
		containerCheck, _ := execute.Run(ctx, execute.Options{
			Command: "docker",
			Args:    []string{"ps", "--filter", fmt.Sprintf("name=%s", ContainerApp), "--format", "{{.Ports}}"},
			Capture: true,
		})

		if !strings.Contains(containerCheck, fmt.Sprintf("%d->", bgi.config.Port)) {
			return eos_err.NewUserError(
				"Port %d is already in use by another process\n"+
					"Either:\n"+
					"  1. Stop the process using: sudo ss -tulnp | grep ':%d'\n"+
					"  2. Use a different port with: --port XXXX",
				bgi.config.Port, bgi.config.Port)
		}
		logger.Debug("Port is used by our own BionicGPT container (acceptable)")
	} else {
		logger.Debug("Port is available", zap.Int("port", bgi.config.Port))
	}

	return nil
}

// getAzureConfiguration prompts for Azure OpenAI configuration if not provided
func (bgi *BionicGPTInstaller) getAzureConfiguration(ctx context.Context) error {
	logger := otelzap.Ctx(ctx)

	// If all required fields are provided, skip prompts
	if bgi.config.AzureEndpoint != "" && bgi.config.AzureDeployment != "" && bgi.config.AzureAPIKey != "" {
		logger.Debug("Azure configuration provided via flags")
		return nil
	}

	logger.Info("terminal prompt: Azure OpenAI configuration required")
	logger.Info("terminal prompt: You can find these in Azure Portal → Your OpenAI Resource → Keys and Endpoint")

	// Prompt for endpoint
	if bgi.config.AzureEndpoint == "" {
		logger.Info("terminal prompt: Enter Azure OpenAI Endpoint (e.g., https://myopenai.openai.azure.com)")
		endpoint, err := eos_io.PromptInput(bgi.rc, "Azure OpenAI Endpoint: ", "azure_endpoint")
		if err != nil {
			return fmt.Errorf("failed to read Azure endpoint: %w", err)
		}
		bgi.config.AzureEndpoint = shared.SanitizeURL(endpoint)
	} else {
		// Sanitize even if provided via flag
		bgi.config.AzureEndpoint = shared.SanitizeURL(bgi.config.AzureEndpoint)
	}

	// Prompt for deployment name
	if bgi.config.AzureDeployment == "" {
		logger.Info("terminal prompt: Enter Deployment Name (e.g., gpt-4)")
		deployment, err := eos_io.PromptInput(bgi.rc, "Deployment Name: ", "deployment_name")
		if err != nil {
			return fmt.Errorf("failed to read deployment name: %w", err)
		}
		bgi.config.AzureDeployment = strings.TrimSpace(deployment)
	}

	// Prompt for API key (only if not managing via Vault)
	if bgi.config.AzureAPIKey == "" {
		logger.Info("terminal prompt: Enter API Key (input will be hidden, or leave blank to use Vault)")
		apiKey, err := interaction.PromptSecret(ctx, "API Key (or Enter for Vault): ")
		if err != nil {
			return fmt.Errorf("failed to read API key: %w", err)
		}
		// If empty, will be retrieved from Vault later
		bgi.config.AzureAPIKey = strings.TrimSpace(apiKey)
	}

	logger.Debug("Azure configuration validated successfully")
	return nil
}

// createEnvFile creates the .env file with configuration
func (bgi *BionicGPTInstaller) createEnvFile(ctx context.Context) error {
	logger := otelzap.Ctx(ctx)

	content := fmt.Sprintf(`# BionicGPT Environment Configuration
# Generated by Eos - Code Monkey Cybersecurity
# Secrets managed by Vault

# PostgreSQL Configuration
POSTGRES_USER=%s
POSTGRES_PASSWORD=%s
POSTGRES_DB=%s

# Application Settings
APP_NAME=%s
LOG_LEVEL=%s
TZ=%s

# JWT Authentication
JWT_SECRET=%s

# Database Connection
APP_DATABASE_URL=postgresql://%s:%s@postgres:5432/%s?sslmode=disable

# Azure OpenAI Configuration
AZURE_OPENAI_ENDPOINT=%s
AZURE_OPENAI_DEPLOYMENT=%s
AZURE_OPENAI_API_KEY=%s
AZURE_OPENAI_API_VERSION=%s

# Feature Flags
ENABLE_RAG=%t
ENABLE_AUDIT_LOG=%t
ENABLE_MULTI_TENANT=%t

# Embeddings Configuration
EMBEDDINGS_MODEL=%s
`,
		bgi.config.PostgresUser,
		bgi.config.PostgresPassword,
		bgi.config.PostgresDB,
		bgi.config.AppName,
		bgi.config.LogLevel,
		bgi.config.Timezone,
		bgi.config.JWTSecret,
		"bionic_application",
		bgi.config.PostgresPassword,
		bgi.config.PostgresDB,
		bgi.config.AzureEndpoint,
		bgi.config.AzureDeployment,
		bgi.config.AzureAPIKey,
		bgi.config.AzureAPIVersion,
		bgi.config.EnableRAG,
		bgi.config.EnableAuditLog,
		bgi.config.EnableMultiTenant,
		bgi.config.EmbeddingsModel,
	)

	// Create .env file with appropriate permissions
	// 0640 = owner read/write, group read, others none
	if err := os.WriteFile(bgi.config.EnvFile, []byte(content), 0640); err != nil {
		return fmt.Errorf("failed to write .env file: %w", err)
	}

	// Attempt to set docker group ownership (best effort - may not exist)
	_, _ = execute.Run(ctx, execute.Options{
		Command: "chgrp",
		Args:    []string{"docker", bgi.config.EnvFile},
		Capture: true,
	})

	logger.Debug(".env file created",
		zap.String("path", bgi.config.EnvFile),
		zap.String("permissions", "0640"))
	return nil
}

// createComposeFile creates the docker-compose.yml file
func (bgi *BionicGPTInstaller) createComposeFile(ctx context.Context) error {
	logger := otelzap.Ctx(ctx)

	// Generate docker-compose.yml for Azure OpenAI (no local LLM)
	content := bgi.generateComposeContent()

	if err := os.WriteFile(bgi.config.ComposeFile, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write docker-compose.yml: %w", err)
	}

	logger.Debug("docker-compose.yml created", zap.String("path", bgi.config.ComposeFile))
	return nil
}

// generateComposeContent generates the docker-compose.yml content for Azure OpenAI
func (bgi *BionicGPTInstaller) generateComposeContent() string {
	return fmt.Sprintf(`# BionicGPT Docker Compose Configuration
# Generated by Eos - Code Monkey Cybersecurity
# Port: %d
# Version: %s
# LLM: Azure OpenAI

services:
  # Embeddings API - Document embeddings
  embeddings-api:
    image: %s:%s
    container_name: %s
    platform: linux/amd64
    networks:
      - bionicgpt-network
    restart: unless-stopped

  # Document chunking engine
  chunking-engine:
    image: %s:%s
    container_name: %s
    platform: linux/amd64
    networks:
      - bionicgpt-network
    restart: unless-stopped

  # PostgreSQL with pgVector
  postgres:
    image: %s
    container_name: %s
    platform: linux/amd64
    environment:
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      POSTGRES_USER: ${POSTGRES_USER}
      POSTGRES_DB: ${POSTGRES_DB}
    volumes:
      - %s:/var/lib/postgresql/data
    networks:
      - bionicgpt-network
    restart: unless-stopped
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER}"]
      interval: 10s
      timeout: 5s
      retries: 10
      start_period: 30s
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

  # Database migrations
  migrations:
    image: %s:%s
    container_name: %s
    platform: linux/amd64
    environment:
      DATABASE_URL: postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@postgres:5432/${POSTGRES_DB}?sslmode=disable
    networks:
      - bionicgpt-network
    depends_on:
      postgres:
        condition: service_healthy

  # RAG Engine - Document processing and retrieval
  rag-engine:
    image: %s:%s
    container_name: %s
    platform: linux/amd64
    environment:
      APP_DATABASE_URL: ${APP_DATABASE_URL}
    networks:
      - bionicgpt-network
    volumes:
      - %s:/documents
    depends_on:
      postgres:
        condition: service_healthy
      migrations:
        condition: service_completed_successfully
    restart: unless-stopped

  # Main application - Web interface with Azure OpenAI integration
  app:
    image: %s:%s
    container_name: %s
    platform: linux/amd64
    environment:
      APP_DATABASE_URL: ${APP_DATABASE_URL}
      JWT_SECRET: ${JWT_SECRET}
      LOG_LEVEL: ${LOG_LEVEL}
      TZ: ${TZ}
      # Azure OpenAI Configuration
      AZURE_OPENAI_ENDPOINT: ${AZURE_OPENAI_ENDPOINT}
      AZURE_OPENAI_DEPLOYMENT: ${AZURE_OPENAI_DEPLOYMENT}
      AZURE_OPENAI_API_KEY: ${AZURE_OPENAI_API_KEY}
      AZURE_OPENAI_API_VERSION: ${AZURE_OPENAI_API_VERSION}
    ports:
      - "%d:7703"
    networks:
      - bionicgpt-network
    depends_on:
      postgres:
        condition: service_healthy
      migrations:
        condition: service_completed_successfully
    restart: unless-stopped
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:7703/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 60s

volumes:
  %s:
    driver: local
  %s:
    driver: local

networks:
  bionicgpt-network:
    driver: bridge
`,
		// Header info
		bgi.config.Port,
		DefaultBionicGPTVersion,
		// Embeddings service
		ImageEmbeddings,
		VersionEmbeddings,
		ContainerEmbeddings,
		// Chunking service
		ImageChunking,
		VersionChunking,
		ContainerChunking,
		// PostgreSQL
		ImagePostgreSQL,
		ContainerPostgres,
		VolumePostgresData,
		// Migrations
		ImageMigrations,
		DefaultBionicGPTVersion,
		ContainerMigrations,
		// RAG Engine
		ImageRAGEngine,
		DefaultBionicGPTVersion,
		ContainerRAGEngine,
		VolumeDocuments,
		// App (with Azure OpenAI)
		ImageBionicGPT,
		DefaultBionicGPTVersion,
		ContainerApp,
		bgi.config.Port,
		// Volumes
		VolumePostgresData,
		VolumeDocuments,
	)
}

// pullDockerImages pulls all required Docker images
func (bgi *BionicGPTInstaller) pullDockerImages(ctx context.Context) error {
	logger := otelzap.Ctx(ctx)

	logger.Info("Pulling Docker images (this may take 5-10 minutes)")
	logger.Info("Note: SSH connection may appear to hang - this is normal for large image downloads")
	logger.Debug("Executing docker compose pull",
		zap.String("command", "docker"),
		zap.Strings("args", []string{"compose", "-f", bgi.config.ComposeFile, "pull"}),
		zap.String("working_dir", bgi.config.InstallDir))

	output, err := execute.Run(ctx, execute.Options{
		Command: "docker",
		Args:    []string{"compose", "-f", bgi.config.ComposeFile, "pull"},
		Dir:     bgi.config.InstallDir,
		Capture: true,
		Timeout: 30 * time.Minute, // 30 minutes for large images (embeddings, chunking, etc.)
	})

	if err != nil {
		logger.Warn("Docker pull reported an error", zap.Error(err))
		return fmt.Errorf("failed to pull Docker images: %s", output)
	}

	logger.Debug("Docker images pulled successfully")
	return nil
}

// startService starts the BionicGPT services
func (bgi *BionicGPTInstaller) startService(ctx context.Context) error {
	logger := otelzap.Ctx(ctx)

	logger.Info("Starting containers with docker compose up")
	logger.Debug("Executing docker compose up",
		zap.String("command", "docker"),
		zap.Strings("args", []string{"compose", "-f", bgi.config.ComposeFile, "up", "-d"}),
		zap.String("working_dir", bgi.config.InstallDir),
		zap.Duration("timeout", 10*time.Minute))

	output, err := execute.Run(ctx, execute.Options{
		Command: "docker",
		Args:    []string{"compose", "-f", bgi.config.ComposeFile, "up", "-d"},
		Dir:     bgi.config.InstallDir,
		Capture: true,
		Timeout: 10 * time.Minute,
	})

	if err != nil {
		logger.Error("Docker compose failed", zap.Error(err), zap.String("output", output))
		return fmt.Errorf("failed to start services: %s", output)
	}

	logger.Info("Services started successfully")
	logger.Debug("Post-operation: all containers started")
	return nil
}

// verifyInstallation verifies that BionicGPT is running correctly
// Uses comprehensive validator with Docker SDK and multi-tenancy checks
func (bgi *BionicGPTInstaller) verifyInstallation(ctx context.Context) error {
	logger := otelzap.Ctx(ctx)
	logger.Info("Verifying installation with comprehensive validation")

	// Wait for services to be ready (database initialization can take time)
	logger.Info("Waiting for services to initialize (this may take 1-2 minutes)")
	time.Sleep(60 * time.Second)

	// Create comprehensive validator
	validator, err := NewValidator(bgi.rc, bgi.config)
	if err != nil {
		return fmt.Errorf("failed to create validator: %w", err)
	}
	defer validator.Close()

	// Run comprehensive validation
	result, err := validator.ValidateDeployment(ctx)
	if err != nil {
		return fmt.Errorf("validation execution failed: %w", err)
	}

	// Display validation results
	bgi.displayValidationResults(ctx, result)

	// Check for critical errors
	if !result.OverallHealth {
		logger.Error("Installation validation failed - critical issues detected")
		return fmt.Errorf("installation validation failed: %d errors, %d warnings",
			len(result.Errors), len(result.Warnings))
	}

	logger.Info("BionicGPT installation verified successfully",
		zap.String("access_url", fmt.Sprintf("http://localhost:%d", bgi.config.Port)))

	return nil
}

// displayValidationResults shows detailed validation results to the user
func (bgi *BionicGPTInstaller) displayValidationResults(ctx context.Context, result *ValidationResult) {
	logger := otelzap.Ctx(ctx)

	logger.Info("================================================================================")
	logger.Info("BionicGPT Validation Results")
	logger.Info("================================================================================")

	// Resource Check
	if result.ResourceCheck != nil {
		logger.Info("Resource Availability:")
		logger.Info(fmt.Sprintf("  CPU Cores:    %d", result.ResourceCheck.CPUCores))
		logger.Info(fmt.Sprintf("  Memory (GB):  %.1f", result.ResourceCheck.MemoryTotalGB))
		logger.Info(fmt.Sprintf("  Status:       %s", bgi.statusString(result.ResourceCheck.MeetsMinimum)))
		if len(result.ResourceCheck.Issues) > 0 {
			for _, issue := range result.ResourceCheck.Issues {
				logger.Warn(fmt.Sprintf("    ⚠ %s", issue))
			}
		}
	}

	// Container Check
	if result.ContainerCheck != nil {
		logger.Info("")
		logger.Info("Container Health:")
		logger.Info(fmt.Sprintf("  Application:  %s", bgi.statusString(result.ContainerCheck.AppRunning)))
		logger.Info(fmt.Sprintf("  PostgreSQL:   %s", bgi.statusString(result.ContainerCheck.PostgresRunning)))
		logger.Info(fmt.Sprintf("  Embeddings:   %s", bgi.statusString(result.ContainerCheck.EmbeddingsRunning)))
		logger.Info(fmt.Sprintf("  RAG Engine:   %s", bgi.statusString(result.ContainerCheck.RAGEngineRunning)))
		logger.Info(fmt.Sprintf("  Chunking:     %s", bgi.statusString(result.ContainerCheck.ChunkingRunning)))
	}

	// PostgreSQL and RLS Check
	if result.PostgreSQLCheck != nil {
		logger.Info("")
		logger.Info("PostgreSQL & Multi-Tenancy:")
		logger.Info(fmt.Sprintf("  Connected:        %s", bgi.statusString(result.PostgreSQLCheck.Connected)))
		logger.Info(fmt.Sprintf("  RLS Enabled:      %s", bgi.statusString(result.PostgreSQLCheck.RLSEnabled)))
		logger.Info(fmt.Sprintf("  RLS Policies:     %d", len(result.PostgreSQLCheck.RLSPolicies)))
		logger.Info(fmt.Sprintf("  pgVector:         %s", bgi.statusString(result.PostgreSQLCheck.PgVectorInstalled)))
		if len(result.PostgreSQLCheck.RLSPolicies) > 0 {
			for _, policy := range result.PostgreSQLCheck.RLSPolicies {
				logger.Info(fmt.Sprintf("    • %s", policy))
			}
		}
		if len(result.PostgreSQLCheck.Issues) > 0 {
			for _, issue := range result.PostgreSQLCheck.Issues {
				logger.Warn(fmt.Sprintf("    ⚠ %s", issue))
			}
		}
	}

	// Multi-Tenancy Check
	if result.MultiTenancyCheck != nil {
		logger.Info("")
		logger.Info("Multi-Tenancy Features:")
		logger.Info(fmt.Sprintf("  Teams Table:      %s", bgi.statusString(result.MultiTenancyCheck.TeamsTableExists)))
		logger.Info(fmt.Sprintf("  Users Table:      %s", bgi.statusString(result.MultiTenancyCheck.UsersTableExists)))
		logger.Info(fmt.Sprintf("  RLS Enforced:     %s", bgi.statusString(result.MultiTenancyCheck.RLSEnforced)))
		if len(result.MultiTenancyCheck.Issues) > 0 {
			for _, issue := range result.MultiTenancyCheck.Issues {
				logger.Warn(fmt.Sprintf("    ⚠ %s", issue))
			}
		}
	}

	// Audit Log Check
	if result.AuditLogCheck != nil {
		logger.Info("")
		logger.Info("Audit Logging:")
		logger.Info(fmt.Sprintf("  Table Exists:     %s", bgi.statusString(result.AuditLogCheck.AuditTableExists)))
		logger.Info(fmt.Sprintf("  Logs Writing:     %s", bgi.statusString(result.AuditLogCheck.LogsBeingWritten)))
		logger.Info(fmt.Sprintf("  Recent Entries:   %d", result.AuditLogCheck.RecentEntryCount))
		if len(result.AuditLogCheck.Issues) > 0 {
			for _, issue := range result.AuditLogCheck.Issues {
				logger.Warn(fmt.Sprintf("    ⚠ %s", issue))
			}
		}
	}

	// RAG Pipeline Check
	if result.RAGPipelineCheck != nil {
		logger.Info("")
		logger.Info("RAG Pipeline:")
		logger.Info(fmt.Sprintf("  Documents Volume: %s", bgi.statusString(result.RAGPipelineCheck.DocumentsVolumeExists)))
		logger.Info(fmt.Sprintf("  Embeddings:       %s", bgi.statusString(result.RAGPipelineCheck.EmbeddingsServiceHealthy)))
		logger.Info(fmt.Sprintf("  Chunking:         %s", bgi.statusString(result.RAGPipelineCheck.ChunkingServiceHealthy)))
		logger.Info(fmt.Sprintf("  RAG Engine:       %s", bgi.statusString(result.RAGPipelineCheck.RAGEngineHealthy)))
		if len(result.RAGPipelineCheck.Issues) > 0 {
			for _, issue := range result.RAGPipelineCheck.Issues {
				logger.Warn(fmt.Sprintf("    ⚠ %s", issue))
			}
		}
	}

	// Summary
	logger.Info("")
	logger.Info("Overall Status:")
	if result.OverallHealth {
		logger.Info("  ✓ All critical checks passed")
	} else {
		logger.Error("  ✗ Critical issues detected")
	}
	logger.Info(fmt.Sprintf("  Errors:   %d", len(result.Errors)))
	logger.Info(fmt.Sprintf("  Warnings: %d", len(result.Warnings)))

	if len(result.Errors) > 0 {
		logger.Info("")
		logger.Info("Critical Errors:")
		for _, err := range result.Errors {
			logger.Error(fmt.Sprintf("  • %s", err))
		}
	}

	if len(result.Warnings) > 0 {
		logger.Info("")
		logger.Info("Warnings:")
		for _, warn := range result.Warnings {
			logger.Warn(fmt.Sprintf("  • %s", warn))
		}
	}

	logger.Info("================================================================================")
}

// statusString converts boolean to status string
func (bgi *BionicGPTInstaller) statusString(status bool) string {
	if status {
		return "✓ OK"
	}
	return "✗ FAILED"
}
