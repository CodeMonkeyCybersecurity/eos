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

	"github.com/CodeMonkeyCybersecurity/eos/pkg/azure"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/container"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/docker"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/environment"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/ollama"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/preflight"
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
	if config.LiteLLMPort == 0 {
		config.LiteLLMPort = DefaultLiteLLMPort
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
	// NOTE: Preflight checks moved inside performInstallation() so they run AFTER
	// secrets are retrieved from Vault. This prevents false validation failures
	// for secrets that haven't been populated yet.
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

	// Step 1: Check prerequisites (Docker, ports) with human-centric informed consent
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

	// Step 3: Get embeddings configuration (local or Azure)
	if err := bgi.configureEmbeddings(ctx); err != nil {
		return err
	}

	// Step 4: Get Azure OpenAI configuration
	// Note: Azure package now initializes secret manager internally
	if err := bgi.getAzureConfiguration(ctx); err != nil {
		return err
	}

	// Step 5: Initialize secret manager for service secrets
	logger.Info("Initializing secret manager")
	secretManager, err := secrets.NewSecretManager(bgi.rc, envConfig)
	if err != nil {
		return fmt.Errorf("failed to initialize secret manager: %w", err)
	}

	// Step 6: Get or generate secrets from Vault
	logger.Info("Managing secrets via Vault")
	requiredSecrets := map[string]secrets.SecretType{
		"postgres_password":  secrets.SecretTypePassword,
		"jwt_secret":         secrets.SecretTypeToken,
		"litellm_master_key": secrets.SecretTypeAPIKey, // LiteLLM proxy master key
	}

	// Only manage Azure API key if not provided via flags
	if bgi.config.AzureAPIKey == "" {
		requiredSecrets["azure_api_key"] = secrets.SecretTypeAPIKey
	}

	serviceSecrets, err := secretManager.GetOrGenerateServiceSecrets(VaultServiceName, requiredSecrets)
	if err != nil {
		return fmt.Errorf("failed to manage secrets: %w", err)
	}

	// Use secrets from Vault (with typed accessors - no manual type assertions!)
	bgi.config.PostgresPassword = serviceSecrets.GetString("postgres_password")
	bgi.config.JWTSecret = serviceSecrets.GetString("jwt_secret")
	bgi.config.LiteLLMMasterKey = serviceSecrets.GetString("litellm_master_key")

	// Only use Azure API key from Vault if not provided via flag
	if bgi.config.AzureAPIKey == "" {
		bgi.config.AzureAPIKey = serviceSecrets.GetString("azure_api_key")
	}

	logger.Info("Secrets retrieved from Vault",
		zap.String("backend", serviceSecrets.Backend))

	// Step 7: NOW run preflight validation with all config populated
	// This validates the COMPLETE configuration, including secrets from Vault
	logger.Info("")
	logger.Info("Running pre-deployment validation with complete configuration...")
	preflightResult, err := bgi.runPreflightChecks(ctx)
	if err != nil {
		return fmt.Errorf("pre-flight checks failed: %w", err)
	}

	if !preflightResult.Passed {
		return eos_err.NewUserError(
			"Pre-deployment validation failed with %d error(s)\n"+
				"Please fix the errors above before retrying installation",
			len(preflightResult.Errors))
	}

	logger.Info("")
	logger.Info("✓ Pre-deployment validation passed - safe to proceed")
	logger.Info("")

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

	// Step 7: Create LiteLLM configuration files
	logger.Info("Creating LiteLLM proxy configuration")
	if err := bgi.createLiteLLMConfig(ctx); err != nil {
		return fmt.Errorf("failed to create LiteLLM config: %w", err)
	}
	if err := bgi.createLiteLLMEnvFile(ctx); err != nil {
		return fmt.Errorf("failed to create LiteLLM env file: %w", err)
	}

	// Step 8: Create database initialization script
	// SHIFT-LEFT FIX: Automate database user creation instead of manual post-deployment step
	logger.Info("Creating database initialization script")
	if err := bgi.createDatabaseInitScript(ctx); err != nil {
		return fmt.Errorf("failed to create database init script: %w", err)
	}

	// Step 9: Create .env file
	logger.Info("Creating environment configuration", zap.String("file", bgi.config.EnvFile))
	if err := bgi.createEnvFile(ctx); err != nil {
		return err
	}

	// Step 10: Create docker-compose.yml
	logger.Info("Creating Docker Compose configuration", zap.String("file", bgi.config.ComposeFile))
	logger.Debug("Pre-operation: compose file creation",
		zap.String("install_dir", bgi.config.InstallDir))
	if err := bgi.createComposeFile(ctx); err != nil {
		return err
	}
	logger.Debug("Post-operation: compose file created")

	// Step 11: Pull Docker images
	logger.Debug("Pre-operation: docker pull",
		zap.String("compose_file", bgi.config.ComposeFile))
	if err := bgi.pullDockerImages(ctx); err != nil {
		return err
	}
	logger.Debug("Post-operation: images pulled successfully")

	// Step 12: Start the service with phased deployment
	// The database init script will automatically create bionic_application user
	// on first startup, so no manual user creation needed
	logger.Info("Starting BionicGPT services")
	logger.Info("Database will automatically create application user on first startup")
	logger.Debug("Pre-operation: service startup",
		zap.Int("port", bgi.config.Port))
	if err := bgi.startService(ctx); err != nil {
		return err
	}
	logger.Debug("Post-operation: services started successfully")

	// Step 13: Post-deployment verification
	// SHIFT-LEFT: Comprehensive verification immediately after deployment
	logger.Info("")
	logger.Info("Running post-deployment verification...")
	verificationResult, err := bgi.runPostDeploymentVerification(ctx)
	if err != nil {
		return fmt.Errorf("post-deployment verification failed: %w", err)
	}

	// Don't fail on warnings, but report them
	if len(verificationResult.Issues) > 0 {
		logger.Warn(fmt.Sprintf("Deployment completed with %d issue(s)", len(verificationResult.Issues)))
		logger.Info("Services may need a few more minutes to fully initialize")
	}

	// Note: Database user creation is automated via init script
	logger.Info("Database initialization complete (automated via init script)")

	return nil
}

// checkPrerequisites verifies that Docker and Docker Compose are installed
// Following P0 human-centric pattern: leverages pkg/container for comprehensive Docker setup
func (bgi *BionicGPTInstaller) checkPrerequisites(ctx context.Context) error {
	logger := otelzap.Ctx(ctx)

	// Use existing pkg/container functionality for Docker installation
	// This handles: checking, prompting, installing, group setup, and verification
	logger.Info("Checking Docker installation (will offer to install if missing)")
	if err := container.EnsureDockerInstalled(bgi.rc); err != nil {
		return fmt.Errorf("Docker is required for BionicGPT: %w", err)
	}

	logger.Info("Docker is installed and running")

	// Check Docker Compose (usually bundled with modern Docker)
	logger.Debug("Checking for Docker Compose")
	if err := container.CheckIfDockerComposeInstalled(bgi.rc); err != nil {
		return eos_err.NewUserError(
			"Docker Compose is not installed\n" +
				"Docker Compose is usually included with Docker Desktop.\n" +
				"Please install Docker Compose: https://docs.docker.com/compose/install/")
	}
	logger.Info("Docker Compose is available")

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

// configureEmbeddings determines embeddings strategy (local vs Azure)
// and runs appropriate preflight checks
// Following ASSESS → INTERVENE → EVALUATE pattern
func (bgi *BionicGPTInstaller) configureEmbeddings(ctx context.Context) error {
	logger := otelzap.Ctx(ctx)

	// If embeddings choice already made via flags, validate and return
	if bgi.config.UseLocalEmbeddings {
		logger.Info("Local embeddings selected via flags, validating Ollama setup")
		return bgi.setupLocalEmbeddings(ctx)
	}

	// If Azure embeddings deployment provided, use Azure
	if bgi.config.AzureEmbeddingsDeployment != "" {
		logger.Info("Azure embeddings deployment provided via flags")
		bgi.config.UseLocalEmbeddings = false
		return nil
	}

	// Interactive: Ask user which embeddings backend to use
	logger.Info("terminal prompt: Embeddings Configuration")
	logger.Info("terminal prompt: BionicGPT needs embeddings for document search (RAG)")
	logger.Info("terminal prompt:")
	logger.Info("terminal prompt: Options:")
	logger.Info("terminal prompt:   1. Local embeddings (via Ollama) - FREE, requires ~1GB RAM")
	logger.Info("terminal prompt:   2. Azure OpenAI embeddings - PAID, higher quality")
	logger.Info("terminal prompt:")

	useLocal := interaction.PromptYesNo(ctx, "Use local embeddings (Ollama)?", true)
	bgi.config.UseLocalEmbeddings = useLocal

	if useLocal {
		return bgi.setupLocalEmbeddings(ctx)
	}

	logger.Info("Azure embeddings selected - will prompt for deployment name")
	return nil
}

// setupLocalEmbeddings configures and validates local embeddings via Ollama
// Following ASSESS → INTERVENE → EVALUATE pattern with human-centric informed consent
func (bgi *BionicGPTInstaller) setupLocalEmbeddings(ctx context.Context) error {
	logger := otelzap.Ctx(ctx)

	logger.Info("=== ASSESS: Checking Ollama availability ===")

	// Use human-centric dependency checking with informed consent
	depConfig := interaction.DependencyConfig{
		Name:          "Ollama",
		Description:   "Local LLM server for embeddings (document search). Runs models locally for FREE.",
		CheckCommand:  "curl",
		CheckArgs:     []string{"-s", "http://localhost:11434/api/version"},
		InstallCmd:    "curl -fsSL https://ollama.ai/install.sh | sh",
		StartCmd:      "ollama serve &",
		Required:      true,
		AutoInstall:   true,  // Safe to auto-install via official script
		AutoStart:     false, // Let user start manually (daemon management varies)
		CustomCheckFn: preflight.CheckOllama,
	}

	result, err := interaction.CheckDependencyWithPrompt(bgi.rc, depConfig)
	if err != nil {
		// Add context about Azure alternative
		return fmt.Errorf("%w\n\n"+
			"Alternative: Use Azure OpenAI embeddings instead:\n"+
			"  eos create bionicgpt --azure-embeddings-deployment <deployment-name>",
			err)
	}

	if !result.Found {
		// User declined or dependency not available
		return eos_err.NewUserError(
			"Ollama is required for local embeddings.\n\n" +
				"Alternative: Use Azure OpenAI embeddings:\n" +
				"  eos create bionicgpt --azure-embeddings-deployment <deployment-name>")
	}

	logger.Info("✓ Ollama is accessible")

	// Set defaults for local embeddings
	if bgi.config.LocalEmbeddingsModel == "" {
		bgi.config.LocalEmbeddingsModel = DefaultLocalEmbeddingsModel
	}
	if bgi.config.OllamaEndpoint == "" {
		bgi.config.OllamaEndpoint = DefaultOllamaEndpoint
	}

	logger.Info("=== INTERVENE: Ensuring embeddings model is available ===")

	// Check if model exists, pull if necessary
	ollamaClient := ollama.NewClient(bgi.config.OllamaEndpoint)

	hasModel, err := ollamaClient.HasModel(ctx, bgi.config.LocalEmbeddingsModel)
	if err != nil {
		return fmt.Errorf("failed to check for model: %w", err)
	}

	if hasModel {
		logger.Info("✓ Embeddings model already available",
			zap.String("model", bgi.config.LocalEmbeddingsModel))
	} else {
		// Get model info for size estimate
		logger.Info("terminal prompt: Model not found, need to download")
		logger.Info("terminal prompt:", zap.String("model", bgi.config.LocalEmbeddingsModel))
		logger.Info("terminal prompt: Size: ~274MB")

		shouldPull := interaction.PromptYesNo(ctx,
			fmt.Sprintf("Pull %s model now?", bgi.config.LocalEmbeddingsModel),
			true)

		if !shouldPull {
			const modelRequiredMsg = "Embeddings model is required but not available.\n" +
				"Please pull the model manually:\n" +
				"  ollama pull %s"
			return fmt.Errorf(modelRequiredMsg, bgi.config.LocalEmbeddingsModel)
		}

		// Pull the model with progress
		logger.Info("Pulling embeddings model (this may take a few minutes)...",
			zap.String("model", bgi.config.LocalEmbeddingsModel))

		err = ollamaClient.PullModel(ctx, bgi.config.LocalEmbeddingsModel, func(progress ollama.PullProgress) {
			if progress.Total > 0 {
				percent := (progress.Completed * 100) / progress.Total
				if percent%10 == 0 { // Log every 10%
					logger.Info("Download progress",
						zap.Int64("percent", percent),
						zap.String("status", progress.Status))
				}
			}
		})

		if err != nil {
			return fmt.Errorf("failed to pull model: %w", err)
		}

		logger.Info("✓ Model downloaded successfully",
			zap.String("model", bgi.config.LocalEmbeddingsModel))
	}

	logger.Info("=== EVALUATE: Local embeddings configured successfully ===",
		zap.String("model", bgi.config.LocalEmbeddingsModel),
		zap.String("endpoint", bgi.config.OllamaEndpoint))

	return nil
}

// getAzureConfiguration uses centralized pkg/azure for Azure OpenAI configuration
// with smart URL parsing, validation, and Vault/Consul integration
func (bgi *BionicGPTInstaller) getAzureConfiguration(ctx context.Context) error {
	logger := otelzap.Ctx(ctx)

	// Create existing config from flags (if provided)
	existingConfig := &azure.OpenAIConfig{
		Endpoint:             bgi.config.AzureEndpoint,
		ChatDeployment:       bgi.config.AzureChatDeployment,
		EmbeddingsDeployment: bgi.config.AzureEmbeddingsDeployment,
		APIKey:               bgi.config.AzureAPIKey,
		APIVersion:           bgi.config.AzureAPIVersion,
		ServiceName:          "bionicgpt",
		Environment:          "production", // TODO: Get from environment discovery
	}

	// Create Azure OpenAI configuration manager
	// Pass nil for secretManager - Azure package will initialize it internally via environment discovery
	azureManager := azure.NewConfigManager(bgi.rc, nil, "bionicgpt")

	// Configure Azure OpenAI (handles validation, auto-detection, etc.)
	azureConfig, err := azureManager.Configure(ctx, existingConfig)
	if err != nil {
		return fmt.Errorf("failed to configure Azure OpenAI: %w", err)
	}

	// Handle local embeddings override
	if bgi.config.UseLocalEmbeddings {
		logger.Info("Using local embeddings (Ollama), overriding Azure embeddings deployment")
		azureConfig.EmbeddingsDeployment = "local" // Placeholder for LiteLLM config
	}

	// Update BionicGPT config with validated Azure config
	bgi.config.AzureEndpoint = azureConfig.Endpoint
	bgi.config.AzureChatDeployment = azureConfig.ChatDeployment
	bgi.config.AzureEmbeddingsDeployment = azureConfig.EmbeddingsDeployment
	bgi.config.AzureAPIKey = azureConfig.APIKey
	bgi.config.AzureAPIVersion = azureConfig.APIVersion

	logger.Info("Azure OpenAI configuration completed successfully",
		zap.String("endpoint", azure.RedactEndpoint(azureConfig.Endpoint)),
		zap.String("chat_deployment", azureConfig.ChatDeployment),
		zap.String("embeddings_deployment", azureConfig.EmbeddingsDeployment))

	return nil
}

// createEnvFile creates the .env file with configuration
// Now configured to use LiteLLM proxy instead of direct Azure connection
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

# LiteLLM Proxy Configuration
LITELLM_MASTER_KEY=%s

# OpenAI Configuration (via LiteLLM Proxy)
# LiteLLM translates OpenAI format to Azure OpenAI format
OPENAI_API_BASE=http://litellm-proxy:4000
OPENAI_API_KEY=%s
OPENAI_MODEL=gpt-4

# Feature Flags
ENABLE_RAG=%t
ENABLE_AUDIT_LOG=%t
ENABLE_MULTI_TENANT=%t

# Embeddings Configuration (via LiteLLM)
EMBEDDINGS_API_BASE=http://litellm-proxy:4000
EMBEDDINGS_API_KEY=%s
EMBEDDINGS_MODEL=text-embedding-ada-002
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
		bgi.config.LiteLLMMasterKey, // LITELLM_MASTER_KEY
		bgi.config.LiteLLMMasterKey, // OPENAI_API_KEY
		bgi.config.EnableRAG,
		bgi.config.EnableAuditLog,
		bgi.config.EnableMultiTenant,
		bgi.config.LiteLLMMasterKey, // EMBEDDINGS_API_KEY
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
      - ./%s:%s:ro  # SHIFT-LEFT: Automated user creation via init script
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

  # LiteLLM Proxy - Translates OpenAI format to Azure OpenAI / Ollama
  litellm-proxy:
    image: %s:%s
    container_name: %s
    platform: linux/amd64
    environment:
      LITELLM_MASTER_KEY: ${LITELLM_MASTER_KEY}
    env_file:
      - .env.litellm
    volumes:
      - ./litellm_config.yaml:/app/config.yaml
    command: ["--config", "/app/config.yaml", "--port", "4000", "--num_workers", "8"]
    ports:
      - "%d:4000"
    extra_hosts:
      - "host.docker.internal:host-gateway"
    networks:
      - bionicgpt-network
    restart: unless-stopped
    healthcheck:
      # SHIFT-LEFT FIX: More tolerant health check configuration
      # - Increased start_period: 90s (was 30s) - allows Azure OpenAI connection time
      # - Increased retries: 5 (was 3) - more tolerant of transient failures
      # - Increased interval: 60s (was 30s) - reduce check frequency
      test: ["CMD", "curl", "-f", "http://localhost:4000/health"]
      interval: 60s
      timeout: 10s
      retries: 5
      start_period: 90s
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

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
      # OpenAI Configuration (via LiteLLM Proxy)
      OPENAI_API_BASE: ${OPENAI_API_BASE}
      OPENAI_API_KEY: ${OPENAI_API_KEY}
      OPENAI_MODEL: ${OPENAI_MODEL}
      # Embeddings Configuration (via LiteLLM)
      EMBEDDINGS_API_BASE: ${EMBEDDINGS_API_BASE}
      EMBEDDINGS_API_KEY: ${EMBEDDINGS_API_KEY}
      EMBEDDINGS_MODEL: ${EMBEDDINGS_MODEL}
    ports:
      - "%d:7703"
    networks:
      - bionicgpt-network
    depends_on:
      postgres:
        condition: service_healthy
      migrations:
        condition: service_completed_successfully
      litellm-proxy:
        condition: service_healthy
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
		InitScriptFilename,   // Init script filename
		InitScriptDockerPath, // Init script mount path
		// Migrations
		ImageMigrations,
		DefaultBionicGPTVersion,
		ContainerMigrations,
		// RAG Engine
		ImageRAGEngine,
		DefaultBionicGPTVersion,
		ContainerRAGEngine,
		VolumeDocuments,
		// LiteLLM proxy
		ImageLiteLLM,
		VersionLiteLLM,
		ContainerLiteLLM,
		bgi.config.LiteLLMPort,
		// App (with Azure OpenAI via LiteLLM)
		ImageBionicGPT,
		DefaultBionicGPTVersion,
		ContainerApp,
		bgi.config.Port,
		// Volumes
		VolumePostgresData,
		VolumeDocuments,
	)
}

// pullDockerImages pulls all required Docker images with real progress tracking
func (bgi *BionicGPTInstaller) pullDockerImages(ctx context.Context) error {
	logger := otelzap.Ctx(ctx)

	logger.Info("Pulling Docker images with real progress tracking",
		zap.String("compose_file", bgi.config.ComposeFile))

	// Use real Docker SDK progress tracking instead of fake timers
	rc := &eos_io.RuntimeContext{Ctx: ctx}
	if err := docker.PullComposeImagesWithProgress(rc, bgi.config.ComposeFile); err != nil {
		logger.Error("Failed to pull Docker images", zap.Error(err))
		return fmt.Errorf("failed to pull Docker images: %w", err)
	}

	logger.Info("Docker images pulled successfully")
	return nil
}

// startService starts the BionicGPT services using phased deployment
// SHIFT-LEFT FIX: Phased deployment instead of "docker compose up -d" all at once
func (bgi *BionicGPTInstaller) startService(ctx context.Context) error {
	logger := otelzap.Ctx(ctx)

	logger.Info("Starting BionicGPT services using phased deployment")
	logger.Info("This ensures services start in correct dependency order")

	// Use intelligent phased deployment instead of starting all at once
	if err := bgi.phasedDeployment(ctx); err != nil {
		logger.Error("Phased deployment failed", zap.Error(err))
		return fmt.Errorf("phased deployment failed: %w", err)
	}

	logger.Info("Phased deployment completed successfully")
	logger.Debug("Post-operation: all containers started and verified")
	return nil
}

// Note: createDatabaseUser function removed - database user creation is now
// automated via init-db.sh script that runs on postgres first startup.
// See dbinit.go for the new implementation.

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
