// Package openwebui provides functionality to install and configure
// Open WebUI with Azure OpenAI backend integration.
//
// The package follows the Eos Assess → Intervene → Evaluate pattern:
//   - Assess: Check prerequisites, Docker availability, and current installation state
//   - Intervene: Install and configure Open WebUI with Docker Compose, generate secrets, test Azure connectivity
//   - Evaluate: Verify the installation is healthy, container running, and health endpoint responds
//
// Security Features:
//   - Automatic generation of 64-character secret keys using crypto.GeneratePassword
//   - Input validation for Azure endpoints, deployment names, and API keys
//   - Secure .env file permissions (0600)
//   - Authentication always enabled (WEBUI_AUTH=True)
//   - Proper secret redaction in logs
//
// Azure OpenAI Integration:
//   - Validates endpoint format (must be https://*.openai.azure.com)
//   - Tests connectivity with detailed error messages for 401, 403, 404, 429
//   - Uses Go's native HTTP client instead of external dependencies
//   - Supports interactive and non-interactive configuration
//
// Example usage:
//
//	config := &openwebui.InstallConfig{
//	    Port: 8501,
//	    AzureEndpoint: "https://myopenai.openai.azure.com",
//	    AzureDeployment: "gpt-4",
//	    AzureAPIKey: "your-32-char-key",
//	}
//	installer := openwebui.NewOpenWebUIInstaller(rc, config)
//	if err := installer.Install(); err != nil {
//	    log.Fatal(err)
//	}
//
// Production Considerations:
//   - Docker image pinned to specific version (v0.3.32) for reproducibility
//   - Resource limits configured (2 CPU, 2GB RAM)
//   - Log rotation enabled (10MB max size, 3 files)
//   - Health checks configured with proper timeouts
//
// Code Monkey Cybersecurity - "Cybersecurity. With humans."
package openwebui

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/telemetry"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// NewOpenWebUIInstaller creates a new Open WebUI installer
func NewOpenWebUIInstaller(rc *eos_io.RuntimeContext, config *InstallConfig) *OpenWebUIInstaller {
	// Set defaults
	if config.InstallDir == "" {
		config.InstallDir = "/opt/openwebui"
	}
	if config.ComposeFile == "" {
		config.ComposeFile = filepath.Join(config.InstallDir, "docker-compose.yml")
	}
	if config.EnvFile == "" {
		config.EnvFile = filepath.Join(config.InstallDir, ".env")
	}
	if config.Port == 0 {
		config.Port = shared.PortOpenWebUI
	}
	if config.AzureAPIVersion == "" {
		config.AzureAPIVersion = "2024-02-15-preview"
	}
	if config.WebUIName == "" {
		config.WebUIName = "Code Monkey AI Chat"
	}
	if config.LogLevel == "" {
		config.LogLevel = "INFO"
	}
	if config.Timezone == "" {
		config.Timezone = "Australia/Perth"
	}
	config.WebUIAuth = true // Always enable auth for security

	return &OpenWebUIInstaller{
		rc:     rc,
		config: config,
	}
}

// Install installs Open WebUI following the Assess → Intervene → Evaluate pattern
func (owi *OpenWebUIInstaller) Install() error {
	ctx, span := telemetry.Start(owi.rc.Ctx, "openwebui.Install")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Starting Open WebUI installation",
		zap.String("install_dir", owi.config.InstallDir),
		zap.Int("port", owi.config.Port))

	// ASSESS: Check current state
	state, err := owi.assessInstallation(ctx)
	if err != nil {
		return fmt.Errorf("failed to assess installation state: %w", err)
	}

	logger.Info("Installation assessment completed",
		zap.Bool("installed", state.Installed),
		zap.Bool("running", state.Running),
		zap.Bool("compose_exists", state.ComposeFileExists),
		zap.Bool("env_exists", state.EnvFileExists))

	// Check if already installed and force not set
	if state.Installed && !owi.config.ForceReinstall {
		return eos_err.NewUserError(
			"Open WebUI is already installed at %s\n"+
				"Use --force to reinstall",
			owi.config.InstallDir)
	}

	// INTERVENE: Perform installation
	if err := owi.performInstallation(ctx); err != nil {
		return fmt.Errorf("installation failed: %w", err)
	}

	// EVALUATE: Verify installation
	if !owi.config.SkipHealthCheck {
		if err := owi.verifyInstallation(ctx); err != nil {
			return fmt.Errorf("installation verification failed: %w", err)
		}
	}

	logger.Info("Open WebUI installation completed successfully",
		zap.String("access_url", fmt.Sprintf("http://localhost:%d", owi.config.Port)))

	return nil
}

// assessInstallation checks the current state of Open WebUI
func (owi *OpenWebUIInstaller) assessInstallation(ctx context.Context) (*InstallState, error) {
	logger := otelzap.Ctx(ctx)
	logger.Debug("Assessing Open WebUI installation state")

	state := &InstallState{
		ExistingPaths: []string{},
	}

	// Check if installation directory exists
	if _, err := os.Stat(owi.config.InstallDir); err == nil {
		state.ExistingPaths = append(state.ExistingPaths, owi.config.InstallDir)
	}

	// Check if compose file exists
	if _, err := os.Stat(owi.config.ComposeFile); err == nil {
		state.ComposeFileExists = true
		state.ExistingPaths = append(state.ExistingPaths, owi.config.ComposeFile)
	}

	// Check if env file exists
	if _, err := os.Stat(owi.config.EnvFile); err == nil {
		state.EnvFileExists = true
		state.ExistingPaths = append(state.ExistingPaths, owi.config.EnvFile)
	}

	// Check if container is running
	output, err := execute.Run(ctx, execute.Options{
		Command: "docker",
		Args:    []string{"ps", "-a", "--filter", "name=open-webui", "--format", "{{.ID}}\t{{.Status}}"},
		Capture: true,
	})
	if err == nil && output != "" {
		parts := strings.Split(strings.TrimSpace(output), "\t")
		if len(parts) >= 1 {
			state.ContainerID = parts[0]
			state.Installed = true
			if len(parts) >= 2 && strings.Contains(parts[1], "Up") {
				state.Running = true
			}
		}
	}

	logger.Debug("Assessment complete",
		zap.Int("existing_paths", len(state.ExistingPaths)),
		zap.String("container_id", state.ContainerID))

	return state, nil
}

// performInstallation performs the actual installation steps
func (owi *OpenWebUIInstaller) performInstallation(ctx context.Context) error {
	logger := otelzap.Ctx(ctx)

	// Step 1: Check prerequisites
	logger.Info("Checking prerequisites")
	if err := owi.checkPrerequisites(ctx); err != nil {
		return err
	}

	// Step 2: Get Azure OpenAI configuration
	logger.Info("Gathering Azure OpenAI configuration")
	if err := owi.getAzureConfiguration(ctx); err != nil {
		return err
	}

	// Step 3: Create installation directory
	logger.Info("Creating installation directory", zap.String("dir", owi.config.InstallDir))
	if err := os.MkdirAll(owi.config.InstallDir, 0755); err != nil {
		return fmt.Errorf("failed to create installation directory: %w", err)
	}

	// Step 4: Generate secret key if not provided
	if owi.config.WebUISecretKey == "" {
		logger.Info("Generating secure secret key")
		secretKey, err := crypto.GeneratePassword(64)
		if err != nil {
			return fmt.Errorf("failed to generate secret key: %w", err)
		}
		owi.config.WebUISecretKey = secretKey
	}

	// Step 5: Test Azure OpenAI connection
	logger.Info("Testing Azure OpenAI connection")
	if err := owi.testAzureConnection(ctx); err != nil {
		logger.Warn("Azure OpenAI connection test failed", zap.Error(err))
		// Continue anyway - user might have network issues that will be resolved later
	} else {
		logger.Info("Successfully connected to Azure OpenAI")
	}

	// Step 6: Create .env file
	logger.Info("Creating environment configuration", zap.String("file", owi.config.EnvFile))
	if err := owi.createEnvFile(ctx); err != nil {
		return err
	}

	// Step 7: Create docker-compose.yml
	logger.Info("Creating Docker Compose configuration", zap.String("file", owi.config.ComposeFile))
	if err := owi.createComposeFile(ctx); err != nil {
		return err
	}

	// Step 8: Pull Docker image
	logger.Info("Pulling Open WebUI Docker image")
	if err := owi.pullDockerImage(ctx); err != nil {
		return err
	}

	// Step 9: Start the service
	logger.Info("Starting Open WebUI service")
	if err := owi.startService(ctx); err != nil {
		return err
	}

	return nil
}

// checkPrerequisites verifies that Docker and Docker Compose are installed
func (owi *OpenWebUIInstaller) checkPrerequisites(ctx context.Context) error {
	logger := otelzap.Ctx(ctx)

	// Check Docker
	logger.Debug("Checking for Docker")
	_, err := execute.Run(ctx, execute.Options{
		Command: "docker",
		Args:    []string{"--version"},
		Capture: true,
	})
	if err != nil {
		return eos_err.NewUserError(
			"Docker is not installed\n" +
				"Please install Docker: https://docs.docker.com/get-docker/")
	}
	logger.Debug("Docker is available")

	// Check Docker Compose
	logger.Debug("Checking for Docker Compose")
	_, err = execute.Run(ctx, execute.Options{
		Command: "docker",
		Args:    []string{"compose", "version"},
		Capture: true,
	})
	if err != nil {
		return eos_err.NewUserError(
			"Docker Compose is not installed\n" +
				"Please install Docker Compose: https://docs.docker.com/compose/install/")
	}
	logger.Debug("Docker Compose is available")

	return nil
}

// getAzureConfiguration prompts for Azure OpenAI configuration if not provided
func (owi *OpenWebUIInstaller) getAzureConfiguration(ctx context.Context) error {
	logger := otelzap.Ctx(ctx)

	// If all required fields are provided, skip prompts
	if owi.config.AzureEndpoint != "" && owi.config.AzureDeployment != "" && owi.config.AzureAPIKey != "" {
		logger.Debug("Azure configuration provided via flags")
		return nil
	}

	logger.Info("terminal prompt: Azure OpenAI configuration required")
	logger.Info("terminal prompt: You can find these in Azure Portal → Your OpenAI Resource → Keys and Endpoint")

	// Prompt for endpoint
	if owi.config.AzureEndpoint == "" {
		logger.Info("terminal prompt: Enter Azure OpenAI Endpoint (e.g., https://myopenai.openai.azure.com)")
		endpoint, err := eos_io.PromptInput(owi.rc, "Azure OpenAI Endpoint: ", "azure_endpoint")
		if err != nil {
			return fmt.Errorf("failed to read Azure endpoint: %w", err)
		}
		owi.config.AzureEndpoint = shared.SanitizeURL(endpoint)
	} else {
		// Sanitize even if provided via flag
		owi.config.AzureEndpoint = shared.SanitizeURL(owi.config.AzureEndpoint)
	}

	// Validate endpoint format
	if err := validateAzureEndpoint(owi.config.AzureEndpoint); err != nil {
		return eos_err.NewUserError(
			"Invalid Azure OpenAI endpoint format\n"+
				"%v\n"+
				"Example: https://myresource.openai.azure.com", err)
	}

	// Prompt for deployment name
	if owi.config.AzureDeployment == "" {
		logger.Info("terminal prompt: Enter Deployment Name (e.g., gpt-4)")
		deployment, err := eos_io.PromptInput(owi.rc, "Deployment Name: ", "deployment_name")
		if err != nil {
			return fmt.Errorf("failed to read deployment name: %w", err)
		}
		owi.config.AzureDeployment = strings.TrimSpace(deployment)
	}

	// Validate deployment name
	if err := validateAzureDeployment(owi.config.AzureDeployment); err != nil {
		return eos_err.NewUserError(
			"Invalid Azure OpenAI deployment name\n"+
				"%v\n"+
				"Deployment names must be alphanumeric with hyphens, periods, or underscores", err)
	}

	// Prompt for API key
	if owi.config.AzureAPIKey == "" {
		logger.Info("terminal prompt: Enter API Key (input will be hidden)")
		apiKey, err := interaction.PromptSecret(owi.rc.Ctx, "API Key: ")
		if err != nil {
			return fmt.Errorf("failed to read API key: %w", err)
		}
		owi.config.AzureAPIKey = strings.TrimSpace(apiKey)
	}

	// Validate API key format
	if err := validateAzureAPIKey(owi.config.AzureAPIKey); err != nil {
		return eos_err.NewUserError(
			"Invalid Azure OpenAI API key format\n%v", err)
	}

	logger.Debug("Azure configuration validated successfully")
	return nil
}

// testAzureConnection tests the Azure OpenAI connection using proper HTTP client
func (owi *OpenWebUIInstaller) testAzureConnection(ctx context.Context) error {
	logger := otelzap.Ctx(ctx)

	endpoint := fmt.Sprintf("%s/openai/models?api-version=%s",
		owi.config.AzureEndpoint,
		owi.config.AzureAPIVersion)

	// Redact sensitive parts for logging
	redactedEndpoint := redactAzureEndpoint(owi.config.AzureEndpoint)
	logger.Debug("Testing Azure OpenAI connection", zap.String("endpoint", redactedEndpoint))

	// Create HTTP request with context
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set Azure OpenAI API key header
	req.Header.Set("api-key", owi.config.AzureAPIKey)
	req.Header.Set("User-Agent", "Eos-OpenWebUI-Installer/1.0")

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	// Execute request
	resp, err := client.Do(req)
	if err != nil {
		return eos_err.NewUserError(
			"Cannot reach Azure OpenAI endpoint: %v\n"+
				"Check your network connection and firewall rules\n"+
				"Verify the endpoint is accessible from this machine", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			logger.Warn("Failed to close response body", zap.Error(closeErr))
		}
	}()

	// Handle different HTTP status codes
	switch resp.StatusCode {
	case http.StatusOK:
		logger.Info("Successfully connected to Azure OpenAI",
			zap.String("endpoint", redactedEndpoint),
			zap.Int("status", resp.StatusCode))
		return nil

	case http.StatusUnauthorized:
		return eos_err.NewUserError(
			"Azure OpenAI authentication failed (401 Unauthorized)\n" +
				"Your API key is invalid or expired\n" +
				"Fix: Go to Azure Portal → Your OpenAI Resource → Keys and Endpoint → Regenerate Key")

	case http.StatusForbidden:
		return eos_err.NewUserError(
			"Azure OpenAI access forbidden (403 Forbidden)\n" +
				"Your API key doesn't have permission to access this resource\n" +
				"Fix: Check your Azure OpenAI resource permissions")

	case http.StatusNotFound:
		return eos_err.NewUserError(
			"Azure OpenAI endpoint not found (404 Not Found)\n" +
				"The endpoint URL is incorrect\n" +
				"Fix: Verify the endpoint URL in Azure Portal → Your OpenAI Resource → Keys and Endpoint")

	case http.StatusTooManyRequests:
		return eos_err.NewUserError(
			"Azure OpenAI rate limit exceeded (429 Too Many Requests)\n" +
				"You've hit the rate limit for your Azure OpenAI resource\n" +
				"Fix: Wait a moment and try again, or upgrade your quota in Azure Portal")

	default:
		// Read error response body for details
		body, _ := io.ReadAll(resp.Body)
		logger.Error("Azure OpenAI returned unexpected status",
			zap.Int("status", resp.StatusCode),
			zap.String("body", string(body)))

		return eos_err.NewUserError(
			"Azure OpenAI returned error: HTTP %d\n"+
				"Response: %s\n"+
				"Fix: Check Azure Portal for service health and your resource status",
			resp.StatusCode, string(body))
	}
}

// createEnvFile creates the .env file with configuration
func (owi *OpenWebUIInstaller) createEnvFile(ctx context.Context) error {
	logger := otelzap.Ctx(ctx)

	content := fmt.Sprintf(`# Open WebUI Environment Configuration
# Generated by Eos - Code Monkey Cybersecurity

# Azure OpenAI Configuration
AZURE_OPENAI_ENDPOINT=%s
AZURE_DEPLOYMENT_NAME=%s
AZURE_OPENAI_API_KEY=%s
AZURE_OPENAI_API_VERSION=%s

# Open WebUI Settings
WEBUI_NAME=%s
WEBUI_SECRET_KEY=%s
WEBUI_AUTH=%t
LOG_LEVEL=%s
TZ=%s
`,
		owi.config.AzureEndpoint,
		owi.config.AzureDeployment,
		owi.config.AzureAPIKey,
		owi.config.AzureAPIVersion,
		owi.config.WebUIName,
		owi.config.WebUISecretKey,
		owi.config.WebUIAuth,
		owi.config.LogLevel,
		owi.config.Timezone,
	)

	if err := os.WriteFile(owi.config.EnvFile, []byte(content), 0600); err != nil {
		return fmt.Errorf("failed to write .env file: %w", err)
	}

	logger.Debug(".env file created", zap.String("path", owi.config.EnvFile))
	return nil
}

// createComposeFile creates the docker-compose.yml file
func (owi *OpenWebUIInstaller) createComposeFile(ctx context.Context) error {
	logger := otelzap.Ctx(ctx)

	content := fmt.Sprintf(`# Open WebUI Docker Compose Configuration
# Generated by Eos - Code Monkey Cybersecurity
# Port: %d

version: '3.8'

services:
  open-webui:
    # Pinned version for reproducibility and security
    # Update this version explicitly when upgrading
    image: ghcr.io/open-webui/open-webui:v0.3.32
    container_name: open-webui
    ports:
      - "%d:8080"
    volumes:
      - open-webui-data:/app/backend/data
    environment:
      # Azure OpenAI Configuration
      - OPENAI_API_BASE_URL=${AZURE_OPENAI_ENDPOINT}/openai/deployments/${AZURE_DEPLOYMENT_NAME}
      - OPENAI_API_KEY=${AZURE_OPENAI_API_KEY}
      - OPENAI_API_TYPE=azure
      - OPENAI_API_VERSION=${AZURE_OPENAI_API_VERSION}

      # Model Configuration
      - MODEL_NAME=${AZURE_DEPLOYMENT_NAME}

      # Open WebUI Settings
      - WEBUI_NAME=${WEBUI_NAME}
      - WEBUI_AUTH=${WEBUI_AUTH}
      - WEBUI_SECRET_KEY=${WEBUI_SECRET_KEY}

      # Logging
      - LOG_LEVEL=${LOG_LEVEL}

      # Timezone
      - TZ=${TZ}

    # Resource limits to prevent runaway container
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 2G
        reservations:
          cpus: '0.5'
          memory: 512M

    # Log rotation to prevent disk fill
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

    restart: unless-stopped
    networks:
      - webui-network
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

volumes:
  open-webui-data:
    driver: local

networks:
  webui-network:
    driver: bridge
`,
		owi.config.Port,
		owi.config.Port,
	)

	if err := os.WriteFile(owi.config.ComposeFile, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write docker-compose.yml: %w", err)
	}

	logger.Debug("docker-compose.yml created", zap.String("path", owi.config.ComposeFile))
	return nil
}

// pullDockerImage pulls the Open WebUI Docker image
func (owi *OpenWebUIInstaller) pullDockerImage(ctx context.Context) error {
	logger := otelzap.Ctx(ctx)

	logger.Info("Pulling Docker image (this may take several minutes for large images)")

	output, err := execute.Run(ctx, execute.Options{
		Command: "docker",
		Args:    []string{"compose", "-f", owi.config.ComposeFile, "pull"},
		Dir:     owi.config.InstallDir,
		Capture: true,
		Timeout: 10 * time.Minute, // Increased from 5 to 10 minutes for large images
	})

	// Docker compose pull can return non-zero even on success with warnings
	// Check if the image was actually pulled by verifying it exists
	if err != nil {
		logger.Warn("Docker pull reported an error, checking if image exists", zap.Error(err))

		// Verify the image exists locally
		checkOutput, checkErr := execute.Run(ctx, execute.Options{
			Command: "docker",
			Args:    []string{"images", "ghcr.io/open-webui/open-webui", "--format", "{{.Repository}}:{{.Tag}}"},
			Capture: true,
		})

		if checkErr != nil || !strings.Contains(checkOutput, "open-webui") {
			// Image truly doesn't exist - this is a real failure
			return fmt.Errorf("failed to pull Docker image: %s\nImage verification failed: %v", output, checkErr)
		}

		// Image exists, the "error" was likely just warnings or non-critical issues
		logger.Info("Docker image verified present despite pull warnings")
	}

	logger.Debug("Docker image pulled successfully")
	return nil
}

// startService starts the Open WebUI service
func (owi *OpenWebUIInstaller) startService(ctx context.Context) error {
	logger := otelzap.Ctx(ctx)

	output, err := execute.Run(ctx, execute.Options{
		Command: "docker",
		Args:    []string{"compose", "-f", owi.config.ComposeFile, "up", "-d"},
		Dir:     owi.config.InstallDir,
		Capture: true,
	})

	if err != nil {
		return fmt.Errorf("failed to start service: %s", output)
	}

	logger.Debug("Service started successfully")
	return nil
}

// verifyInstallation verifies that Open WebUI is running correctly
func (owi *OpenWebUIInstaller) verifyInstallation(ctx context.Context) error {
	logger := otelzap.Ctx(ctx)
	logger.Info("Verifying installation")

	// Check if container is running
	output, err := execute.Run(ctx, execute.Options{
		Command: "docker",
		Args:    []string{"compose", "-f", owi.config.ComposeFile, "ps"},
		Dir:     owi.config.InstallDir,
		Capture: true,
	})

	if err != nil {
		return fmt.Errorf("failed to check service status: %s", output)
	}

	if !strings.Contains(output, "Up") && !strings.Contains(output, "running") {
		return fmt.Errorf("container is not running. Check logs with: docker compose -f %s logs",
			owi.config.ComposeFile)
	}

	logger.Debug("Container is running, checking health endpoint")

	// Verify health endpoint responds (retry up to 30 seconds)
	healthURL := fmt.Sprintf("http://localhost:%d/health", owi.config.Port)
	client := &http.Client{Timeout: 5 * time.Second}

	maxRetries := 6
	for i := 0; i < maxRetries; i++ {
		logger.Debug("Checking health endpoint",
			zap.String("url", healthURL),
			zap.Int("attempt", i+1),
			zap.Int("max_attempts", maxRetries))

		req, err := http.NewRequestWithContext(ctx, "GET", healthURL, nil)
		if err != nil {
			return fmt.Errorf("failed to create health check request: %w", err)
		}

		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				logger.Info("Open WebUI is healthy and responding",
					zap.Int("port", owi.config.Port),
					zap.String("access_url", fmt.Sprintf("http://localhost:%d", owi.config.Port)))
				return nil
			}
			logger.Debug("Health endpoint returned non-OK status",
				zap.Int("status_code", resp.StatusCode))
		} else {
			logger.Debug("Health endpoint not ready yet",
				zap.Error(err),
				zap.Int("attempt", i+1))
		}

		if i < maxRetries-1 {
			logger.Debug("Waiting before retry", zap.Duration("wait", 5*time.Second))
			time.Sleep(5 * time.Second)
		}
	}

	return fmt.Errorf("health endpoint did not respond after %d attempts\n"+
		"Container is running but may not be fully initialized\n"+
		"Check logs with: docker compose -f %s logs", maxRetries, owi.config.ComposeFile)
}

// validateAzureEndpoint validates the Azure OpenAI endpoint format
func validateAzureEndpoint(endpoint string) error {
	if endpoint == "" {
		return fmt.Errorf("azure OpenAI endpoint cannot be empty")
	}

	// Must start with https://
	if !strings.HasPrefix(endpoint, "https://") {
		return fmt.Errorf("azure OpenAI endpoint must start with https://\nProvided: %s", endpoint)
	}

	// Must end with .openai.azure.com
	if !strings.HasSuffix(endpoint, ".openai.azure.com") {
		return fmt.Errorf("azure OpenAI endpoint must end with .openai.azure.com\nProvided: %s", endpoint)
	}

	// Validate it's a valid URL
	if _, err := url.Parse(endpoint); err != nil {
		return fmt.Errorf("invalid URL format: %w", err)
	}

	return nil
}

// validateAzureAPIKey validates the Azure OpenAI API key format
func validateAzureAPIKey(apiKey string) error {
	if apiKey == "" {
		return fmt.Errorf("azure OpenAI API key cannot be empty")
	}

	// Azure provides two key formats:
	// 1. Legacy format: 32 hexadecimal characters
	// 2. New format: Base64-encoded string (typically 43-44 chars ending with =)

	apiKeyLen := len(apiKey)

	// Check for 32-character hex format (legacy)
	if apiKeyLen == 32 {
		for _, ch := range apiKey {
			isHex := (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')
			if !isHex {
				return fmt.Errorf("32-character key must be hexadecimal\nInvalid character found: %c", ch)
			}
		}
		return nil
	}

	// Check for base64 format (new Azure keys are typically 43-44 chars)
	// Base64 uses: A-Z, a-z, 0-9, +, /, and = for padding
	if apiKeyLen >= 40 && apiKeyLen <= 88 {
		for _, ch := range apiKey {
			isBase64 := (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
				(ch >= '0' && ch <= '9') || ch == '+' || ch == '/' || ch == '='
			if !isBase64 {
				return fmt.Errorf("API key contains invalid character: %c\n"+
					"Azure API keys should be either:\n"+
					"  - 32 hexadecimal characters (legacy format)\n"+
					"  - 43-44 base64 characters (new format)", ch)
			}
		}
		return nil
	}

	return fmt.Errorf("unexpected API key length: %d characters\n"+
		"Azure API keys are typically:\n"+
		"  - 32 characters (legacy hex format)\n"+
		"  - 43-44 characters (new base64 format)\n"+
		"You provided: %d characters\n"+
		"Please check Azure Portal → Your OpenAI Resource → Keys and Endpoint",
		apiKeyLen, apiKeyLen)
}

// validateAzureDeployment validates the deployment name
func validateAzureDeployment(deployment string) error {
	if deployment == "" {
		return fmt.Errorf("azure OpenAI deployment name cannot be empty")
	}

	// Azure deployment names: alphanumeric with hyphens, periods, and underscores
	// Examples: gpt-4, gpt-4.1, gpt-35-turbo, my_deployment
	for _, ch := range deployment {
		isValid := (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '.' || ch == '_'
		if !isValid {
			return fmt.Errorf("deployment name must be alphanumeric with hyphens, periods, or underscores\nProvided: %s", deployment)
		}
	}

	return nil
}

// redactAzureEndpoint redacts sensitive parts of the endpoint for logging
func redactAzureEndpoint(endpoint string) string {
	// Extract just the resource name for logging
	// https://myresource.openai.azure.com -> myresource.openai.azure.com
	if strings.HasPrefix(endpoint, "https://") {
		return endpoint[8:] // Remove https://
	}
	return endpoint
}
