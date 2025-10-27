// Package bionicgpt provides pre-deployment validation for shift-left failure prevention
//
// This module implements comprehensive pre-flight checks to catch issues BEFORE deployment starts.
// Following shift-left principles: validate early, fail fast, provide actionable feedback.
//
// Code Monkey Cybersecurity - "Cybersecurity. With humans."
package bionicgpt

import (
	"context"
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// PreflightResult contains results of pre-deployment validation
type PreflightResult struct {
	Passed              bool
	Errors              []string
	Warnings            []string
	RequiredFilesOK     bool
	EnvVarsOK           bool
	PortsAvailable      bool
	DockerHealthy       bool
	DiskSpaceSufficient bool
}

// runPreflightChecks performs comprehensive pre-deployment validation
// This catches issues BEFORE deployment starts (shift-left principle)
func (bgi *BionicGPTInstaller) runPreflightChecks(ctx context.Context) (*PreflightResult, error) {
	logger := otelzap.Ctx(ctx)

	logger.Info("════════════════════════════════════════════════════════════════")
	logger.Info("BionicGPT Pre-Deployment Validation")
	logger.Info("Checking configuration before deployment starts...")
	logger.Info("════════════════════════════════════════════════════════════════")

	result := &PreflightResult{
		Passed:   true,
		Errors:   []string{},
		Warnings: []string{},
	}

	// Check 1: Required files will exist after creation
	logger.Info("CHECK 1: Configuration Readiness")
	result.RequiredFilesOK = bgi.checkConfigurationReadiness(ctx, result)

	// Check 2: Environment variables are set
	logger.Info("CHECK 2: Environment Variables")
	result.EnvVarsOK = bgi.checkEnvironmentVariables(ctx, result)

	// Check 3: Ports availability
	logger.Info("CHECK 3: Port Availability")
	result.PortsAvailable = bgi.checkPortAvailability(ctx, result)

	// Check 4: Docker health
	logger.Info("CHECK 4: Docker Status")
	result.DockerHealthy = bgi.checkDockerHealth(ctx, result)

	// Check 5: Disk space
	logger.Info("CHECK 5: Disk Space")
	result.DiskSpaceSufficient = bgi.checkDiskSpace(ctx, result)

	// Check 6: Azure configuration (if using Azure)
	if !bgi.config.UseLocalEmbeddings {
		logger.Info("CHECK 6: Azure OpenAI Configuration")
		bgi.checkAzureConfiguration(ctx, result)
	}

	// Overall result
	logger.Info("────────────────────────────────────────────────────────────────")
	if len(result.Errors) > 0 {
		result.Passed = false
		logger.Error("Pre-deployment validation FAILED",
			zap.Int("errors", len(result.Errors)),
			zap.Int("warnings", len(result.Warnings)))

		logger.Info("")
		logger.Error("Critical Errors:")
		for _, err := range result.Errors {
			logger.Error(fmt.Sprintf("  ✗ %s", err))
		}
	} else {
		logger.Info("✓ All pre-deployment checks passed",
			zap.Int("warnings", len(result.Warnings)))
	}

	if len(result.Warnings) > 0 {
		logger.Info("")
		logger.Info("Warnings:")
		for _, warn := range result.Warnings {
			logger.Warn(fmt.Sprintf("  ⚠ %s", warn))
		}
	}

	logger.Info("════════════════════════════════════════════════════════════════")

	return result, nil
}

// checkConfigurationReadiness verifies that configuration is complete
func (bgi *BionicGPTInstaller) checkConfigurationReadiness(ctx context.Context, result *PreflightResult) bool {
	logger := otelzap.Ctx(ctx)
	allOK := true

	// Check install directory can be created
	if bgi.config.InstallDir == "" {
		result.Errors = append(result.Errors, "Installation directory not specified")
		allOK = false
	} else {
		logger.Info(fmt.Sprintf("  ✓ Installation directory: %s", bgi.config.InstallDir))
	}

	// Check Azure configuration (if not using local embeddings)
	if !bgi.config.UseLocalEmbeddings {
		if bgi.config.AzureEndpoint == "" {
			result.Errors = append(result.Errors, "Azure endpoint not configured")
			allOK = false
		}
		if bgi.config.AzureChatDeployment == "" {
			result.Errors = append(result.Errors, "Azure chat deployment not configured")
			allOK = false
		}
		if bgi.config.AzureAPIKey == "" {
			result.Errors = append(result.Errors, "Azure API key not configured")
			allOK = false
		}
	}

	// Check secrets are configured
	if bgi.config.PostgresPassword == "" {
		result.Errors = append(result.Errors, "PostgreSQL password not set")
		allOK = false
	} else {
		logger.Info("  ✓ PostgreSQL password configured")
	}

	if bgi.config.JWTSecret == "" {
		result.Errors = append(result.Errors, "JWT secret not set")
		allOK = false
	} else {
		logger.Info("  ✓ JWT secret configured")
	}

	if bgi.config.LiteLLMMasterKey == "" {
		result.Errors = append(result.Errors, "LiteLLM master key not set")
		allOK = false
	} else {
		logger.Info("  ✓ LiteLLM master key configured")
	}

	if allOK {
		logger.Info("  ✓ All required configuration present")
	}

	return allOK
}

// checkEnvironmentVariables verifies environment setup
func (bgi *BionicGPTInstaller) checkEnvironmentVariables(ctx context.Context, result *PreflightResult) bool {
	logger := otelzap.Ctx(ctx)

	// Basic sanity checks - actual env vars will be written to files
	if bgi.config.Port == 0 {
		result.Errors = append(result.Errors, "Port not configured")
		logger.Error("  ✗ Port not configured")
		return false
	}

	logger.Info(fmt.Sprintf("  ✓ Port configured: %d", bgi.config.Port))
	return true
}

// checkPortAvailability verifies required ports are not in use
func (bgi *BionicGPTInstaller) checkPortAvailability(ctx context.Context, result *PreflightResult) bool {
	logger := otelzap.Ctx(ctx)
	allOK := true

	ports := []int{
		bgi.config.Port,        // BionicGPT web interface
		bgi.config.LiteLLMPort, // LiteLLM proxy
	}

	for _, port := range ports {
		output, err := execute.Run(ctx, execute.Options{
			Command: "sh",
			Args:    []string{"-c", fmt.Sprintf("ss -tuln | grep ':%d ' || true", port)},
			Capture: true,
		})

		if err == nil && strings.TrimSpace(output) != "" {
			// Port is in use - check if it's our own container
			containerCheck, _ := execute.Run(ctx, execute.Options{
				Command: "docker",
				Args:    []string{"ps", "--filter", fmt.Sprintf("name=%s", ContainerApp), "--format", "{{.Ports}}"},
				Capture: true,
			})

			if strings.Contains(containerCheck, fmt.Sprintf("%d->", port)) {
				logger.Info(fmt.Sprintf("  ⚠ Port %d in use by existing BionicGPT (will be restarted)", port))
				result.Warnings = append(result.Warnings, fmt.Sprintf("Port %d already used by BionicGPT", port))
			} else {
				logger.Error(fmt.Sprintf("  ✗ Port %d already in use", port))
				result.Errors = append(result.Errors,
					fmt.Sprintf("Port %d in use. Stop the process or use --port flag", port))
				allOK = false
			}
		} else {
			logger.Info(fmt.Sprintf("  ✓ Port %d available", port))
		}
	}

	return allOK
}

// checkDockerHealth verifies Docker daemon is running and healthy
// NOTE: This runs AFTER checkPrerequisites(), so Docker should already be validated
func (bgi *BionicGPTInstaller) checkDockerHealth(ctx context.Context, result *PreflightResult) bool {
	logger := otelzap.Ctx(ctx)

	// Check Docker is installed (quick revalidation)
	_, err := execute.Run(ctx, execute.Options{
		Command: "docker",
		Args:    []string{"--version"},
		Capture: true,
	})
	if err != nil {
		result.Warnings = append(result.Warnings, "Docker not found (should have been caught earlier)")
		logger.Warn("  ⚠ Docker not installed")
		return false
	}
	logger.Info("  ✓ Docker installed")

	// Check Docker daemon is running
	_, err = execute.Run(ctx, execute.Options{
		Command: "docker",
		Args:    []string{"info"},
		Capture: true,
	})
	if err != nil {
		result.Warnings = append(result.Warnings, "Docker daemon not running")
		logger.Warn("  ⚠ Docker daemon not running")
		return false
	}
	logger.Info("  ✓ Docker daemon healthy")

	// Check Docker Compose
	_, err = execute.Run(ctx, execute.Options{
		Command: "docker",
		Args:    []string{"compose", "version"},
		Capture: true,
	})
	if err != nil {
		result.Warnings = append(result.Warnings, "Docker Compose not available")
		logger.Warn("  ⚠ Docker Compose not available")
		return false
	}
	logger.Info("  ✓ Docker Compose available")

	return true
}

// checkDiskSpace verifies sufficient disk space is available
func (bgi *BionicGPTInstaller) checkDiskSpace(ctx context.Context, result *PreflightResult) bool {
	logger := otelzap.Ctx(ctx)

	// Get available disk space for installation directory
	output, err := execute.Run(ctx, execute.Options{
		Command: "df",
		Args:    []string{"-BG", "/opt"},
		Capture: true,
	})

	if err != nil {
		result.Warnings = append(result.Warnings, "Could not check disk space")
		logger.Warn("  ⚠ Could not check disk space")
		return true // Don't fail on this
	}

	// Parse output (second line, 4th column)
	lines := strings.Split(output, "\n")
	if len(lines) < 2 {
		result.Warnings = append(result.Warnings, "Could not parse disk space output")
		logger.Warn("  ⚠ Could not parse disk space")
		return true
	}

	fields := strings.Fields(lines[1])
	if len(fields) < 4 {
		result.Warnings = append(result.Warnings, "Could not parse disk space fields")
		logger.Warn("  ⚠ Could not parse disk space fields")
		return true
	}

	availableStr := strings.TrimSuffix(fields[3], "G")
	var available int
	_, _ = fmt.Sscanf(availableStr, "%d", &available)

	const minDiskSpaceGB = 10
	if available < minDiskSpaceGB {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("Low disk space: %dGB available, %dGB recommended", available, minDiskSpaceGB))
		logger.Warn(fmt.Sprintf("  ⚠ Low disk space: %dGB available", available))
		return false
	}

	logger.Info(fmt.Sprintf("  ✓ Sufficient disk space: %dGB available", available))
	return true
}

// checkAzureConfiguration verifies Azure OpenAI configuration AND connectivity
// P0 FIX: Test actual Azure connectivity to fail in 5 seconds, not 33 minutes
// RATIONALE: Catches bad credentials before wasting time on deployment
// REFERENCE: Adversarial Analysis ADVERSARIAL_ANALYSIS_BIONICGPT_PHASE6_FAILURE.md P0 Fix #2
func (bgi *BionicGPTInstaller) checkAzureConfiguration(ctx context.Context, result *PreflightResult) bool {
	logger := otelzap.Ctx(ctx)
	allOK := true

	// Step 1: Check configuration values are set
	if bgi.config.AzureEndpoint == "" {
		result.Errors = append(result.Errors, "Azure endpoint not configured")
		logger.Error("  ✗ Azure endpoint missing")
		allOK = false
	}

	if bgi.config.AzureChatDeployment == "" {
		result.Errors = append(result.Errors, "Azure chat deployment not configured")
		logger.Error("  ✗ Azure chat deployment missing")
		allOK = false
	}

	if !bgi.config.UseLocalEmbeddings && bgi.config.AzureEmbeddingsDeployment == "" {
		result.Errors = append(result.Errors, "Azure embeddings deployment not configured")
		logger.Error("  ✗ Azure embeddings deployment missing")
		allOK = false
	}

	if bgi.config.AzureAPIKey == "" {
		result.Errors = append(result.Errors, "Azure API key not configured")
		logger.Error("  ✗ Azure API key missing")
		allOK = false
	}

	// If config values are missing, can't test connectivity
	if !allOK {
		return false
	}

	// Step 2: P0 FIX - Test actual Azure OpenAI connectivity
	logger.Info("  Testing Azure OpenAI connectivity (prevents wasting 33 minutes on bad config)...")

	// Build test URL for chat deployment
	testURL := fmt.Sprintf("%s/openai/deployments/%s/chat/completions?api-version=%s",
		strings.TrimSuffix(bgi.config.AzureEndpoint, "/"),
		bgi.config.AzureChatDeployment,
		bgi.config.AzureAPIVersion)

	// Make lightweight test request (OPTIONS to avoid quota usage)
	output, err := execute.Run(ctx, execute.Options{
		Command: "curl",
		Args: []string{
			"-X", "OPTIONS",
			"-H", fmt.Sprintf("api-key: %s", bgi.config.AzureAPIKey),
			"-m", "10", // 10 second timeout
			"--silent",
			"--show-error",
			"-w", "%{http_code}",
			"-o", "/dev/null",
			testURL,
		},
		Capture: true,
		Timeout: 15000, // 15 seconds total
	})

	httpCode := strings.TrimSpace(output)

	if err != nil {
		result.Errors = append(result.Errors,
			fmt.Sprintf("Azure OpenAI connectivity test FAILED: %v (HTTP %s)", err, httpCode))
		logger.Error("  ✗ Azure OpenAI connection failed",
			zap.Error(err),
			zap.String("http_code", httpCode))
		logger.Error("")
		logger.Error("  This means your Azure configuration is incorrect.")
		logger.Error("  Fix before retrying deployment to avoid wasting 30+ minutes.")
		logger.Error("")
		logger.Error("  Common Issues:")
		logger.Error("    - Invalid API key (check Vault)")
		logger.Error("    - Wrong endpoint URL")
		logger.Error("    - Deployment name doesn't exist")
		logger.Error("    - Network/firewall blocking access")
		logger.Error("")
		logger.Error("  Debug:")
		logger.Error(fmt.Sprintf("    Endpoint: %s", bgi.config.AzureEndpoint))
		logger.Error(fmt.Sprintf("    Deployment: %s", bgi.config.AzureChatDeployment))
		logger.Error(fmt.Sprintf("    Test URL: %s", testURL))
		logger.Error("    API key: vault kv get secret/bionicgpt/azure_api_key")
		return false
	}

	// Check HTTP response code
	switch httpCode {
	case "200", "204", "405":
		// 200/204 = Success
		// 405 = Method Not Allowed (OPTIONS not supported, but auth worked!)
		logger.Info(fmt.Sprintf("  ✓ Azure OpenAI connection successful (HTTP %s)", httpCode))
		logger.Info(fmt.Sprintf("    Endpoint: %s", bgi.config.AzureEndpoint))
		logger.Info(fmt.Sprintf("    Chat deployment: %s", bgi.config.AzureChatDeployment))
		if !bgi.config.UseLocalEmbeddings {
			logger.Info(fmt.Sprintf("    Embeddings deployment: %s", bgi.config.AzureEmbeddingsDeployment))
		}
		return true

	case "401", "403":
		result.Errors = append(result.Errors,
			fmt.Sprintf("Azure OpenAI authentication FAILED (HTTP %s) - Invalid API key", httpCode))
		logger.Error(fmt.Sprintf("  ✗ Azure authentication failed (HTTP %s)", httpCode))
		logger.Error("")
		logger.Error("  Your API key is invalid or expired.")
		logger.Error("")
		logger.Error("  Fix:")
		logger.Error("    1. Get correct API key from Azure Portal")
		logger.Error("    2. Update Vault: vault kv put secret/bionicgpt/azure_api_key value=YOUR_NEW_KEY")
		logger.Error("    3. Retry deployment: eos create bionicgpt --force")
		return false

	case "404":
		result.Errors = append(result.Errors,
			fmt.Sprintf("Azure deployment '%s' NOT FOUND (HTTP 404)", bgi.config.AzureChatDeployment))
		logger.Error("  ✗ Deployment not found (HTTP 404)")
		logger.Error("")
		logger.Error(fmt.Sprintf("  Deployment '%s' does not exist in your Azure OpenAI resource.", bgi.config.AzureChatDeployment))
		logger.Error("")
		logger.Error("  Fix:")
		logger.Error("    1. Check Azure Portal for correct deployment name")
		logger.Error("    2. Create deployment if missing")
		logger.Error("    3. Retry with correct name: eos create bionicgpt --azure-chat-deployment CORRECT_NAME")
		return false

	case "429":
		result.Warnings = append(result.Warnings,
			"Azure OpenAI rate limit hit during connectivity test")
		logger.Warn("  ⚠ Azure rate limit hit (HTTP 429), but credentials appear valid")
		logger.Warn("  Proceeding with deployment - rate limits should reset soon")
		return true // Rate limit means auth worked, proceed

	default:
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("Azure returned unexpected HTTP code: %s", httpCode))
		logger.Warn(fmt.Sprintf("  ⚠ Unexpected HTTP code: %s", httpCode))
		logger.Warn("  Proceeding with deployment - connection might still work")
		return true // Don't fail for unknown codes
	}
}
