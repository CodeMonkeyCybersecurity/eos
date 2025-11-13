// Package bionicgpt provides LiteLLM error classification for better diagnostics
//
// This module classifies LiteLLM errors into categories to provide actionable remediation:
//   - Config errors (bad API key) → fail fast with clear message
//   - Network errors (Azure unreachable) → retry with backoff
//   - Quota errors (Azure quota exhausted) → actionable user message
//   - Transient errors (temporary glitch) → retry
//
// Code Monkey Cybersecurity - "Cybersecurity. With humans."
package bionicgpt

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// LiteLLMErrorType represents the category of LiteLLM error
type LiteLLMErrorType string

const (
	// Config errors - fail fast, don't retry
	LiteLLMErrorConfig LiteLLMErrorType = "config"

	// Network errors - retry with backoff
	LiteLLMErrorNetwork LiteLLMErrorType = "network"

	// Quota errors - fail fast with actionable message
	LiteLLMErrorQuota LiteLLMErrorType = "quota"

	// Permission errors - fail fast
	LiteLLMErrorPermission LiteLLMErrorType = "permission"

	// Transient errors - retry
	LiteLLMErrorTransient LiteLLMErrorType = "transient"

	// Unknown errors - log and continue
	LiteLLMErrorUnknown LiteLLMErrorType = "unknown"
)

// LiteLLMError represents a classified LiteLLM error
type LiteLLMError struct {
	Type        LiteLLMErrorType
	Message     string
	Remediation string
	ShouldRetry bool
}

// ClassifyLiteLLMError analyzes LiteLLM container logs and classifies the error
func ClassifyLiteLLMError(ctx context.Context, containerLogs string) *LiteLLMError {
	logger := otelzap.Ctx(ctx)

	// Check for configuration errors (fail fast)
	if strings.Contains(containerLogs, "invalid_api_key") ||
		strings.Contains(containerLogs, "Incorrect API key") ||
		strings.Contains(containerLogs, "Authentication failed") ||
		strings.Contains(containerLogs, "401") {
		return &LiteLLMError{
			Type:    LiteLLMErrorConfig,
			Message: "Invalid Azure OpenAI API key",
			Remediation: "Check your Azure API key:\n" +
				"  1. Verify API key in Azure Portal: https://portal.azure.com\n" +
				"  2. Update Vault secret: vault kv put secret/bionicgpt/azure_api_key value=<new-key>\n" +
				"  3. Restart BionicGPT: docker compose -f /opt/bionicgpt/docker-compose.yml restart",
			ShouldRetry: false,
		}
	}

	// Check for quota exhaustion (fail fast with actionable message)
	if strings.Contains(containerLogs, "quota") ||
		strings.Contains(containerLogs, "rate_limit") ||
		strings.Contains(containerLogs, "429") {
		return &LiteLLMError{
			Type:    LiteLLMErrorQuota,
			Message: "Azure OpenAI quota exhausted or rate limit exceeded",
			Remediation: "Azure API quota exceeded:\n" +
				"  1. Check quotas: https://portal.azure.com → Quotas\n" +
				"  2. Increase quota limits in Azure Portal\n" +
				"  3. Wait for quota reset (typically hourly)\n\n" +
				"Alternative: Use local embeddings:\n" +
				"  sudo eos create bionicgpt --local-embeddings",
			ShouldRetry: false,
		}
	}

	// Check for permission errors (fail fast)
	if strings.Contains(containerLogs, "403") ||
		strings.Contains(containerLogs, "Forbidden") ||
		strings.Contains(containerLogs, "insufficient permissions") {
		return &LiteLLMError{
			Type:    LiteLLMErrorPermission,
			Message: "Insufficient permissions for Azure OpenAI resource",
			Remediation: "Azure permissions issue:\n" +
				"  1. Check Azure RBAC permissions\n" +
				"  2. Ensure API key has access to deployment\n" +
				"  3. Verify deployment exists: Azure Portal → Azure OpenAI → Deployments",
			ShouldRetry: false,
		}
	}

	// Check for network errors (retry with backoff)
	if strings.Contains(containerLogs, "connection refused") ||
		strings.Contains(containerLogs, "connection timeout") ||
		strings.Contains(containerLogs, "network unreachable") ||
		strings.Contains(containerLogs, "DNS") {
		return &LiteLLMError{
			Type:    LiteLLMErrorNetwork,
			Message: "Cannot reach Azure OpenAI endpoint",
			Remediation: "Network connectivity issue:\n" +
				"  1. Check internet connectivity: ping 8.8.8.8\n" +
				"  2. Verify Azure endpoint URL in config\n" +
				"  3. Check firewall/network policies\n" +
				"  4. Verify DNS resolution: nslookup <your-resource>.openai.azure.com",
			ShouldRetry: true,
		}
	}

	// Check for endpoint configuration errors
	if strings.Contains(containerLogs, "404") ||
		strings.Contains(containerLogs, "not found") ||
		strings.Contains(containerLogs, "deployment not found") {
		return &LiteLLMError{
			Type:    LiteLLMErrorConfig,
			Message: "Azure OpenAI deployment not found",
			Remediation: "Deployment configuration error:\n" +
				"  1. Verify deployment name in Azure Portal\n" +
				"  2. Check litellm_config.yaml deployment names\n" +
				"  3. Ensure deployment is active in Azure",
			ShouldRetry: false,
		}
	}

	// Check for transient errors (retry)
	if strings.Contains(containerLogs, "503") ||
		strings.Contains(containerLogs, "service unavailable") ||
		strings.Contains(containerLogs, "temporarily unavailable") {
		return &LiteLLMError{
			Type:    LiteLLMErrorTransient,
			Message: "Azure OpenAI service temporarily unavailable",
			Remediation: "Temporary Azure service issue - will retry automatically.\n" +
				"If issue persists:\n" +
				"  Check Azure status: https://status.azure.com",
			ShouldRetry: true,
		}
	}

	// Unknown error type
	logger.Warn("Unknown LiteLLM error type - check container logs",
		zap.String("logs_sample", containerLogs[:min(500, len(containerLogs))]))

	return &LiteLLMError{
		Type:    LiteLLMErrorUnknown,
		Message: "LiteLLM proxy encountered an error",
		Remediation: "Check detailed logs:\n" +
			"  docker logs bionicgpt-litellm --tail 100\n\n" +
			"Common issues:\n" +
			"  - API key configuration\n" +
			"  - Network connectivity\n" +
			"  - Azure deployment configuration",
		ShouldRetry: true, // Conservative - retry unknown errors
	}
}

// GetLiteLLMContainerLogs retrieves the last N lines of LiteLLM container logs
func GetLiteLLMContainerLogs(ctx context.Context, containerName string, tailLines int) (string, error) {
	output, err := execute.Run(ctx, execute.Options{
		Command: "docker",
		Args:    []string{"logs", "--tail", fmt.Sprintf("%d", tailLines), containerName},
		Capture: true,
		Timeout: 10 * time.Second,
	})

	if err != nil {
		return "", fmt.Errorf("failed to get container logs: %w", err)
	}

	return output, nil
}

// DiagnoseLiteLLMHealth performs intelligent health check with error classification
func DiagnoseLiteLLMHealth(ctx context.Context, containerName string) (*LiteLLMError, error) {
	logger := otelzap.Ctx(ctx)

	logger.Info("Diagnosing LiteLLM health", zap.String("container", containerName))

	// Get recent container logs
	logs, err := GetLiteLLMContainerLogs(ctx, containerName, 100)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve logs: %w", err)
	}

	// Classify error from logs
	liteLLMError := ClassifyLiteLLMError(ctx, logs)

	logger.Info("LiteLLM error classified",
		zap.String("type", string(liteLLMError.Type)),
		zap.String("message", liteLLMError.Message),
		zap.Bool("should_retry", liteLLMError.ShouldRetry))

	return liteLLMError, nil
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
