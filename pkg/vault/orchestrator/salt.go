// Package orchestrator provides Vault orchestration utilities
package orchestrator

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/saltstack/client"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/saltstack/config"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/saltstack/orchestrator"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CreateSaltOperation creates the Salt operation for Vault installation.
// It follows the Assess → Intervene → Evaluate pattern.
func CreateSaltOperation(opts *orchestrator.OrchestrationOptions) *orchestrator.SaltOperation {
	// Create pillar data from command flags and orchestration options
	pillar := make(map[string]interface{})

	// Copy orchestration pillar
	for k, v := range opts.Pillar {
		pillar[k] = v
	}

	// Add default Vault configuration
	pillar["vault"] = map[string]interface{}{
		"version":     "latest",
		"config_path": "/etc/vault.d",
		"data_path":   "/opt/vault/data",
		"tls_enabled": true,
		"backend":     "file",
	}

	return &orchestrator.SaltOperation{
		Type:   "orchestrate",
		Module: "hashicorp.vault.deploy",
		Pillar: pillar,
	}
}

// ExecuteWithSalt executes Vault installation using Salt orchestration.
// It follows the Assess → Intervene → Evaluate pattern.
func ExecuteWithSalt(rc *eos_io.RuntimeContext, opts *orchestrator.OrchestrationOptions, directExec orchestrator.DirectExecutor, saltOp *orchestrator.SaltOperation) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Executing Vault installation via Salt orchestration")

	// ASSESS - Create Salt client configuration
	saltConfig := GetSaltConfigFromEnv()

	// Check if Salt configuration is available
	if saltConfig.BaseURL == "" || saltConfig.Username == "" || saltConfig.Password == "" {
		logger.Warn("Salt configuration not available, falling back to direct execution")
		return directExec(rc)
	}

	// INTERVENE - Create Salt client
	saltClient, err := client.NewHTTPSaltClient(rc, saltConfig)
	if err != nil {
		logger.Warn("Failed to create Salt client, falling back to direct execution",
			zap.Error(err))
		return directExec(rc)
	}

	// Authenticate
	_, err = saltClient.Login(rc.Ctx, nil)
	if err != nil {
		logger.Warn("Salt authentication failed, falling back to direct execution",
			zap.Error(err))
		return directExec(rc)
	}
	defer saltClient.Logout(rc.Ctx)

	// Create enhancer and execute
	enhancer := orchestrator.NewEnhancer(rc, saltClient)
	result, err := enhancer.ExecuteWithOrchestration(rc.Ctx, opts, directExec, saltOp)
	if err != nil {
		return fmt.Errorf("orchestrated Vault installation failed: %w", err)
	}

	// EVALUATE - Display results
	return DisplayOrchestrationResult(rc, result)
}

// GetSaltConfigFromEnv retrieves Salt configuration from environment variables
func GetSaltConfigFromEnv() *client.ClientConfig {
	return config.GetFromEnv()
}
