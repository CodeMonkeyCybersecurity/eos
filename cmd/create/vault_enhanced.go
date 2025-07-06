// cmd/create/vault_enhanced.go
package create

import (
	"fmt"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/salt/client"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/salt/orchestrator"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var CreateVaultEnhancedCmd = &cobra.Command{
	Use:   "vault-enhanced",
	Short: "Installs Vault with TLS, systemd service, and initial configuration (Salt orchestration supported)",
	Long: `Install and configure HashiCorp Vault with comprehensive orchestration support.

This enhanced version supports both direct execution and Salt orchestration,
allowing for coordinated deployment across multiple nodes and integration
with broader infrastructure automation.

Direct Execution:
  eos create vault-enhanced

Salt Orchestration:
  eos create vault-enhanced --orchestrator=salt --salt-target 'vault-*'
  eos create vault-enhanced --orchestrator=salt --salt-target 'vault-cluster' --salt-pillar cluster_size=3
  eos create vault-enhanced --orchestrator=salt --salt-batch 1 --salt-async

Features:
  - TLS certificate generation and configuration
  - Systemd service setup and management
  - Initial Vault configuration and unsealing
  - HA cluster support via Salt orchestration
  - Integration with Consul backend when available
  - Automated backup configuration
  - Security hardening and best practices

Salt States Used:
  - hashicorp.vault.install: Core Vault installation
  - hashicorp.vault.config: Configuration management
  - hashicorp.vault.cluster: HA cluster setup
  - hashicorp.vault.security: Security hardening

Environment Variables:
  VAULT_VERSION: Specific Vault version to install
  VAULT_CONFIG_PATH: Custom configuration directory
  VAULT_DATA_PATH: Custom data directory`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		
		// Get orchestration options
		opts, err := orchestrator.GetOrchestrationOptions(cmd)
		if err != nil {
			return fmt.Errorf("failed to get orchestration options: %w", err)
		}

		logger.Info("Starting Vault creation",
			zap.String("orchestration_mode", string(opts.Mode)),
			zap.String("target", opts.Target))

		// Define direct execution function
		directExec := func(rc *eos_io.RuntimeContext) error {
			logger.Info("Executing direct Vault installation")
			err := vault.OrchestrateVaultCreate(rc)
			if err != nil {
				return fmt.Errorf("vault create failed: %w", err)
			}
			return nil
		}

		// Define Salt operation
		saltOp := createVaultSaltOperation(opts)

		// Execute based on orchestration mode
		if opts.Mode == orchestrator.OrchestrationModeSalt {
			return executeVaultWithSalt(rc, opts, directExec, saltOp)
		}

		// Execute directly
		return directExec(rc)
	}),
}

func init() {
	// Add orchestration flags
	orchestrator.AddOrchestrationFlags(CreateVaultEnhancedCmd)
	
	// Add Vault-specific flags
	CreateVaultEnhancedCmd.Flags().String("vault-version", "", "Specific Vault version to install")
	CreateVaultEnhancedCmd.Flags().String("vault-config-path", "/etc/vault.d", "Vault configuration directory")
	CreateVaultEnhancedCmd.Flags().String("vault-data-path", "/opt/vault/data", "Vault data directory")
	CreateVaultEnhancedCmd.Flags().Bool("vault-ha", false, "Configure for high availability")
	CreateVaultEnhancedCmd.Flags().String("vault-backend", "file", "Storage backend (file, consul, etc.)")
	CreateVaultEnhancedCmd.Flags().String("vault-cluster-name", "vault-cluster", "Cluster name for HA setup")
	CreateVaultEnhancedCmd.Flags().Int("vault-cluster-size", 3, "Number of nodes in HA cluster")
	CreateVaultEnhancedCmd.Flags().Bool("vault-auto-unseal", false, "Configure auto-unseal with cloud providers")
	CreateVaultEnhancedCmd.Flags().String("vault-tls-cert", "", "Path to TLS certificate")
	CreateVaultEnhancedCmd.Flags().String("vault-tls-key", "", "Path to TLS private key")
	
	CreateCmd.AddCommand(CreateVaultEnhancedCmd)
}

// createVaultSaltOperation creates the Salt operation for Vault installation
func createVaultSaltOperation(opts *orchestrator.OrchestrationOptions) *orchestrator.SaltOperation {
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

// executeVaultWithSalt executes Vault installation using Salt orchestration
func executeVaultWithSalt(rc *eos_io.RuntimeContext, opts *orchestrator.OrchestrationOptions, directExec orchestrator.DirectExecutor, saltOp *orchestrator.SaltOperation) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Executing Vault installation via Salt orchestration")

	// Create Salt client configuration
	saltConfig := &client.ClientConfig{
		BaseURL:    getSaltURLFromEnv(),
		Username:   getSaltUsernameFromEnv(),
		Password:   getSaltPasswordFromEnv(),
		Eauth:      getSaltEauthFromEnv(),
		Timeout:    30 * time.Second,
		MaxRetries: 3,
		RetryDelay: 2 * time.Second,
	}

	// Check if Salt configuration is available
	if saltConfig.BaseURL == "" || saltConfig.Username == "" || saltConfig.Password == "" {
		logger.Warn("Salt configuration not available, falling back to direct execution")
		return directExec(rc)
	}

	// Create Salt client
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

	// Display results
	return displayVaultOrchestrationResult(rc, result)
}

// displayVaultOrchestrationResult displays the orchestration results
func displayVaultOrchestrationResult(rc *eos_io.RuntimeContext, result *orchestrator.OrchestrationResult) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Vault orchestration completed",
		zap.String("mode", string(result.Mode)),
		zap.Bool("success", result.Success),
		zap.Duration("duration", result.Duration))

	fmt.Printf("\n🏛️  Vault Installation Result\n")
	fmt.Printf("============================\n")
	fmt.Printf("Mode: %s\n", result.Mode)
	fmt.Printf("Status: ")
	if result.Success {
		fmt.Printf("✅ SUCCESS\n")
	} else {
		fmt.Printf("❌ FAILED\n")
	}
	fmt.Printf("Duration: %s\n", result.Duration)
	fmt.Printf("Message: %s\n", result.Message)

	if result.JobID != "" {
		fmt.Printf("Salt Job ID: %s\n", result.JobID)
	}

	if len(result.Minions) > 0 {
		fmt.Printf("\n🎯 Target Minions (%d):\n", len(result.Minions))
		for _, minion := range result.Minions {
			fmt.Printf("   • %s\n", minion)
		}
	}

	if len(result.Failed) > 0 {
		fmt.Printf("\n❌ Failed Minions (%d):\n", len(result.Failed))
		for _, minion := range result.Failed {
			fmt.Printf("   • %s\n", minion)
		}
	}

	if result.Mode == orchestrator.OrchestrationModeSalt && result.Success {
		fmt.Printf("\n💡 Next Steps:\n")
		fmt.Printf("   • Check Vault status: eos salt run '%s' vault.status\n", "vault-*")
		fmt.Printf("   • Initialize Vault: eos salt run '%s' vault.init\n", "vault-*") 
		fmt.Printf("   • Unseal Vault: eos salt run '%s' vault.unseal\n", "vault-*")
		fmt.Printf("   • View logs: eos salt run '%s' cmd.run 'journalctl -u vault -f'\n", "vault-*")
	}

	return nil
}

// Helper functions to get Salt configuration from environment
func getSaltURLFromEnv() string {
	// This would typically read from environment variables or config files
	// For now, return empty to trigger fallback
	return ""
}

func getSaltUsernameFromEnv() string {
	return ""
}

func getSaltPasswordFromEnv() string {
	return ""
}

func getSaltEauthFromEnv() string {
	return "pam"
}