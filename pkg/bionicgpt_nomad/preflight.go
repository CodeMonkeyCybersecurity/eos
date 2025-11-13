// pkg/bionicgpt_nomad/preflight.go - Phase 3: Preflight checks

package bionicgpt_nomad

import (
	"fmt"
	"os/exec"
	"strings"

	consulapi "github.com/hashicorp/consul/api"
	vaultapi "github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/nomad"
)

// Preflight runs all preflight checks
func (ei *EnterpriseInstaller) Preflight() error {
	logger := otelzap.Ctx(ei.rc.Ctx)

	checks := []PreflightCheck{
		{
			Name:        "Nomad",
			Description: "Check if Nomad is accessible",
			Check:       ei.checkNomad,
			Required:    true,
		},
		{
			Name:        "Consul",
			Description: "Check if Consul is accessible",
			Check:       ei.checkConsul,
			Required:    true,
		},
		{
			Name:        "Docker",
			Description: "Check if Docker is available",
			Check:       ei.checkDocker,
			Required:    true,
		},
		{
			Name:        "Vault",
			Description: "Check if Vault is accessible",
			Check:       ei.checkVault,
			Required:    true,
		},
		{
			Name:        "Caddy Admin API",
			Description: "Check if Caddy Admin API is accessible on cloud node",
			Check:       ei.checkCaddyAdminAPI,
			Required:    true,
		},
		{
			Name:        "Ollama",
			Description: "Check if Ollama is available (for local embeddings)",
			Check:       ei.checkOllama,
			Required:    ei.config.UseLocalEmbeddings,
		},
	}

	failed := false
	for i := range checks {
		check := &checks[i]
		logger.Info(fmt.Sprintf("  [%d/%d] %s", i+1, len(checks), check.Name))

		err := check.Check()
		check.Passed = (err == nil)
		check.Error = err

		if err != nil {
			if check.Required {
				logger.Error(fmt.Sprintf("  ✗ %s (REQUIRED)", check.Name), zap.Error(err))
				failed = true
			} else {
				logger.Warn(fmt.Sprintf("  ⚠ %s (optional)", check.Name), zap.Error(err))
			}
		} else {
			logger.Info(fmt.Sprintf("  ✓ %s", check.Name))
		}
	}

	if failed {
		return fmt.Errorf("one or more required preflight checks failed")
	}

	return nil
}

// checkTailscale checks if Tailscale is installed and connected
func (ei *EnterpriseInstaller) checkTailscale() error {
	// Check if tailscale command exists
	if _, err := exec.LookPath("tailscale"); err != nil {
		return fmt.Errorf("tailscale not installed: %w", err)
	}

	// Check if tailscale is running
	cmd := exec.CommandContext(ei.rc.Ctx, "tailscale", "status", "--json")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("tailscale not running: %w", err)
	}

	// Basic check that we got valid output
	if len(output) == 0 {
		return fmt.Errorf("tailscale status returned empty response")
	}

	return nil
}

// checkAuthentikToken checks if Authentik API token exists in Vault
func (ei *EnterpriseInstaller) checkAuthentikToken() error {
	logger := otelzap.Ctx(ei.rc.Ctx)

	// Create Vault client
	vaultClient, err := vaultapi.NewClient(vaultapi.DefaultConfig())
	if err != nil {
		return fmt.Errorf("failed to create Vault client: %w", err)
	}

	// Read Authentik credentials from Vault
	secret, err := vaultClient.Logical().Read("secret/data/bionicgpt/authentik")
	if err != nil {
		return fmt.Errorf("failed to read from Vault: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return fmt.Errorf("no Authentik credentials found in Vault at secret/bionicgpt/authentik")
	}

	data, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid secret format")
	}

	apiKey, ok := data["api_key"].(string)
	if !ok || apiKey == "" {
		return fmt.Errorf("api_key not found in Vault secret")
	}

	logger.Debug("Authentik API token found in Vault")
	return nil
}

// checkAzureCredentials checks if Azure OpenAI credentials exist in Vault
func (ei *EnterpriseInstaller) checkAzureCredentials() error {
	logger := otelzap.Ctx(ei.rc.Ctx)

	// Only check if Azure is configured
	if ei.config.AzureEndpoint == "" && ei.config.AzureChatDeployment == "" {
		logger.Debug("Azure OpenAI not configured, skipping credential check")
		return nil
	}

	// Create Vault client
	vaultClient, err := vaultapi.NewClient(vaultapi.DefaultConfig())
	if err != nil {
		return fmt.Errorf("failed to create Vault client: %w", err)
	}

	// Read Azure credentials from Vault
	secret, err := vaultClient.Logical().Read("secret/data/bionicgpt/azure")
	if err != nil {
		return fmt.Errorf("failed to read from Vault: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return fmt.Errorf("no Azure credentials found in Vault at secret/bionicgpt/azure")
	}

	data, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid secret format")
	}

	apiKey, ok := data["api_key"].(string)
	if !ok || apiKey == "" {
		return fmt.Errorf("api_key not found in Vault secret")
	}

	logger.Debug("Azure OpenAI credentials found in Vault")
	return nil
}

// checkNomad checks if Nomad is accessible
func (ei *EnterpriseInstaller) checkNomad() error {
	logger := otelzap.Ctx(ei.rc.Ctx)

	// Create Nomad client with a basic zap logger
	// Note: Nomad client needs *zap.Logger, not otelzap wrapper
	zapLogger := zap.NewNop()
	nomadClient, err := nomad.NewClient(ei.config.NomadAddress, zapLogger)
	if err != nil {
		return fmt.Errorf("failed to create Nomad client: %w", err)
	}

	// Check Nomad health
	if err := nomadClient.CheckHealth(ei.rc.Ctx); err != nil {
		return fmt.Errorf("nomad health check failed: %w", err)
	}

	logger.Debug("Nomad is accessible and healthy")
	return nil
}

// checkConsul checks if Consul is accessible
func (ei *EnterpriseInstaller) checkConsul() error {
	logger := otelzap.Ctx(ei.rc.Ctx)

	// Create Consul client
	config := consulapi.DefaultConfig()
	config.Address = ei.config.ConsulAddress

	consulClient, err := consulapi.NewClient(config)
	if err != nil {
		return fmt.Errorf("failed to create Consul client: %w", err)
	}

	// Try to get the leader
	leader, err := consulClient.Status().Leader()
	if err != nil {
		return fmt.Errorf("failed to get Consul leader: %w", err)
	}

	if leader == "" {
		return fmt.Errorf("no Consul leader elected")
	}

	logger.Debug("Consul is accessible", zap.String("leader", leader))
	return nil
}

// checkVault checks if Vault is accessible
func (ei *EnterpriseInstaller) checkVault() error {
	logger := otelzap.Ctx(ei.rc.Ctx)

	// Create Vault client
	vaultClient, err := vaultapi.NewClient(vaultapi.DefaultConfig())
	if err != nil {
		return fmt.Errorf("failed to create Vault client: %w", err)
	}

	// Check if we can access Vault (health check)
	health, err := vaultClient.Sys().Health()
	if err != nil {
		return fmt.Errorf("failed to check Vault health: %w", err)
	}

	if health.Sealed {
		return fmt.Errorf("vault is sealed")
	}

	logger.Debug("Vault is accessible and unsealed")
	return nil
}

// checkDocker checks if Docker is available
func (ei *EnterpriseInstaller) checkDocker() error {
	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("docker not installed: %w", err)
	}

	// Try to run docker ps to verify it's working
	cmd := exec.CommandContext(ei.rc.Ctx, "docker", "ps")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker daemon not accessible: %w", err)
	}

	return nil
}

// checkCaddyAdminAPI checks if Caddy Admin API is accessible
func (ei *EnterpriseInstaller) checkCaddyAdminAPI() error {
	logger := otelzap.Ctx(ei.rc.Ctx)

	// Get Tailscale IP of cloud node
	cloudIP, err := ei.getTailscaleIP(ei.config.CloudNode)
	if err != nil {
		return fmt.Errorf("failed to get cloud node Tailscale IP: %w", err)
	}

	// Create Caddy Admin API client
	caddyClient := hecate.NewCaddyAdminClient(cloudIP)

	// Check health
	if err := caddyClient.Health(ei.rc.Ctx); err != nil {
		return fmt.Errorf("caddy admin API not accessible at %s:2019: %w", cloudIP, err)
	}

	logger.Debug("Caddy Admin API is accessible", zap.String("host", cloudIP))
	return nil
}

// checkOllama checks if Ollama is available
func (ei *EnterpriseInstaller) checkOllama() error {
	if _, err := exec.LookPath("ollama"); err != nil {
		return fmt.Errorf("ollama not installed: %w", err)
	}

	// Try to list ollama models to verify it's working
	cmd := exec.CommandContext(ei.rc.Ctx, "ollama", "list")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("ollama not running or not accessible: %w", err)
	}

	return nil
}

// getTailscaleIP gets the Tailscale IP for a given hostname
func (ei *EnterpriseInstaller) getTailscaleIP(hostname string) (string, error) {
	cmd := exec.CommandContext(ei.rc.Ctx, "tailscale", "ip", hostname)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get Tailscale IP for %s: %w", hostname, err)
	}

	ip := strings.TrimSpace(string(output))
	if ip == "" {
		return "", fmt.Errorf("empty IP returned for %s", hostname)
	}

	return ip, nil
}

// getLocalTailscaleIP gets the local node's Tailscale IP
func (ei *EnterpriseInstaller) getLocalTailscaleIP() (string, error) {
	cmd := exec.CommandContext(ei.rc.Ctx, "tailscale", "ip", "-4")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get local Tailscale IP: %w", err)
	}

	ip := strings.TrimSpace(string(output))
	if ip == "" {
		return "", fmt.Errorf("empty local IP returned")
	}

	return ip, nil
}
