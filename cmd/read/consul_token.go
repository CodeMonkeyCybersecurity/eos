// cmd/read/consul_token.go
//
// Retrieve Consul ACL bootstrap token from Vault and display configuration instructions.
//
// Last Updated: 2025-01-25

package read

import (
	"fmt"

	consulacl "github.com/CodeMonkeyCybersecurity/eos/pkg/consul/acl"
	consulenv "github.com/CodeMonkeyCybersecurity/eos/pkg/consul/environment"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	consulapi "github.com/hashicorp/consul/api"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var (
	consulTokenExport   bool
	consulTokenValidate bool
)

// ConsulTokenCmd retrieves the Consul bootstrap token from Vault
var ConsulTokenCmd = &cobra.Command{
	Use:   "consul-token",
	Short: "Retrieve Consul bootstrap token from Vault",
	Long: `Retrieve the Consul ACL bootstrap token from Vault and display configuration instructions.

This command helps you:
1. Retrieve the bootstrap token from Vault (secret/consul/bootstrap-token)
2. Validate the token works with Consul
3. Display instructions for configuring your environment
4. Optionally generate export command for shell

The bootstrap token is the master Consul ACL token with global-management permissions.
It's stored in Vault during 'eos update consul --bootstrap-token'.

Examples:
  # Retrieve token and show configuration instructions
  eos read consul-token

  # Validate token works with Consul API
  eos read consul-token --validate

  # Generate export command for current shell session
  eos read consul-token --export

  # Retrieve and export in one step
  eval $(eos read consul-token --export)

Use Cases:
  - Configure CONSUL_HTTP_TOKEN for eos commands
  - Configure Vault Consul secrets engine
  - Create additional ACL tokens
  - Troubleshoot ACL permissions

Security Note:
  The bootstrap token has full permissions. Protect it carefully.
  Consider creating service-specific tokens for applications.

Code Monkey Cybersecurity - "Cybersecurity. With humans."`,
	RunE: eos.Wrap(runConsulTokenRead),
}

func init() {
	ConsulTokenCmd.Flags().BoolVar(&consulTokenExport, "export", false,
		"Output as shell export command (use with: eval $(eos read consul-token --export))")
	ConsulTokenCmd.Flags().BoolVar(&consulTokenValidate, "validate", false,
		"Validate token works with Consul API")
}

func runConsulTokenRead(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Get Vault client
	vaultClient, err := vault.GetVaultClient(rc)
	if err != nil {
		return eos_err.NewUserError(
			"Failed to connect to Vault.\n\n" +
				"The Consul bootstrap token is stored in Vault at:\n" +
				"  secret/consul/bootstrap-token\n\n" +
				"Remediation:\n" +
				"  - Ensure Vault is installed: eos create vault\n" +
				"  - Ensure Vault is unsealed: vault status\n" +
				"  - Check Vault agent is running: systemctl status vault-agent-eos\n\n" +
				fmt.Sprintf("Error: %v", err))
	}

	// Discover environment from Consul (required for Vault path)
	env, err := consulenv.DiscoverFromConsul(rc)
	if err != nil {
		return fmt.Errorf("failed to discover environment: %w\n\n"+
			"Token retrieval requires knowing the environment.\n"+
			"Consul is the authoritative source for environment configuration.\n\n"+
			"Remediation:\n"+
			"  1. Ensure Consul is running: systemctl status consul\n"+
			"  2. Set environment: eos update consul --environment <env>\n"+
			"  3. Emergency override (Consul unavailable):\n"+
			"     CONSUL_EMERGENCY_OVERRIDE=true eos read consul-token --environment <env>",
			err)
	}

	logger.Info("Using environment for Vault secret path",
		zap.String("environment", string(env)))

	// ASSESS - Retrieve token from Vault
	logger.Info("Retrieving Consul bootstrap token from Vault")

	token, err := consulacl.GetBootstrapTokenFromVault(rc, vaultClient, env)
	if err != nil {
		return eos_err.NewUserError(
			"Failed to retrieve Consul bootstrap token from Vault.\n\n" +
				"The token may not exist yet. Bootstrap ACLs first:\n" +
				"  eos update consul --bootstrap-token\n\n" +
				"Or check if token exists in Vault:\n" +
				"  vault kv get secret/consul/bootstrap-token\n\n" +
				fmt.Sprintf("Error: %v", err))
	}

	if token == "" {
		return eos_err.NewUserError(
			"Consul bootstrap token is empty in Vault.\n\n" +
				"This indicates a storage issue. Re-bootstrap:\n" +
				"  eos update consul --bootstrap-token\n\n" +
				"Vault path: secret/consul/bootstrap-token")
	}

	// EVALUATE - Validate token if requested
	if consulTokenValidate {
		logger.Info("Validating token with Consul API")

		consulConfig := consulapi.DefaultConfig()
		consulConfig.Token = token
		consulClient, err := consulapi.NewClient(consulConfig)
		if err != nil {
			return fmt.Errorf("failed to create Consul client for validation: %w\n"+
				"Token retrieved from Vault but client creation failed.\n"+
				"Check Consul is running: systemctl status consul",
				err)
		}

		// Try to read self
		selfToken, _, err := consulClient.ACL().TokenReadSelf(nil)
		if err != nil {
			return fmt.Errorf("token validation failed: %w\n"+
				"Token exists in Vault but Consul rejected it.\n"+
				"Possible causes:\n"+
				"  - Token was revoked or deleted in Consul\n"+
				"  - Consul ACL system was re-initialized\n"+
				"  - Network connectivity to Consul API\n\n"+
				"Re-bootstrap to generate a new token:\n"+
				"  eos update consul --bootstrap-token",
				err)
		}

		logger.Info("Token validated successfully",
			zap.String("accessor", selfToken.AccessorID),
			zap.String("description", selfToken.Description),
			zap.Int("policies", len(selfToken.Policies)))

		// Check for global-management
		hasGlobalManagement := false
		for _, policy := range selfToken.Policies {
			if policy.Name == "global-management" {
				hasGlobalManagement = true
				break
			}
		}

		if hasGlobalManagement {
			logger.Info("Token has global-management policy (full permissions)")
		} else {
			logger.Warn("Token does not have global-management policy",
				zap.String("note", "This may not be the bootstrap token"))
		}
	}

	// INTERVENE - Output based on mode
	if consulTokenExport {
		// Export mode: output ONLY the export command (for eval)
		fmt.Printf("export CONSUL_HTTP_TOKEN=\"%s\"\n", token)
		return nil
	}

	// Standard mode: show token and instructions
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: ✓ Consul Bootstrap Token Retrieved")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: Token: " + token)
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: === Configuration Instructions ===")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: For current shell session:")
	logger.Info("terminal prompt:   export CONSUL_HTTP_TOKEN=\"" + token + "\"")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: For persistent configuration (add to ~/.bashrc or ~/.zshrc):")
	logger.Info("terminal prompt:   echo 'export CONSUL_HTTP_TOKEN=\"" + token + "\"' >> ~/.bashrc")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: Or use eval to set immediately:")
	logger.Info("terminal prompt:   eval $(eos read consul-token --export)")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: Verify configuration:")
	logger.Info("terminal prompt:   consul acl token read -self")
	logger.Info("terminal prompt:   eos read consul-token --validate")
	logger.Info("terminal prompt: ")

	if !consulTokenValidate {
		logger.Info("terminal prompt: Run with --validate to test token against Consul API")
		logger.Info("terminal prompt: ")
	}

	return nil
}
