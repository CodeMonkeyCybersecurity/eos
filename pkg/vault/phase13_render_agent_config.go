// pkg/vault/phase13_render_agent_config.go

//--------------------------------------------------------------------
// 11. Render Vault Agent Configuration
//--------------------------------------------------------------------

// PHASE 11 — PhaseRenderVaultAgentConfig()
//            └── RenderAgentConfig()
//            └── EnsureAgentConfig()
//            └── ReloadDaemonAndEnable()

package vault

import (
	"fmt"
	"os"
	"text/template"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

// PhaseRenderVaultAgentConfig creates the Vault Agent HCL config.
func PhaseRenderVaultAgentConfig(client *api.Client) error {
	zap.L().Info("📝 [Phase 13] Rendering Vault Agent configuration")

	addr := os.Getenv(shared.VaultAddrEnv)
	if addr == "" {
		return fmt.Errorf("VAULT_ADDR not set")
	}

	roleID, secretID, err := readAppRoleCredsFromDisk()
	if err != nil {
		return fmt.Errorf("read AppRole creds: %w", err)
	}

	if err := RenderAgentConfig(addr, roleID, secretID); err != nil {
		return fmt.Errorf("render agent config: %w", err)
	}

	if err := EnsureAgentConfig(addr); err != nil {
		return fmt.Errorf("ensure agent config: %w", err)
	}

	if err := system.ReloadDaemonAndEnable(shared.VaultAgentService); err != nil {
		return fmt.Errorf("reload daemon and enable agent service: %w", err)
	}

	zap.L().Info("✅ Vault Agent configuration rendered and systemd enabled")
	return nil
}

func RenderAgentConfig(addr, roleID, secretID string) error {
	if err := shared.EnsureSecretsDir(); err != nil {
		return err
	}

	if err := shared.EnsureFileExists(shared.AppRolePaths.RoleID, roleID, shared.OwnerReadOnly); err != nil {
		return err
	}
	if err := shared.EnsureFileExists(shared.AppRolePaths.SecretID, secretID, shared.OwnerReadOnly); err != nil {
		return err
	}

	data := shared.BuildAgentTemplateData(addr)
	tpl := template.Must(template.New("agent.hcl").Parse(shared.AgentConfigTmpl))

	zap.L().Info("📄 Writing Vault Agent config file", zap.String("path", shared.VaultAgentConfigPath))
	if err := shared.WriteAgentConfig(shared.VaultAgentConfigPath, tpl, data); err != nil {
		return err
	}

	if err := shared.SetFilePermission(shared.VaultAgentConfigPath, shared.FilePermStandard); err != nil {
		return err
	}

	zap.L().Info("✅ Vault Agent HCL successfully rendered", zap.String("output", shared.VaultAgentConfigPath))
	return nil
}

func EnsureAgentConfig(vaultAddr string) error {
	if _, err := os.Stat(shared.VaultAgentConfigPath); err == nil {
		zap.L().Info("✅ Vault Agent config already exists — skipping rewrite")
		return nil
	}

	// Check that required AppRole files exist
	if _, err := os.Stat(shared.AppRolePaths.RoleID); err != nil {
		return fmt.Errorf("role_id not found: %w", err)
	}
	if _, err := os.Stat(shared.AppRolePaths.SecretID); err != nil {
		return fmt.Errorf("secret_id not found: %w", err)
	}

	// Build the AgentConfigData from shared helper
	data := shared.BuildAgentTemplateData(vaultAddr)

	// Prepare the template
	tpl := template.Must(template.New("agent.hcl").Parse(shared.AgentConfigTmpl))

	// Write the config using shared WriteAgentConfig helper
	if err := shared.WriteAgentConfig(shared.VaultAgentConfigPath, tpl, data); err != nil {
		return fmt.Errorf("failed to write Vault Agent config: %w", err)
	}

	return nil
}
