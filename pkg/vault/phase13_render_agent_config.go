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
	"path/filepath"
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

	// ─── Render & install the systemd unit for Vault Agent ───────────────────
	if err := renderAgentSystemdUnit(); err != nil {
		return fmt.Errorf("render agent systemd unit: %w", err)
	}

	if err := system.ReloadDaemonAndEnable(shared.VaultAgentService); err != nil {

		return fmt.Errorf("reload daemon and enable agent service: %w", err)
	}

	zap.L().Info("✅ Vault Agent configuration rendered and systemd enabled")
	return nil
}

// renderAgentSystemdUnit writes out the Vault Agent systemd service file
// using the shared.AgentSystemDUnit template and AgentSystemdData.
func renderAgentSystemdUnit() error {
	// fill in the templating data
	unitData := shared.AgentSystemdData{
		Description: "Vault Agent (eos)",
		User:        "eos",
		Group:       "eos",
		// use the same directory where we sink tokens
		RuntimeDir:  filepath.Dir(shared.AgentToken),
		RuntimePath: shared.AgentToken,
		ExecStart:   fmt.Sprintf("vault agent -config=%s", shared.VaultAgentConfigPath),
		RuntimeMode: 0755,
	}

	tpl := template.Must(template.New("vault-agent-eos.service").Parse(shared.AgentSystemDUnit))
	f, err := os.Create(shared.VaultAgentServicePath)
	if err != nil {
		return fmt.Errorf("create systemd unit file: %w", err)
	}
	defer f.Close()

	if err := tpl.Execute(f, unitData); err != nil {
		return fmt.Errorf("execute systemd unit template: %w", err)
	}

	if err := os.Chmod(shared.VaultAgentServicePath, 0644); err != nil {
		return fmt.Errorf("chmod systemd unit file: %w", err)
	}

	zap.L().Info("✅ Vault Agent systemd unit rendered", zap.String("path", shared.VaultAgentServicePath))
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
