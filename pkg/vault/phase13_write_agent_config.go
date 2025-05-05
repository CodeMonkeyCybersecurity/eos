// pkg/vault/phase13_write_agent_config.go

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

// PhaseRenderVaultAgentConfig drives everything in one pass:
// 1) Render+write agent HCL, 2) Render+write systemd, 3) daemon-reload+enable.
func PhaseRenderVaultAgentConfig(client *api.Client) error {
	logger := zap.L().Named("vault.PhaseRenderVaultAgentConfig")

	addr := os.Getenv(shared.VaultAddrEnv)
	if addr == "" {
		return fmt.Errorf("VAULT_ADDR not set")
	}

	// 2) ensure AppRole credentials exist on disk
	roleID, secretID, err := readAppRoleCredsFromDisk()
	if err != nil {
		return fmt.Errorf("read AppRole credentials: %w", err)
	}

	// 3) render + write Vault Agent HCL
	if err := writeAgentHCL(addr, roleID, secretID); err != nil {
		return fmt.Errorf("render/write agent HCL: %w", err)
	}

	// 4) Make sure our token‐sink path is a file, not a directory,
	//    then render & write the systemd unit.
	if fi, err := os.Stat(shared.AgentToken); err == nil && fi.IsDir() {
		if err := os.RemoveAll(shared.AgentToken); err != nil {
			return fmt.Errorf("remove stray token directory %s: %w", shared.AgentToken, err)
		}
	}
	// touch an empty file with 0600 perms so Vault Agent can sink into it
	f, err := os.OpenFile(shared.AgentToken, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("create token sink file %s: %w", shared.AgentToken, err)
	}
	f.Close()

	if err := writeAgentUnit(); err != nil {
		return fmt.Errorf("render/write systemd unit: %w", err)
	}

	// finally reload & enable
	if err := system.ReloadDaemonAndEnable(shared.VaultAgentService); err != nil {
		return fmt.Errorf("reload/enable service: %w", err)
	}

	logger.Info("✅ Vault Agent config + service installed")
	return nil
}

// writeAgentHCL ensures your AppRole files, renders the HCL template, writes it
func writeAgentHCL(addr, roleID, secretID string) error {
	// ensure the secrets directory exists
	if err := shared.EnsureSecretsDir(); err != nil {
		return err
	}

	// ensure role_id & secret_id files
	if err := shared.EnsureFileExists(shared.AppRolePaths.RoleID, roleID, shared.OwnerReadOnly); err != nil {
		return err
	}
	if err := shared.EnsureFileExists(shared.AppRolePaths.SecretID, secretID, shared.OwnerReadOnly); err != nil {
		return err
	}

	// parse & execute the HCL template
	data := shared.BuildAgentTemplateData(addr)
	tpl, err := template.New("agent.hcl").Parse(shared.AgentConfigTmpl)
	if err != nil {
		return fmt.Errorf("parse HCL template: %w", err)
	}

	path := shared.VaultAgentConfigPath
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create config %s: %w", path, err)
	}
	defer f.Close()

	if err := tpl.Execute(f, data); err != nil {
		return fmt.Errorf("execute HCL template: %w", err)
	}

	if err := os.Chmod(path, shared.FilePermStandard); err != nil {
		return fmt.Errorf("chmod %s: %w", path, err)
	}

	zap.L().Info("Wrote Vault Agent HCL", zap.String("path", path))

	return nil
}

// writeAgentUnit renders the systemd unit and sets proper permissions.
func writeAgentUnit() error {
	tpl := template.Must(
		template.New("vault-agent-eos.service").
			Parse(shared.AgentSystemDUnit),
	)

	data := shared.AgentSystemdData{
		Description: "Vault Agent (EOS)",
		User:        "eos",
		Group:       "eos",
		RuntimeDir:  filepath.Base(filepath.Dir(shared.AgentToken)),
		RuntimePath: shared.AgentToken,
		ExecStart:   fmt.Sprintf("vault agent -config=%s", shared.VaultAgentConfigPath),
		RuntimeMode: "0700",
	}

	path := shared.VaultAgentServicePath
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create unit %s: %w", path, err)
	}
	defer f.Close()

	// --- now: execute once directly to the file ---
	if err := tpl.Execute(f, data); err != nil {
		return fmt.Errorf("execute unit template: %w", err)
	}

	if err := os.Chmod(path, 0644); err != nil {
		return fmt.Errorf("chmod unit %s: %w", path, err)
	}

	zap.L().Info("Wrote Vault Agent systemd unit", zap.String("path", path))
	return nil
}
