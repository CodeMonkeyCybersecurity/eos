// pkg/vault/phase11_render_agent_config.go

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
	"strings"
	"text/template"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

// PhaseRenderVaultAgentConfig creates the Vault Agent HCL config.
func PhaseRenderVaultAgentConfig(client *api.Client, log *zap.Logger) error {
	log.Info("📝 [Phase 11] Rendering Vault Agent configuration")

	addr := os.Getenv(shared.VaultAddrEnv)
	if addr == "" {
		return fmt.Errorf("VAULT_ADDR not set")
	}

	roleID, secretID, err := readAppRoleCredsFromDisk(log)
	if err != nil {
		return fmt.Errorf("read AppRole creds: %w", err)
	}

	if err := RenderAgentConfig(addr, roleID, secretID, log); err != nil {
		return fmt.Errorf("render agent config: %w", err)
	}

	if err := EnsureAgentConfig(addr, log); err != nil {
		return fmt.Errorf("ensure agent config: %w", err)
	}

	if err := system.ReloadDaemonAndEnable(log, "vault-agent-eos.service"); err != nil {
		return fmt.Errorf("reload daemon and enable agent service: %w", err)
	}

	log.Info("✅ Vault Agent configuration rendered and systemd enabled")
	return nil
}

func RenderAgentConfig(addr, roleID, secretID string, log *zap.Logger) error {
	log.Info("🧩 Rendering Vault Agent HCL template",
		zap.String("VAULT_ADDR", addr),
		zap.String("role_id_path", shared.RoleIDPath),
		zap.String("secret_id_path", shared.SecretIDPath),
		zap.String("config_path", shared.VaultAgentConfigPath),
	)

	// Ensure secrets directory exists
	if err := os.MkdirAll(filepath.Dir(shared.RoleIDPath), shared.FilePermOwnerRWX); err != nil {
		log.Error("❌ Failed to create secrets directory", zap.String("dir", filepath.Dir(shared.RoleIDPath)), zap.Error(err))
		return err
	}
	log.Info("✅ Ensured secrets directory exists", zap.String("dir", filepath.Dir(shared.RoleIDPath)))

	// Ensure role_id exists or re-write it
	if _, err := os.Stat(shared.RoleIDPath); os.IsNotExist(err) {
		log.Warn("🔧 role_id file missing — re-creating", zap.String("path", shared.RoleIDPath))
		if err := os.WriteFile(shared.RoleIDPath, []byte(roleID), shared.OwnerReadOnly); err != nil {
			log.Error("❌ Failed to write role_id", zap.String("path", shared.RoleIDPath), zap.Error(err))
			return err
		}
		log.Info("✅ Wrote role_id", zap.String("path", shared.RoleIDPath), zap.String("perm", "0400"))
	} else {
		log.Info("📄 role_id file already exists", zap.String("path", shared.RoleIDPath))
	}

	// Ensure secret_id exists or re-write it
	if _, err := os.Stat(shared.SecretIDPath); os.IsNotExist(err) {
		log.Warn("🔧 secret_id file missing — re-creating", zap.String("path", shared.SecretIDPath))
		if err := os.WriteFile(shared.SecretIDPath, []byte(secretID), shared.OwnerReadOnly); err != nil {
			log.Error("❌ Failed to write secret_id", zap.String("path", shared.SecretIDPath), zap.Error(err))
			return err
		}
		log.Info("✅ Wrote secret_id", zap.String("path", shared.SecretIDPath), zap.String("perm", "0400"))
	} else {
		log.Info("📄 secret_id file already exists", zap.String("path", shared.SecretIDPath))
	}

	// Build template data
	data := struct {
		Addr, CACert, RoleFile, SecretFile, TokenSink string
	}{
		Addr:       addr,
		CACert:     shared.VaultAgentCACopyPath,
		RoleFile:   shared.RoleIDPath,
		SecretFile: shared.SecretIDPath,
		TokenSink:  shared.VaultAgentTokenPath,
	}

	// Write HCL config to disk
	log.Info("📄 Writing Vault Agent config file", zap.String("path", shared.VaultAgentConfigPath))
	tpl := template.Must(template.New("agent.hcl").Parse(shared.AgentConfigTmpl))
	f, err := os.Create(shared.VaultAgentConfigPath)
	if err != nil {
		log.Error("❌ Failed to create Vault Agent config file", zap.String("path", shared.VaultAgentConfigPath), zap.Error(err))
		return fmt.Errorf("create %s: %w", shared.VaultAgentConfigPath, err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			log.Warn("⚠️ Failed to close Vault Agent config file", zap.String("path", shared.VaultAgentConfigPath), zap.Error(cerr))
		}
	}()

	if err := tpl.Execute(f, data); err != nil {
		log.Error("❌ Failed to render Vault Agent template", zap.Error(err))
		return fmt.Errorf("execute template: %w", err)
	}

	if err := os.Chmod(shared.VaultAgentConfigPath, shared.FilePermStandard); err != nil {
		log.Warn("⚠️ Failed to set permissions on Vault Agent config", zap.String("path", shared.VaultAgentConfigPath), zap.Error(err))
	} else {
		log.Info("✅ Set permissions on Vault Agent config", zap.String("perm", fmt.Sprintf("%#o", shared.FilePermStandard)))
	}

	log.Info("✅ Vault Agent HCL successfully rendered", zap.String("output", shared.VaultAgentConfigPath))
	return nil
}

func EnsureAgentConfig(vaultAddr string, log *zap.Logger) error {

	// ✅ Check for existing config first
	if _, err := os.Stat(shared.VaultAgentConfigPath); err == nil {
		log.Info("✅ Vault Agent config already exists — skipping rewrite", zap.String("path", shared.VaultAgentConfigPath))
		return nil
	}

	// ✅ Check AppRole files exist
	if _, err := os.Stat(shared.RoleIDPath); err != nil {
		return fmt.Errorf("role_id not found: %w", err)
	}
	if _, err := os.Stat(shared.SecretIDPath); err != nil {
		return fmt.Errorf("secret_id not found: %w", err)
	}

	log.Info("✍️ Writing Vault Agent config file", zap.String("path", shared.VaultAgentConfigPath))

	// Use dynamic Vault address and listener
	content := fmt.Sprintf(`
pid_file = "%s"

auto_auth {
  method "approle" {
    config = {
      role_id_file_path   = "%s"
      secret_id_file_path = "%s"
    }
  }
  sink "file" {
    config = {
      path = "%s"
    }
  }
}

vault {
  address = "%s"
}

listener "tcp" {
  address     = "%s"
}

cache {
  use_auto_auth_token = true
}`, shared.AgentPID, shared.RoleIDPath, shared.SecretIDPath, shared.VaultAgentTokenPath, vaultAddr, shared.VaultDefaultPort)

	if err := os.WriteFile(shared.VaultAgentConfigPath, []byte(strings.TrimSpace(content)+"\n"), 0644); err != nil {
		return fmt.Errorf("failed to write Vault Agent config to %s: %w", shared.VaultAgentConfigPath, err)
	}

	log.Info("✅ Vault Agent config written successfully", zap.String("path", shared.VaultAgentConfigPath))
	return nil
}
