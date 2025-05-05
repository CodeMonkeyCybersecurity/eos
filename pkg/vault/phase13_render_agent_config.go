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
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"text/template"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

// PhaseRenderVaultAgentConfig creates the Vault Agent HCL config, renders & installs the systemd unit,
// then reloads & enables it.
func PhaseRenderVaultAgentConfig(client *api.Client) error {
	logger := zap.L().Named("vault.PhaseRenderVaultAgentConfig")
	logger.Info("▶️ [Phase 13] Starting PhaseRenderVaultAgentConfig")

	// 1. Load VAULT_ADDR
	addr := os.Getenv(shared.VaultAddrEnv)
	logger.Debug("loaded environment", zap.String(shared.VaultAddrEnv, addr))
	if addr == "" {
		logger.Error("VAULT_ADDR is unset")
		return fmt.Errorf("VAULT_ADDR not set")
	}

	// 2. Read existing AppRole creds
	logger.Info("reading AppRole credentials from disk",
		zap.String("role_path", shared.AppRolePaths.RoleID),
		zap.String("secret_path", shared.AppRolePaths.SecretID),
	)
	roleID, secretID, err := readAppRoleCredsFromDisk()
	if err != nil {
		logger.Error("failed to read AppRole creds", zap.Error(err))
		return fmt.Errorf("read AppRole creds: %w", err)
	}
	logger.Info("AppRole credentials loaded", zap.String("role_id", roleID), zap.Int("secret_id_len", len(secretID)))

	// 3. Render HCL config
	logger.Info("rendering Vault Agent HCL config",
		zap.String("addr", addr),
	)
	if err := RenderAgentConfig(addr, roleID, secretID); err != nil {
		logger.Error("RenderAgentConfig failed", zap.Error(err))
		return fmt.Errorf("render agent config: %w", err)
	}
	logger.Info("Vault Agent HCL rendered", zap.String("path", shared.VaultAgentConfigPath))

	// 4. Render & write systemd unit
	logger.Info("rendering Vault Agent systemd unit")
	if err := renderAgentSystemdUnit(); err != nil {
		logger.Error("renderAgentSystemdUnit failed", zap.Error(err))
		return fmt.Errorf("render agent systemd unit: %w", err)
	}

	// 5. Reload and enable the service
	logger.Info("reloading systemd daemon & enabling service", zap.String("unit", shared.VaultAgentService))
	if err := system.ReloadDaemonAndEnable(shared.VaultAgentService); err != nil {
		// capture stderr if it's an ExitError
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			logger.Error("systemctl reload/enable failed",
				zap.String("unit", shared.VaultAgentService),
				zap.ByteString("stderr", exitErr.Stderr),
			)
		} else {
			logger.Error("failed to reload/enable systemd unit", zap.Error(err))
		}
		return fmt.Errorf("reload daemon and enable agent service: %w", err)
	}
	logger.Info("systemd daemon reloaded & service enabled", zap.String("unit", shared.VaultAgentService))

	logger.Info("✅ PhaseRenderVaultAgentConfig completed successfully")
	return nil
}

// renderAgentSystemdUnit writes out the Vault Agent systemd service file
// using the shared.AgentSystemDUnit template and AgentSystemdData.
func renderAgentSystemdUnit() error {
	logger := zap.L().Named("vault.renderAgentSystemdUnit")
	logger.Info("▶️ Starting renderAgentSystemdUnit")

	// prepare unit data
	unitData := shared.AgentSystemdData{
		Description: "Vault Agent (EOS)",
		User:        "eos",
		Group:       "eos",
		RuntimeDir:  filepath.Dir(shared.AgentToken),
		RuntimePath: shared.AgentToken,
		ExecStart:   fmt.Sprintf("vault agent -config=%s", shared.VaultAgentConfigPath),
		RuntimeMode: 0755,
	}
	logger.Debug("prepared systemd unit data", zap.Any("unitData", unitData))

	// parse template
	tpl, err := template.New("vault-agent-eos.service").Parse(shared.AgentSystemDUnit)
	if err != nil {
		logger.Error("failed to parse systemd unit template", zap.Error(err))
		return fmt.Errorf("parse systemd template: %w", err)
	}

	// create file
	path := shared.VaultAgentServicePath
	logger.Debug("creating systemd unit file", zap.String("path", path))
	f, err := os.Create(path)
	if err != nil {
		logger.Error("failed to create unit file", zap.String("path", path), zap.Error(err))
		return fmt.Errorf("create systemd unit file: %w", err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			logger.Warn("failed to close unit file", zap.String("path", path), zap.Error(cerr))
		}
	}()

	// execute template
	logger.Debug("executing systemd unit template", zap.String("path", path))
	if err := tpl.Execute(f, unitData); err != nil {
		logger.Error("failed to execute unit template", zap.Error(err))
		return fmt.Errorf("execute systemd unit template: %w", err)
	}

	// set permissions
	logger.Debug("setting permissions on unit file", zap.String("path", path), zap.String("perm", "0644"))
	if err := os.Chmod(path, 0644); err != nil {
		logger.Error("failed to chmod unit file", zap.String("path", path), zap.Error(err))
		return fmt.Errorf("chmod systemd unit file: %w", err)
	}

	logger.Info("✅ Vault Agent systemd unit rendered", zap.String("path", path))
	return nil
}

// RenderAgentConfig writes the agent HCL file, ensures perms, and logs each step.
func RenderAgentConfig(addr, roleID, secretID string) error {
	logger := zap.L().Named("vault.RenderAgentConfig")
	logger.Info("starting Vault Agent HCL render",
		zap.String("VAULT_ADDR", addr),
		zap.String("role_id", roleID),
		zap.String("secret_id", secretID),
	)

	// 1) ensure secrets directory exists
	dir := filepath.Dir(shared.AppRolePaths.RoleID)
	logger.Debug("ensuring secrets dir exists", zap.String("dir", dir))
	if err := shared.EnsureSecretsDir(); err != nil {
		logger.Error("failed to ensure secrets dir", zap.String("dir", dir), zap.Error(err))
		return err
	}
	logger.Info("secrets dir ready", zap.String("dir", dir))

	// 2) ensure role_id file
	logger.Debug("ensuring role_id file exists", zap.String("path", shared.AppRolePaths.RoleID))
	if err := shared.EnsureFileExists(shared.AppRolePaths.RoleID, roleID, shared.OwnerReadOnly); err != nil {
		logger.Error("failed to write role_id file", zap.String("path", shared.AppRolePaths.RoleID), zap.Error(err))
		return err
	}
	logger.Info("role_id file in place", zap.String("path", shared.AppRolePaths.RoleID))

	// 3) ensure secret_id file
	logger.Debug("ensuring secret_id file exists", zap.String("path", shared.AppRolePaths.SecretID))
	if err := shared.EnsureFileExists(shared.AppRolePaths.SecretID, secretID, shared.OwnerReadOnly); err != nil {
		logger.Error("failed to write secret_id file", zap.String("path", shared.AppRolePaths.SecretID), zap.Error(err))
		return err
	}
	logger.Info("secret_id file in place", zap.String("path", shared.AppRolePaths.SecretID))

	// 4) build template data
	data := shared.BuildAgentTemplateData(addr)
	logger.Debug("agent template data built", zap.Any("data", data))

	// 5) parse the HCL template
	tpl, err := template.New("agent.hcl").Parse(shared.AgentConfigTmpl)
	if err != nil {
		logger.Error("failed to parse agent HCL template", zap.Error(err))
		return fmt.Errorf("parse template: %w", err)
	}

	// 6) write out the HCL
	logger.Info("writing Vault Agent HCL", zap.String("path", shared.VaultAgentConfigPath))
	if err := shared.WriteAgentConfig(shared.VaultAgentConfigPath, tpl, data); err != nil {
		logger.Error("failed to write agent HCL", zap.String("path", shared.VaultAgentConfigPath), zap.Error(err))
		return fmt.Errorf("write config: %w", err)
	}
	logger.Info("agent HCL written", zap.String("path", shared.VaultAgentConfigPath))

	// 7) set file perms
	logger.Debug("setting file permissions", zap.String("path", shared.VaultAgentConfigPath), zap.String("perm", fmt.Sprintf("%#o", shared.FilePermStandard)))
	if err := shared.SetFilePermission(shared.VaultAgentConfigPath, shared.FilePermStandard); err != nil {
		logger.Error("failed to set file permissions", zap.String("path", shared.VaultAgentConfigPath), zap.Error(err))
		return err
	}
	logger.Info("file permissions set", zap.String("path", shared.VaultAgentConfigPath))

	logger.Info("RenderAgentConfig completed successfully", zap.String("output", shared.VaultAgentConfigPath))
	return nil
}

// EnsureAgentConfig only writes a new HCL if one doesn’t already exist.
func EnsureAgentConfig(vaultAddr string) error {
	logger := zap.L().Named("vault.EnsureAgentConfig")
	logger.Info("checking for existing Vault Agent config", zap.String("path", shared.VaultAgentConfigPath))

	if _, err := os.Stat(shared.VaultAgentConfigPath); err == nil {
		logger.Info("existing config detected; skipping", zap.String("path", shared.VaultAgentConfigPath))
		return nil
	}

	// verify AppRole creds are on disk
	for _, p := range []struct{ name, path string }{
		{"role_id", shared.AppRolePaths.RoleID},
		{"secret_id", shared.AppRolePaths.SecretID},
	} {
		logger.Debug("verifying AppRole file exists", zap.String("type", p.name), zap.String("path", p.path))
		if _, err := os.Stat(p.path); err != nil {
			logger.Error("AppRole file not found", zap.String("path", p.path), zap.Error(err))
			return fmt.Errorf("%s not found: %w", p.name, err)
		}
	}

	// build data & template
	logger.Debug("building agent template data", zap.String("VAULT_ADDR", vaultAddr))
	data := shared.BuildAgentTemplateData(vaultAddr)
	tpl, err := template.New("agent.hcl").Parse(shared.AgentConfigTmpl)
	if err != nil {
		logger.Error("failed to parse agent HCL template", zap.Error(err))
		return fmt.Errorf("parse template: %w", err)
	}

	// write new config
	logger.Info("writing new Vault Agent config", zap.String("path", shared.VaultAgentConfigPath))
	if err := shared.WriteAgentConfig(shared.VaultAgentConfigPath, tpl, data); err != nil {
		logger.Error("failed to write new config", zap.String("path", shared.VaultAgentConfigPath), zap.Error(err))
		return fmt.Errorf("write config: %w", err)
	}
	logger.Info("new Vault Agent config written", zap.String("path", shared.VaultAgentConfigPath))

	return nil
}
