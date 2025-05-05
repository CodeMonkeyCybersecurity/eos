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

// PhaseRenderVaultAgentConfig drives everything in one pass:
// 1) Render+write agent HCL, 2) Render+write systemd, 3) daemon-reload+enable.
func PhaseRenderVaultAgentConfig(client *api.Client) error {
	logger := zap.L().Named("vault.PhaseRenderVaultAgentConfig")

	addr := os.Getenv(shared.VaultAddrEnv)
	if addr == "" {
		return fmt.Errorf("VAULT_ADDR not set")
	}

	// ensure the AppRole creds files exist & are readable
	if _, _, err := readAppRoleCredsFromDisk(); err != nil {
		return fmt.Errorf("read AppRole creds: %w", err)
	}

	// —— Single helper that does parse+write+chmod ——
	if err := renderAndWriteAgentHCL(addr); err != nil {
		return fmt.Errorf("render/write agent HCL: %w", err)
	}

	// —— Single helper for systemd unit ——
	if err := renderAgentSystemdUnit(); err != nil {
		return fmt.Errorf("render/write systemd unit: %w", err)
	}

	// finally reload & enable
	if err := system.ReloadDaemonAndEnable(shared.VaultAgentService); err != nil {
		return fmt.Errorf("reload/enable service: %w", err)
	}

	logger.Info("✅ Vault Agent config + service installed")
	return nil
}

// renderAndWriteAgentHCL combines what used to be RenderAgentConfig + EnsureAgentConfig
func renderAndWriteAgentHCL(addr string) error {
	logger := zap.L().Named("vault.renderAndWriteAgentHCL")

	data := shared.BuildAgentTemplateData(addr)
	tpl, err := template.New("agent.hcl").Parse(shared.AgentConfigTmpl)
	if err != nil {
		return fmt.Errorf("parse HCL template: %w", err)
	}

	path := shared.VaultAgentConfigPath
	// create or overwrite
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create HCL file: %w", err)
	}
	defer f.Close()

	if err := tpl.Execute(f, data); err != nil {
		return fmt.Errorf("execute HCL template: %w", err)
	}
	if err := os.Chmod(path, shared.FilePermStandard); err != nil {
		return fmt.Errorf("chmod HCL file: %w", err)
	}

	logger.Info("agent HCL written", zap.String("path", path))
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
		RuntimeMode: "0700",
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
