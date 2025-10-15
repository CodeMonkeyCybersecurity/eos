// pkg/vault/phase13_write_agent_config.go

package vault

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"text/template"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var (
	// parse once at init
	agentHCLTpl     = template.Must(template.New("agent.hcl").Parse(shared.AgentConfigTmpl))
	agentServiceTpl = template.Must(template.New("vault-agent-eos.service").Parse(shared.AgentSystemDUnit))
)

func PhaseRenderVaultAgentConfig(rc *eos_io.RuntimeContext, client *api.Client) error {
	log := otelzap.Ctx(rc.Ctx)

	addr := os.Getenv(shared.VaultAddrEnv)
	if addr == "" {
		return fmt.Errorf("VAULT_ADDR not set")
	}

	// 0) create systemd tmpfiles configuration for runtime directory persistence
	if err := createTmpfilesConfig(rc); err != nil {
		return fmt.Errorf("create tmpfiles config: %w", err)
	}

	// 1) prepare /run/eos and the sink file
	// Use vault user instead of deprecated eos user
	if err := prepareTokenSink(rc, shared.AgentToken, "vault"); err != nil {
		return fmt.Errorf("prepare token sink: %w", err)
	}

	// 1.5) clean up any stale HCP directory that may cause JSON parsing issues
	if err := cleanupStaleHCPDirectory(rc); err != nil {
		log.Warn("Failed to clean stale HCP directory", zap.Error(err))
		// Don't fail the entire process as this is not critical
	}

	// 2) render + write HCL
	roleID, secretID, err := readAppRoleCredsFromDisk(rc, client)
	if err != nil {
		return fmt.Errorf("read AppRole creds: %w", err)
	}
	if err := writeAgentHCL(rc, addr, roleID, secretID); err != nil {
		return fmt.Errorf("write agent HCL: %w", err)
	}

	// 3) render + write systemd unit (remove any stale file first)
	if err := os.Remove(shared.VaultAgentServicePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("cleanup old unit file: %w", err)
	}
	if err := writeAgentUnit(); err != nil {
		return fmt.Errorf("write systemd unit: %w", err)
	}

	// 4) reload & enable
	if err := eos_unix.ReloadDaemonAndEnable(rc.Ctx, shared.VaultAgentService); err != nil {
		return fmt.Errorf("reload/enable service: %w", err)
	}

	log.Info(" Vault Agent config + service installed")
	return nil
}

// prepareTokenSink ensures the runtime directory exists, ownership is correct,
// and the sink file is a fresh, zero‐length file owned by `user`.
func prepareTokenSink(rc *eos_io.RuntimeContext, tokenPath, user string) error {
	log := otelzap.Ctx(rc.Ctx)
	runDir := filepath.Dir(tokenPath)

	log.Info("Preparing Vault Agent token sink",
		zap.String("token_path", tokenPath),
		zap.String("runtime_dir", runDir),
		zap.String("target_owner", user),
		zap.String("target_permissions", "0600"))

	// Create runtime directory
	log.Debug("Creating runtime directory if needed",
		zap.String("dir", runDir),
		zap.String("mode", "0755"))

	if err := os.MkdirAll(runDir, 0o755); err != nil {
		log.Error("Failed to create runtime directory",
			zap.String("dir", runDir),
			zap.Error(err))
		return err
	}

	// Lookup target user
	uid, gid, err := eos_unix.LookupUser(rc.Ctx, user)
	if err != nil {
		log.Error("Failed to lookup user for runtime directory ownership",
			zap.String("user", user),
			zap.Error(err))
		return err
	}

	log.Debug("User resolved for runtime directory ownership",
		zap.String("user", user),
		zap.Int("uid", uid),
		zap.Int("gid", gid))

	// Set directory ownership
	log.Debug("Setting runtime directory ownership",
		zap.String("dir", runDir),
		zap.String("user", user),
		zap.Int("uid", uid),
		zap.Int("gid", gid))

	if err := os.Chown(runDir, uid, gid); err != nil {
		log.Error("Failed to set ownership on runtime directory",
			zap.String("dir", runDir),
			zap.String("user", user),
			zap.Int("uid", uid),
			zap.Int("gid", gid),
			zap.Error(err))
		return err
	}

	// Verify directory ownership
	dirStat, err := os.Stat(runDir)
	if err != nil {
		log.Warn("Directory created but verification stat failed",
			zap.String("dir", runDir),
			zap.Error(err))
	} else {
		log.Debug("Runtime directory ownership verified",
			zap.String("dir", runDir),
			zap.String("mode", dirStat.Mode().String()),
			zap.String("owner", user))
	}

	// Remove stray directory if token path is a directory
	if fi, err := os.Lstat(tokenPath); err == nil && fi.IsDir() {
		log.Warn("Token path exists as directory, removing",
			zap.String("path", tokenPath))
		if err := os.RemoveAll(tokenPath); err != nil {
			log.Error("Failed to remove stray directory at token path",
				zap.String("path", tokenPath),
				zap.Error(err))
			return err
		}
		log.Debug("Stray directory removed", zap.String("path", tokenPath))
	}

	// Create empty token file
	log.Debug("Creating empty token sink file",
		zap.String("path", tokenPath),
		zap.String("mode", "0600"))

	f, err := os.OpenFile(tokenPath,
		os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0o600)
	if err != nil {
		log.Error("Failed to create token sink file",
			zap.String("path", tokenPath),
			zap.Error(err))
		return err
	}
	if cerr := f.Close(); cerr != nil {
		log.Error("Failed to close token sink file after creation",
			zap.String("path", tokenPath),
			zap.Error(cerr))
		return cerr
	}

	// Set token file ownership
	log.Debug("Setting token file ownership",
		zap.String("path", tokenPath),
		zap.String("user", user),
		zap.Int("uid", uid),
		zap.Int("gid", gid))

	if err := os.Chown(tokenPath, uid, gid); err != nil {
		log.Error("Failed to set ownership on token file",
			zap.String("path", tokenPath),
			zap.String("user", user),
			zap.Int("uid", uid),
			zap.Int("gid", gid),
			zap.Error(err))
		return err
	}

	// Final verification of token file
	tokenStat, err := os.Stat(tokenPath)
	if err != nil {
		log.Warn("Token file created but verification stat failed",
			zap.String("path", tokenPath),
			zap.Error(err))
	} else {
		log.Info("Token sink prepared successfully",
			zap.String("path", tokenPath),
			zap.String("mode", tokenStat.Mode().String()),
			zap.Int64("size", tokenStat.Size()),
			zap.String("owner", user))
	}

	return nil
}

func writeAgentHCL(rc *eos_io.RuntimeContext, addr, roleID, secretID string) error {
	log := otelzap.Ctx(rc.Ctx)

	log.Info("Writing Vault Agent HCL configuration",
		zap.String("config_path", shared.VaultAgentConfigPath),
		zap.String("vault_addr", addr),
		zap.String("role_id_path", shared.AppRolePaths.RoleID),
		zap.String("secret_id_path", shared.AppRolePaths.SecretID),
		zap.String("target_owner", "vault"))

	// Ensure AppRole files exist WITH PROPER OWNERSHIP
	log.Debug("Ensuring secrets directory exists",
		zap.String("dir", filepath.Dir(shared.AppRolePaths.RoleID)))

	if err := shared.EnsureSecretsDir(); err != nil {
		log.Error("Failed to create secrets directory",
			zap.Error(err))
		return err
	}

	// Use eos_unix.WriteFile to ensure proper ownership on AppRole credential files
	log.Info("Ensuring AppRole credential files exist with vault ownership")

	// Write role_id with vault ownership
	if err := eos_unix.WriteFile(rc.Ctx, shared.AppRolePaths.RoleID, []byte(roleID), shared.OwnerReadOnly, "vault"); err != nil {
		log.Error("Failed to write role_id file with ownership",
			zap.String("path", shared.AppRolePaths.RoleID),
			zap.Error(err))
		return fmt.Errorf("write role_id: %w", err)
	}

	// Write secret_id with vault ownership
	if err := eos_unix.WriteFile(rc.Ctx, shared.AppRolePaths.SecretID, []byte(secretID), shared.OwnerReadOnly, "vault"); err != nil {
		log.Error("Failed to write secret_id file with ownership",
			zap.String("path", shared.AppRolePaths.SecretID),
			zap.Error(err))
		return fmt.Errorf("write secret_id: %w", err)
	}

	log.Info("AppRole credential files written with vault ownership",
		zap.String("role_id_path", shared.AppRolePaths.RoleID),
		zap.String("secret_id_path", shared.AppRolePaths.SecretID))

	// Build template data
	data := shared.BuildAgentTemplateData(addr)
	path := shared.VaultAgentConfigPath

	log.Info("Rendering Vault Agent config file",
		zap.String("path", path),
		zap.String("vault_addr", data.Addr),
		zap.String("sink_path", data.SinkPath),
		zap.String("target_owner", "vault"))

	// Render template to memory first
	var buf bytes.Buffer
	if err := agentHCLTpl.Execute(&buf, data); err != nil {
		log.Error("Failed to render Vault Agent config template",
			zap.Error(err))
		return fmt.Errorf("render template: %w", err)
	}

	log.Debug("Template rendered successfully",
		zap.Int("size_bytes", buf.Len()))

	// Write config file with vault ownership using eos_unix.WriteFile
	log.Debug("Writing config file with vault ownership",
		zap.String("path", path),
		zap.String("mode", fmt.Sprintf("%#o", shared.RuntimeFilePerms)))

	if err := eos_unix.WriteFile(rc.Ctx, path, buf.Bytes(), shared.RuntimeFilePerms, "vault"); err != nil {
		log.Error("Failed to write Vault Agent config file with ownership",
			zap.String("path", path),
			zap.Error(err))
		return fmt.Errorf("write config file: %w", err)
	}

	// Final verification
	stat, err := os.Stat(path)
	if err != nil {
		log.Warn("Config file written but verification stat failed",
			zap.String("path", path),
			zap.Error(err))
	} else {
		log.Info("Vault Agent HCL configuration written successfully",
			zap.String("path", path),
			zap.String("mode", stat.Mode().String()),
			zap.Int64("size", stat.Size()),
			zap.String("owner", "vault"))
	}

	return nil
}

func writeAgentUnit() error {
	log := otelzap.L()

	data := shared.AgentSystemdData{
		Description: "Vault Agent (Eos)",
		User:        "vault",
		Group:       "vault",
		RuntimeDir:  "eos", // fix: use relative path for RuntimeDirectory, not absolute
		ExecStart:   fmt.Sprintf("vault agent -config=%s", shared.VaultAgentConfigPath),
		RuntimeMode: "0700",
	}

	path := shared.VaultAgentServicePath

	log.Info("Writing Vault Agent systemd unit file",
		zap.String("path", path),
		zap.String("user", data.User),
		zap.String("group", data.Group),
		zap.String("runtime_dir", data.RuntimeDir),
		zap.String("exec_start", data.ExecStart))

	log.Debug("Creating systemd unit file",
		zap.String("path", path))

	f, err := os.Create(path)
	if err != nil {
		log.Error("Failed to create systemd unit file",
			zap.String("path", path),
			zap.Error(err))
		return err
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			log.Warn("Failed to close systemd unit file",
				zap.String("path", path),
				zap.Error(cerr))
		}
	}()

	log.Debug("Rendering systemd unit template")

	if err := agentServiceTpl.Execute(f, data); err != nil {
		log.Error("Failed to render systemd unit template",
			zap.Error(err))
		return err
	}

	log.Debug("Setting systemd unit file permissions",
		zap.String("path", path),
		zap.String("mode", "0644"))

	if err := os.Chmod(path, 0o644); err != nil {
		log.Error("Failed to set systemd unit file permissions",
			zap.String("path", path),
			zap.Error(err))
		return err
	}

	// Verify final state
	stat, err := os.Stat(path)
	if err != nil {
		log.Warn("Systemd unit file written but verification stat failed",
			zap.String("path", path),
			zap.Error(err))
	} else {
		log.Info("Vault Agent systemd unit file written successfully",
			zap.String("path", path),
			zap.String("mode", stat.Mode().String()),
			zap.Int64("size", stat.Size()))
	}

	return nil
}

// createTmpfilesConfig creates systemd tmpfiles configuration to ensure /run/eos persists across reboots
func createTmpfilesConfig(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)

	tmpfilesPath := "/etc/tmpfiles.d/eos.conf"
	// Use vault user instead of deprecated eos user
	tmpfilesContent := "d /run/eos 0755 vault vault -\n"

	log.Info(" Creating systemd tmpfiles configuration", zap.String("path", tmpfilesPath))

	if err := os.WriteFile(tmpfilesPath, []byte(tmpfilesContent), 0o644); err != nil {
		return fmt.Errorf("write tmpfiles config %s: %w", tmpfilesPath, err)
	}

	// Apply tmpfiles configuration immediately to create /run/eos
	log.Info(" Applying tmpfiles configuration immediately")
	cmd := exec.CommandContext(rc.Ctx, "systemd-tmpfiles", "--create", "--prefix=/run/eos")
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Error(" Failed to apply tmpfiles config immediately",
			zap.Error(err),
			zap.String("output", string(out)))
		// This is critical for Vault Agent to work, so return the error
		return fmt.Errorf("failed to apply tmpfiles config: %w", err)
	}

	// Verify the directory was created
	if stat, err := os.Stat("/run/eos"); err != nil {
		log.Error(" /run/eos directory still doesn't exist after tmpfiles creation", zap.Error(err))
		return fmt.Errorf("runtime directory not created by tmpfiles: %w", err)
	} else {
		log.Info(" Runtime directory created by tmpfiles",
			zap.String("path", "/run/eos"),
			zap.String("mode", stat.Mode().String()))
	}

	log.Info(" Systemd tmpfiles configuration created and applied", zap.String("path", tmpfilesPath))
	return nil
}

// cleanupStaleHCPDirectory removes the HCP directory that vault binary creates despite VAULT_SKIP_HCP=true
func cleanupStaleHCPDirectory(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)
	// Use vault user's home instead of deprecated eos user
	hcpDir := "/home/vault/.config/hcp"

	// Check if directory exists
	if _, err := os.Stat(hcpDir); os.IsNotExist(err) {
		log.Info(" HCP directory does not exist - no cleanup needed")
		return nil
	}

	log.Info(" Cleaning up stale HCP directory to prevent JSON parsing issues",
		zap.String("path", hcpDir))

	// Remove the entire HCP directory
	if err := os.RemoveAll(hcpDir); err != nil {
		log.Error(" Failed to remove HCP directory",
			zap.String("path", hcpDir),
			zap.Error(err))
		return fmt.Errorf("remove HCP directory %s: %w", hcpDir, err)
	}

	log.Info(" HCP directory cleaned up successfully", zap.String("path", hcpDir))
	return nil
}
