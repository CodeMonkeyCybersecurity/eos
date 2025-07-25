// pkg/vault/phase13_write_agent_config.go

package vault

import (
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

	log.Info(" Preparing runtime directory", zap.String("dir", runDir))

	if err := os.MkdirAll(runDir, 0o755); err != nil {
		log.Error(" Failed to create runtime directory",
			zap.String("dir", runDir),
			zap.Error(err))
		return err
	}

	uid, gid, err := eos_unix.LookupUser(rc.Ctx, user)
	if err != nil {
		log.Error(" Failed to lookup user for runtime directory ownership",
			zap.String("user", user),
			zap.Error(err))
		return err
	}

	if err := os.Chown(runDir, uid, gid); err != nil {
		log.Error(" Failed to set ownership on runtime directory",
			zap.String("dir", runDir),
			zap.String("user", user),
			zap.Error(err))
		return err
	}

	log.Info(" Runtime directory prepared successfully",
		zap.String("dir", runDir),
		zap.String("owner", user),
		zap.String("mode", "0755"))

	// remove stray directory if present
	if fi, err := os.Lstat(tokenPath); err == nil && fi.IsDir() {
		if err := os.RemoveAll(tokenPath); err != nil {
			return err
		}
	}
	f, err := os.OpenFile(tokenPath,
		os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	if cerr := f.Close(); cerr != nil {
		return cerr
	}
	return os.Chown(tokenPath, uid, gid)
}

func writeAgentHCL(rc *eos_io.RuntimeContext, addr, roleID, secretID string) error {
	// ensure AppRole files exist
	if err := shared.EnsureSecretsDir(); err != nil {
		return err
	}
	if err := shared.EnsureFileExists(rc.Ctx, shared.AppRolePaths.RoleID, roleID, shared.OwnerReadOnly); err != nil {
		return err
	}
	if err := shared.EnsureFileExists(rc.Ctx, shared.AppRolePaths.SecretID, secretID, shared.OwnerReadOnly); err != nil {
		return err
	}

	data := shared.BuildAgentTemplateData(addr)
	path := shared.VaultAgentConfigPath
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() {
		if err := f.Close(); err != nil {
			// Log silently as this is a file write operation
			_ = err
		}
	}()

	if err := agentHCLTpl.Execute(f, data); err != nil {
		return err
	}
	return os.Chmod(path, shared.FilePermStandard)
}

func writeAgentUnit() error {
	data := shared.AgentSystemdData{
		Description: "Vault Agent (Eos)",
		User:        "vault",
		Group:       "vault",
		RuntimeDir:  "eos", // fix: use relative path for RuntimeDirectory, not absolute
		ExecStart:   fmt.Sprintf("vault agent -config=%s", shared.VaultAgentConfigPath),
		RuntimeMode: "0700",
	}

	path := shared.VaultAgentServicePath
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() {
		if err := f.Close(); err != nil {
			// Log silently as this is a file write operation
			_ = err
		}
	}()

	if err := agentServiceTpl.Execute(f, data); err != nil {
		return err
	}
	return os.Chmod(path, 0o644)
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

	log.Info("🧹 Cleaning up stale HCP directory to prevent JSON parsing issues",
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
