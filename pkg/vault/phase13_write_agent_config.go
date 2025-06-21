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
	if err := prepareTokenSink(rc, shared.AgentToken, shared.EosID); err != nil {
		return fmt.Errorf("prepare token sink: %w", err)
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

	log.Info("✅ Vault Agent config + service installed")
	return nil
}

// prepareTokenSink ensures the runtime directory exists, ownership is correct,
// and the sink file is a fresh, zero‐length file owned by `user`.
func prepareTokenSink(rc *eos_io.RuntimeContext, tokenPath, user string) error {
	runDir := filepath.Dir(tokenPath)
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		return err
	}
	uid, gid, err := eos_unix.LookupUser(rc.Ctx, user)
	if err != nil {
		return err
	}
	if err := os.Chown(runDir, uid, gid); err != nil {
		return err
	}

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
		User:        shared.EosID,
		Group:       shared.EosID,
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
	tmpfilesContent := "d /run/eos 0755 eos eos -\n"

	log.Info("📁 Creating systemd tmpfiles configuration", zap.String("path", tmpfilesPath))

	if err := os.WriteFile(tmpfilesPath, []byte(tmpfilesContent), 0o644); err != nil {
		return fmt.Errorf("write tmpfiles config %s: %w", tmpfilesPath, err)
	}

	// Apply tmpfiles configuration immediately
	cmd := exec.CommandContext(rc.Ctx, "systemd-tmpfiles", "--create", tmpfilesPath)
	if err := cmd.Run(); err != nil {
		log.Warn("⚠️ Failed to apply tmpfiles config immediately", zap.Error(err))
		// Don't fail the entire process as the config will be applied on next boot
	}

	log.Info("✅ Systemd tmpfiles configuration created", zap.String("path", tmpfilesPath))
	return nil
}
