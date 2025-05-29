// pkg/vault/phase13_write_agent_config.go

package vault

import (
	"fmt"
	"os"
	"path/filepath"
	"text/template"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
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
	defer f.Close()

	if err := agentHCLTpl.Execute(f, data); err != nil {
		return err
	}
	return os.Chmod(path, shared.FilePermStandard)
}

func writeAgentUnit() error {
	data := shared.AgentSystemdData{
		Description: "Vault Agent (EOS)",
		User:        shared.EosID,
		Group:       shared.EosID,
		RuntimeDir:  shared.EosID,
		ExecStart:   fmt.Sprintf("vault agent -config=%s", shared.VaultAgentConfigPath),
		RuntimeMode: "0700",
	}

	path := shared.VaultAgentServicePath
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	if err := agentServiceTpl.Execute(f, data); err != nil {
		return err
	}
	return os.Chmod(path, 0o644)
}
