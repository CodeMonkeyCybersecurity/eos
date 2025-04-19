// pkg/vault/lifecycle_agent.go

package vault

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"text/template"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/xdg"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

//
// ========================== ENSURE ==========================
//

// EnsureAgent configures & launches the Vault Agent under the eos system‑user.
// `password` is only used by the userpass method; for AppRole you can pass ""
// and `opts` comes from DefaultAppRoleOptions().
func EnsureAgent(client *api.Client, password string, log *zap.Logger, opts AppRoleOptions) error {
	log.Info("🔧 Starting Vault Agent setup for user 'eos'")

	// 1) render agent HCL
	addr := os.Getenv("VAULT_ADDR")
	ca := VaultAgentCACopyPath
	log.Info("📝 Rendering Vault Agent HCL", zap.String("path", VaultAgentConfigPath))
	if err := RenderAgentConfig(addr, ca, FallbackRoleIDPath, FallbackSecretIDPath, VaultAgentTokenPath, log); err != nil {
		return fmt.Errorf("render agent config: %w", err)
	}

	// 2) write password (if any)
	if password != "" {
		log.Info("🔑 Writing Agent password file")
		if err := writeAgentPassword(password, log); err != nil {
			return err
		}
	}

	// 3) ensure AppRole (drops role_id & secret_id into /etc/vault)
	log.Info("🔐 Provisioning AppRole for Agent")
	if err := EnsureAppRole(client, log, opts); err != nil {
		return fmt.Errorf("ensure approle: %w", err)
	}

	// 4) write systemd unit
	log.Info("⚙️ Writing Vault Agent systemd unit")
	if err := WriteSystemdUnit(log); err != nil {
		return fmt.Errorf("write systemd unit: %w", err)
	}

	// 5) reload & enable
	log.Info("🚀 Enabling & starting Vault Agent service")
	if err := system.ReloadDaemonAndEnable(log, VaultAgentService); err != nil {
		return fmt.Errorf("enable agent service: %w", err)
	}

	log.Info("✅ Vault Agent for eos is running and ready")
	return nil
}

// --- Helper Functions ---

func writeAgentPassword(password string, log *zap.Logger) error {
	log.Debug("🔏 Writing Vault Agent password to file", zap.String("path", VaultAgentPassPath))

	if err := os.WriteFile(VaultAgentPassPath, []byte(password+"\n"), 0600); err != nil {
		log.Error("❌ Failed to write password file", zap.String("path", VaultAgentPassPath), zap.Error(err))
		return fmt.Errorf("failed to write Vault Agent password to %s: %w", VaultAgentPassPath, err)
	}

	log.Info("✅ Vault Agent password file written", zap.String("path", VaultAgentPassPath))
	return nil
}

//
// ========================= RENDERING =========================
//

// RenderAgentConfig fills in the `agentConfigTmpl` from types.go
func RenderAgentConfig(addr, ca, roleFile, secretFile, tokenSink string, log *zap.Logger) error {
	data := struct {
		Addr, CACert, RoleFile, SecretFile, TokenSink string
	}{
		Addr:       addr,
		CACert:     ca,
		RoleFile:   roleFile,
		SecretFile: secretFile,
		TokenSink:  tokenSink,
	}

	tpl := template.Must(template.New("agent.hcl").Parse(agentConfigTmpl))
	f, err := os.Create(VaultAgentConfigPath)
	if err != nil {
		return fmt.Errorf("create %s: %w", VaultAgentConfigPath, err)
	}
	defer f.Close()

	if err := tpl.Execute(f, data); err != nil {
		return fmt.Errorf("execute template: %w", err)
	}
	if err := os.Chmod(VaultAgentConfigPath, 0o640); err != nil {
		log.Warn("chmod agent HCL", zap.Error(err))
	}
	return nil
}

// ------------------------ ENVIRONMENT ------------------------

// PrepareVaultAgentEnvironment ensures runtime dir exists and port 8179 is free.
func PrepareVaultAgentEnvironment(log *zap.Logger) error {
	log.Info("🧼 Preparing Vault Agent environment")

	if err := EnsureVaultDirs(log); err != nil {
		log.Error("Failed to prepare runtime dir", zap.Error(err))
		return err
	}

	if err := killVaultAgentPort(log); err != nil {
		log.Warn("Failed to kill Vault Agent port", zap.Error(err))
		return err
	}

	log.Info("✅ Vault Agent environment ready")
	return nil
}

// func ensureEosVaultProfile(log *zap.Logger) error {
// 	content := fmt.Sprintf("export VAULT_CACERT=%s\n", VaultAgentCACopyPath)
// 	log.Info("🔧 Writing EOS vault CA env‑profile", zap.String("path", EosProfileD))
// 	if err := os.WriteFile(EosProfileD, []byte(content), 0o644); err != nil {
// 	  return fmt.Errorf("writing %s: %w", EosProfileD, err)
// 	}
// 	// owned by root:root––that’s fine for /etc/profile.d
// 	if err := os.Chown(EosProfileD, 0, 0); err != nil {
// 	  log.Warn("could not chown profile.d file", zap.Error(err))
// 	}
// 	return nil
//   }

//
// ========================= SYSTEMD =========================
//
//

// WriteSystemdUnit writes out your `agentSystemDUnit` template from types.go.
func WriteSystemdUnit(log *zap.Logger) error {
	unit := fmt.Sprintf(agentSystemDUnit,
		// %s User,   VaultAgentUser
		// %s Group,  VaultAgentGroup
		// %o RuntimeDirectoryMode, xdg.VaultRuntimePerms
		// %s ExecStartPre owner, VaultAgentUser
		// %s ExecStartPre group, VaultAgentGroup
		// %o ExecStartPre mode,  xdg.VaultRuntimePerms
		// %s ExecStartPre path,  EosRunDir
		// %s ExecStart   config,  VaultAgentConfigPath
		VaultAgentUser,
		VaultAgentGroup,
		xdg.VaultRuntimePerms,
		VaultAgentUser,
		VaultAgentGroup,
		xdg.VaultRuntimePerms,
		EosRunDir,
		VaultAgentConfigPath,
	)

	log.Debug("✍️  Writing systemd unit", zap.String("path", VaultAgentServicePath))
	if err := os.WriteFile(VaultAgentServicePath,
		[]byte(strings.TrimSpace(unit)+"\n"),
		xdg.SystemdUnitFilePerms,
	); err != nil {
		return fmt.Errorf("write unit file: %w", err)
	}
	log.Info("✅ Systemd unit written", zap.String("path", VaultAgentServicePath))
	return nil
}

//
// ========================== DELETE ==========================
//

func killVaultAgentPort(log *zap.Logger) error {
	log.Info("🔍 Checking for processes using Vault Agent port", zap.String("port", VaultDefaultPort))

	out, err := exec.Command("lsof", "-i", ":"+VaultDefaultPort, "-t").Output()
	if err != nil {
		log.Info("✅ No process is using the Vault Agent port", zap.String("port", VaultDefaultPort))
		return nil
	}

	pids := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(pids) == 0 || (len(pids) == 1 && pids[0] == "") {
		log.Info("✅ Vault Agent port is already free", zap.String("port", VaultDefaultPort))
		return nil
	}

	log.Warn("⚠️ Killing processes using Vault Agent port", zap.Strings("pids", pids))
	for _, pid := range pids {
		if pid == "" {
			continue
		}
		log.Debug("🔪 Killing process", zap.String("pid", pid))
		if err := exec.Command("kill", "-9", pid).Run(); err != nil {
			log.Warn("❌ Failed to kill process", zap.String("pid", pid), zap.Error(err))
		} else {
			log.Info("✅ Killed process using port", zap.String("pid", pid), zap.String("port", VaultDefaultPort))
		}
	}

	return nil
}

//
// ========================== DEPRECATED ==========================
//

// func reloadAndStartService(log *zap.Logger) error {
// 	log.Info("🔄 Reloading systemd and starting Vault Agent service")

// 	cmds := [][]string{
// 		{"systemctl", "daemon-reexec"},
// 		{"systemctl", "daemon-reload"},
// 		{"systemctl", "enable", "--now", "vault-agent-eos.service"},
// 	}

// 	for _, args := range cmds {
// 		log.Debug("⚙️ Running systemctl command", zap.Strings("cmd", args))
// 		cmd := exec.Command(args[0], args[1:]...)
// 		output, err := cmd.CombinedOutput()
// 		if err != nil {
// 			log.Error("❌ Failed to run systemctl command",
// 				zap.Strings("cmd", args),
// 				zap.ByteString("output", output),
// 				zap.Error(err),
// 			)
// 			return err
// 		}
// 		log.Info("✅ systemctl command succeeded", zap.Strings("cmd", args))
// 	}

// 	// 🔁 Explicit restart just in case
// 	log.Debug("🔁 Restarting Vault Agent service")
// 	if err := exec.Command("systemctl", "restart", "vault-agent-eos.service").Run(); err != nil {
// 		log.Error("❌ Failed to restart Vault Agent", zap.Error(err))
// 		return err
// 	}

// 	log.Info("✅ Vault Agent service started successfully")
// 	return nil
// }

// func stepInstallVaultAgentSystemd(log *zap.Logger) error {
// 	// … your logic to render + write the .service file …

// 	// now reload & enable the unit:
// 	if err := system.ReloadDaemonAndEnable(log, VaultAgentService); err != nil {
// 		return fmt.Errorf("could not enable Vault Agent service: %w", err)
// 	}
// 	return nil
// }
