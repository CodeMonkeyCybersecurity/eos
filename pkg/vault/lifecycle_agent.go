// pkg/vault/lifecycle_agent.go

package vault

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
// EnsureAgent configures & launches the Vault Agent under the eos system‑user.
// `password` is only used by the userpass method; for AppRole you can pass ""
// and `opts` comes from DefaultAppRoleOptions().
func EnsureAgent(client *api.Client, password string, log *zap.Logger, opts AppRoleOptions) error {
	log.Info("🔧 Starting Vault Agent setup for user 'eos'",
		zap.Bool("userpass", password != ""),
		zap.Bool("force_recreate", opts.ForceRecreate),
		zap.Bool("refresh_creds", opts.RefreshCreds),
	)

	// Step 1: Provision AppRole
	log.Info("🔐 Provisioning AppRole credentials",
		zap.String("role_id_path", RoleIDPath),
		zap.String("secret_id_path", SecretIDPath),
	)
	roleID, secretID, err := EnsureAppRole(client, log, opts)
	if err != nil {
		log.Error("❌ Failed to ensure AppRole", zap.Error(err))
		return fmt.Errorf("ensure approle: %w", err)
	}
	log.Info("✅ AppRole credentials provisioned")

	// Step 2: Render Vault Agent HCL
	addr := os.Getenv("VAULT_ADDR")
	if addr == "" {
		log.Warn("⚠️ VAULT_ADDR is empty — expected it to be set before agent setup")
	}
	log.Info("📝 Rendering Vault Agent HCL",
		zap.String("VAULT_ADDR", addr),
		zap.String("agent_config_path", VaultAgentConfigPath),
	)
	if err := RenderAgentConfig(addr, roleID, secretID, log); err != nil {
		log.Error("❌ Failed to render Vault Agent config", zap.Error(err))
		return fmt.Errorf("render agent config: %w", err)
	}
	log.Info("✅ Vault Agent config rendered")

	// Step 3: Write optional userpass password (if provided)
	if password != "" {
		log.Info("🔑 Writing Vault Agent userpass password",
			zap.String("path", VaultAgentPassPath),
		)
		if err := writeAgentPassword(password, log); err != nil {
			log.Error("❌ Failed to write agent password", zap.Error(err))
			return fmt.Errorf("write agent password: %w", err)
		}
		log.Info("✅ Agent password file written")
	}

	// Step 4: Write systemd unit
	log.Info("⚙️ Writing systemd unit for Vault Agent", zap.String("unit_path", VaultAgentServicePath))
	if err := WriteSystemdUnit(log); err != nil {
		log.Error("❌ Failed to write systemd unit", zap.Error(err))
		return fmt.Errorf("write systemd unit: %w", err)
	}
	log.Info("✅ Vault Agent systemd unit written")

	// Step 5: Enable & start agent service
	log.Info("🚀 Enabling and starting Vault Agent systemd service")
	if err := system.ReloadDaemonAndEnable(log, VaultAgentService); err != nil {
		log.Error("❌ Failed to enable/start Vault Agent service", zap.Error(err))
		return fmt.Errorf("enable agent service: %w", err)
	}

	log.Info("✅ Vault Agent is now running as systemd service", zap.String("service", VaultAgentService))
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

func RenderAgentConfig(addr, roleID, secretID string, log *zap.Logger) error {
	log.Info("🧩 Rendering Vault Agent HCL template",
		zap.String("VAULT_ADDR", addr),
		zap.String("role_id_path", RoleIDPath),
		zap.String("secret_id_path", SecretIDPath),
		zap.String("config_path", VaultAgentConfigPath),
	)

	// Ensure secrets directory exists
	if err := os.MkdirAll(filepath.Dir(RoleIDPath), xdg.FilePermOwnerRWX); err != nil {
		log.Error("❌ Failed to create secrets directory", zap.String("dir", filepath.Dir(RoleIDPath)), zap.Error(err))
		return err
	}
	log.Info("✅ Ensured secrets directory exists", zap.String("dir", filepath.Dir(RoleIDPath)))

	// Ensure role_id exists or re-write it
	if _, err := os.Stat(RoleIDPath); os.IsNotExist(err) {
		log.Warn("🔧 role_id file missing — re-creating", zap.String("path", RoleIDPath))
		if err := os.WriteFile(RoleIDPath, []byte(roleID), xdg.OwnerReadOnly); err != nil {
			log.Error("❌ Failed to write role_id", zap.String("path", RoleIDPath), zap.Error(err))
			return err
		}
		log.Info("✅ Wrote role_id", zap.String("path", RoleIDPath), zap.String("perm", "0400"))
	} else {
		log.Info("📄 role_id file already exists", zap.String("path", RoleIDPath))
	}

	// Ensure secret_id exists or re-write it
	if _, err := os.Stat(SecretIDPath); os.IsNotExist(err) {
		log.Warn("🔧 secret_id file missing — re-creating", zap.String("path", SecretIDPath))
		if err := os.WriteFile(SecretIDPath, []byte(secretID), xdg.OwnerReadOnly); err != nil {
			log.Error("❌ Failed to write secret_id", zap.String("path", SecretIDPath), zap.Error(err))
			return err
		}
		log.Info("✅ Wrote secret_id", zap.String("path", SecretIDPath), zap.String("perm", "0400"))
	} else {
		log.Info("📄 secret_id file already exists", zap.String("path", SecretIDPath))
	}

	// Build template data
	data := struct {
		Addr, CACert, RoleFile, SecretFile, TokenSink string
	}{
		Addr:       addr,
		CACert:     VaultAgentCACopyPath,
		RoleFile:   RoleIDPath,
		SecretFile: SecretIDPath,
		TokenSink:  VaultAgentTokenPath,
	}

	// Write HCL config to disk
	log.Info("📄 Writing Vault Agent config file", zap.String("path", VaultAgentConfigPath))
	tpl := template.Must(template.New("agent.hcl").Parse(AgentConfigTmpl))
	f, err := os.Create(VaultAgentConfigPath)
	if err != nil {
		log.Error("❌ Failed to create Vault Agent config file", zap.String("path", VaultAgentConfigPath), zap.Error(err))
		return fmt.Errorf("create %s: %w", VaultAgentConfigPath, err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			log.Warn("⚠️ Failed to close Vault Agent config file", zap.String("path", VaultAgentConfigPath), zap.Error(cerr))
		}
	}()

	if err := tpl.Execute(f, data); err != nil {
		log.Error("❌ Failed to render Vault Agent template", zap.Error(err))
		return fmt.Errorf("execute template: %w", err)
	}

	if err := os.Chmod(VaultAgentConfigPath, xdg.FilePermStandard); err != nil {
		log.Warn("⚠️ Failed to set permissions on Vault Agent config", zap.String("path", VaultAgentConfigPath), zap.Error(err))
	} else {
		log.Info("✅ Set permissions on Vault Agent config", zap.String("perm", fmt.Sprintf("%#o", xdg.FilePermStandard)))
	}

	log.Info("✅ Vault Agent HCL successfully rendered", zap.String("output", VaultAgentConfigPath))
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
		xdg.FilePermStandard,
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
