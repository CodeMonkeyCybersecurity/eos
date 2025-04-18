// pkg/vault/lifecycle_agent.go

package vault

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

//
// ========================== ENSURE ==========================
//

// EnsureAgent configures and launches the Vault Agent under the eos user context.
func EnsureAgent(client *api.Client, password string, log *zap.Logger, opts AppRoleOptions) error {
	log.Info("🔧 Starting Vault Agent setup for user 'eos'")

	// Step 1: Ensure eos Vault user exists in Vault
	log.Info("🔐 Ensuring Vault user 'eos' exists...")
	if err := EnsureEosVaultUser(client, log); err != nil {
		log.Error("❌ Failed to ensure eos Vault user", zap.Error(err))
		return err
	}
	log.Info("✅ Vault user 'eos' is configured")

	// Step 2: Write Vault Agent config file
	addr := getVaultAddr()
	log.Info("📝 Writing Vault Agent configuration", zap.String("vault_addr", addr))
	if err := EnsureAgentConfig(addr, log); err != nil {
		log.Error("❌ Failed to write Vault Agent config", zap.String("vault_addr", addr), zap.Error(err))
		return err
	}
	log.Info("✅ Vault Agent configuration written")

	// Step 3: Write Vault Agent password to disk
	log.Info("🔑 Writing Vault Agent password to disk...")
	if err := writeAgentPassword(password, log); err != nil {
		log.Error("❌ Failed to write agent password", zap.Error(err))
		return err
	}
	log.Info("✅ Vault Agent password file created")

	// Step 4: Ensure /run/eos exists and owned correctly
	log.Info("📁 Ensuring /run/eos runtime directory is ready...")
	if err := EnsureRuntimeDir(log); err != nil {
		log.Error("❌ Failed to prepare /run/eos directory", zap.Error(err))
		return err
	}
	log.Info("✅ Runtime directory ready")

	// Step 5: Create or refresh AppRole credentials
	log.Info("🔐 Ensuring Vault AppRole is created and credentialed...")
	if err := EnsureAppRole(client, log, DefaultAppRoleOptions()); err != nil {
		log.Error("❌ AppRole setup failed", zap.Error(err))
		return err
	}
	log.Info("✅ AppRole created and credentials written")

	// Step 6: Write systemd unit
	log.Info("⚙️ Writing systemd service unit for Vault Agent...")
	if err := EnsureSystemdUnit(log); err != nil {
		log.Error("❌ Failed to write systemd unit", zap.Error(err))
		return err
	}
	log.Info("✅ Systemd unit for Vault Agent written")

	// Step 7: Clean environment (port kill etc)
	log.Info("🧼 Preparing environment for Vault Agent launch...")
	if err := PrepareVaultAgentEnvironment(log); err != nil {
		log.Error("❌ Failed to prepare Vault Agent environment", zap.Error(err))
		return err
	}
	log.Info("✅ Environment preparation complete")

	// Step 8: Start Vault Agent systemd service
	log.Info("🚀 Starting Vault Agent systemd service...")
	if err := reloadAndStartService(log); err != nil {
		log.Error("❌ Failed to start Vault Agent systemd service", zap.Error(err))
		return err
	}
	log.Info("✅ Vault Agent service started and running")

	fmt.Println("✅ Vault Agent for eos is running and ready.")
	return nil
}

// --- Helper Functions ---

func writeAgentPassword(password string, log *zap.Logger) error {
	const passPath = "/etc/vault-agent-eos.pass"
	log.Debug("🔏 Writing Vault Agent password to file", zap.String("path", passPath))

	if err := os.WriteFile(passPath, []byte(password+"\n"), 0600); err != nil {
		log.Error("❌ Failed to write password file", zap.String("path", passPath), zap.Error(err))
		return fmt.Errorf("failed to write Vault Agent password to %s: %w", passPath, err)
	}

	log.Info("✅ Vault Agent password file written", zap.String("path", passPath))
	return nil
}

// ------------------------ ENVIRONMENT ------------------------

func EnsureRuntimeDir(log *zap.Logger) error {
	const dir = "/run/eos"

	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("failed to create runtime dir: %w", err)
	}

	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("failed to stat %s: %w", dir, err)
	}

	uid, gid, err := system.LookupUser("eos")
	if err != nil {
		return fmt.Errorf("failed to lookup eos user: %w", err)
	}

	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		if int(stat.Uid) != uid || int(stat.Gid) != gid {
			if err := os.Chown(dir, uid, gid); err != nil {
				return fmt.Errorf("failed to chown %s to eos:eos: %w", dir, err)
			}
			log.Info("🔧 Updated ownership of runtime dir", zap.String("path", dir))
		}
	}

	return nil
}

// PrepareVaultAgentEnvironment ensures /run/eos exists and port 8179 is free.
func PrepareVaultAgentEnvironment(log *zap.Logger) error {
	log.Info("🧼 Preparing Vault Agent environment")

	if err := EnsureRuntimeDir(log); err != nil {
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

// ------------------------ APP ROLE ------------------------

func EnsureAppRole(client *api.Client, log *zap.Logger, opts AppRoleOptions) error {
	if !opts.ForceRecreate {
		if _, err := os.Stat(AppRoleIDPath); err == nil {
			log.Info("🔐 AppRole credentials already present — skipping creation",
				zap.String("role_id_path", AppRoleIDPath),
				zap.Bool("refresh", opts.RefreshCreds),
			)
			if opts.RefreshCreds {
				log.Info("🔄 Refreshing AppRole credentials...")
				return refreshAppRoleCreds(client, log)
			}
			return nil
		}
	}

	log.Info("🛠️ Creating or updating Vault AppRole",
		zap.String("role_path", rolePath),
		zap.Strings("policies", []string{EosVaultPolicy}),
	)

	// Enable auth method
	log.Debug("📡 Enabling AppRole auth method if needed...")
	if err := client.Sys().EnableAuthWithOptions("approle", &api.EnableAuthOptions{Type: "approle"}); err != nil {
		log.Warn("⚠️ AppRole auth method may already be enabled", zap.Error(err))
	}

	// Write role config
	log.Debug("📦 Writing AppRole definition to Vault...")
	if _, err := client.Logical().Write(rolePath, map[string]interface{}{
		"policies":      []string{EosVaultPolicy},
		"token_ttl":     "60m",
		"token_max_ttl": "120m",
	}); err != nil {
		log.Error("❌ Failed to write AppRole definition", zap.String("path", rolePath), zap.Error(err))
		return fmt.Errorf("failed to create AppRole %q: %w", rolePath, err)
	}

	log.Info("✅ AppRole written to Vault", zap.String("role_path", rolePath))
	return refreshAppRoleCreds(client, log)
}

func refreshAppRoleCreds(client *api.Client, log *zap.Logger) error {
	log.Debug("🔑 Requesting AppRole credentials from Vault...")

	roleID, err := client.Logical().Read(rolePath + "/role-id")
	if err != nil {
		log.Error("❌ Failed to read AppRole role_id", zap.String("path", rolePath+"/role-id"), zap.Error(err))
		return fmt.Errorf("failed to read role_id: %w", err)
	}

	secretID, err := client.Logical().Write(rolePath+"/secret-id", nil)
	if err != nil {
		log.Error("❌ Failed to generate AppRole secret_id", zap.String("path", rolePath+"/secret-id"), zap.Error(err))
		return fmt.Errorf("failed to generate secret_id: %w", err)
	}

	// Extract safely with type assertion guard
	rawRoleID, ok := roleID.Data["role_id"].(string)
	if !ok {
		log.Error("❌ Invalid or missing role_id in Vault response", zap.Any("data", roleID.Data))
		return fmt.Errorf("unexpected Vault response format for role_id")
	}

	rawSecretID, ok := secretID.Data["secret_id"].(string)
	if !ok {
		log.Error("❌ Invalid or missing secret_id in Vault response", zap.Any("data", secretID.Data))
		return fmt.Errorf("unexpected Vault response format for secret_id")
	}

	// Write to disk
	log.Debug("💾 Writing AppRole credentials to disk...")
	if err := os.WriteFile(AppRoleIDPath, []byte(rawRoleID+"\n"), 0640); err != nil {
		log.Error("❌ Failed to write role_id to disk", zap.String("path", AppRoleIDPath), zap.Error(err))
		return fmt.Errorf("failed to write role_id: %w", err)
	}
	if err := os.WriteFile(AppSecretIDPath, []byte(rawSecretID+"\n"), 0640); err != nil {
		log.Error("❌ Failed to write secret_id to disk", zap.String("path", AppSecretIDPath), zap.Error(err))
		return fmt.Errorf("failed to write secret_id: %w", err)
	}

	log.Info("✅ AppRole credentials written to disk",
		zap.String("role_id_path", AppRoleIDPath),
		zap.String("secret_id_path", AppSecretIDPath),
	)
	return nil
}

// ------------------------ SYSTEMD ------------------------

func EnsureSystemdUnit(log *zap.Logger) error {
	unit := `
[Unit]
Description=Vault Agent (Eos)
After=network.target

[Service]
ExecStartPre=/usr/bin/mkdir -p /run/eos
ExecStartPre=/usr/bin/chown eos:eos /run/eos
User=eos
Group=eos
ExecStart=/usr/bin/vault agent -config=/etc/vault-agent-eos.hcl
Restart=on-failure
RuntimeDirectory=eos
RuntimeDirectoryMode=0750

[Install]
WantedBy=multi-user.target`
	unitPath := "/etc/systemd/system/vault-agent-eos.service"
	if err := os.WriteFile(unitPath, []byte(strings.TrimSpace(unit)+"\n"), 0644); err != nil {
		log.Error("Failed to write Vault Agent systemd unit file",
			zap.String("path", unitPath),
			zap.Error(err),
		)
		return err
	}
	log.Info("✅ Systemd unit file written", zap.String("path", unitPath))
	return nil
}

//
// ========================== LIST ==========================
//

//
// ========================== READ ==========================
//

//
// ========================== UPDATE ==========================
//

//
// ========================== DELETE ==========================
//

func killVaultAgentPort(log *zap.Logger) error {
	const port = "8179"
	log.Info("🔍 Checking for processes using Vault Agent port", zap.String("port", port))

	out, err := exec.Command("lsof", "-i", ":"+port, "-t").Output()
	if err != nil {
		log.Info("✅ No process is using the Vault Agent port", zap.String("port", port))
		return nil
	}

	pids := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(pids) == 0 || (len(pids) == 1 && pids[0] == "") {
		log.Info("✅ Vault Agent port is already free", zap.String("port", port))
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
			log.Info("✅ Killed process using port", zap.String("pid", pid), zap.String("port", port))
		}
	}

	return nil
}
func reloadAndStartService(log *zap.Logger) error {
	log.Info("🔄 Reloading systemd and starting Vault Agent service")

	cmds := [][]string{
		{"systemctl", "daemon-reexec"},
		{"systemctl", "daemon-reload"},
		{"systemctl", "enable", "--now", "vault-agent-eos.service"},
	}

	for _, args := range cmds {
		log.Debug("⚙️ Running systemctl command", zap.Strings("cmd", args))
		cmd := exec.Command(args[0], args[1:]...)
		output, err := cmd.CombinedOutput()
		if err != nil {
			log.Error("❌ Failed to run systemctl command",
				zap.Strings("cmd", args),
				zap.ByteString("output", output),
				zap.Error(err),
			)
			return err
		}
		log.Info("✅ systemctl command succeeded", zap.Strings("cmd", args))
	}

	// 🔁 Explicit restart just in case
	log.Debug("🔁 Restarting Vault Agent service")
	if err := exec.Command("systemctl", "restart", "vault-agent-eos.service").Run(); err != nil {
		log.Error("❌ Failed to restart Vault Agent", zap.Error(err))
		return err
	}

	log.Info("✅ Vault Agent service started successfully")
	return nil
}
