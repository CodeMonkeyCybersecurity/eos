/* pkg/vault/agent_lifecycle.go */

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

// setupVaultAgent configures the Vault Agent to run as the eos user.
func EnsureVaultAgent(client *api.Client, password string, log *zap.Logger) error {

	fmt.Println("🔧 Setting up Vault Agent to run as 'eos'...")

	if err := EnsureEosVaultUser(client, log); err != nil {
		log.Error("Failed to ensure eos vault user", zap.Error(err))
		return err
	}

	if err := writeAgentConfig(); err != nil {
		log.Error("Failed to write agent config", zap.Error(err))
		return err
	}
	if err := writeAgentPassword(password); err != nil {
		log.Error("Failed to write agent password", zap.Error(err))
		return err
	}

	if err := EnsureRuntimeDir(log); err != nil {
		log.Error("Failed to prepare runtime directory", zap.Error(err))
		return err
	}

	if err := EnsureAppRole(client, log); err != nil {
		log.Error("AppRole setup failed", zap.Error(err))
		return err
	}

	if err := writeSystemdUnit(); err != nil {
		log.Error("Failed to write systemd unit", zap.Error(err))
		return err
	}

	if err := PrepareVaultAgentEnvironment(log); err != nil {
		log.Error("Failed to vault agent environment", zap.Error(err))
		return err
	}

	if err := reloadAndStartService(log); err != nil {
		log.Error("Failed to reload/start service", zap.Error(err))
		return err
	}

	fmt.Println("✅ Vault Agent for eos is running and ready.")
	return nil
}

func WriteAppRoleCredentials(client *api.Client, log *zap.Logger) error {
	roleID, err := client.Logical().Read(rolePath + "/role-id")
	if err != nil {
		return fmt.Errorf("failed to read role_id: %w", err)
	}
	secretID, err := client.Logical().Write(rolePath+"/secret-id", nil)
	if err != nil {
		return fmt.Errorf("failed to generate secret_id: %w", err)
	}

	if err := os.WriteFile(AppRoleIDPath, []byte(roleID.Data["role_id"].(string)), 0400); err != nil {
		return err
	}
	if err := os.WriteFile(AppSecretIDPath, []byte(secretID.Data["secret_id"].(string)), 0400); err != nil {
		return err
	}
	return nil
}

func killVaultAgentPort() error {
	out, err := exec.Command("lsof", "-i", ":8179", "-t").Output()
	if err != nil {
		return nil // No process
	}

	pids := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, pid := range pids {
		if pid == "" {
			continue
		}
		_ = exec.Command("kill", "-9", pid).Run()
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

	if err := killVaultAgentPort(); err != nil {
		log.Warn("Failed to kill Vault Agent port", zap.Error(err))
		return err
	}

	log.Info("✅ Vault Agent environment ready")
	return nil
}

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

func EnsureVaultAgentRunning(log *zap.Logger) error {
	if err := EnsureAppRoleFiles(log); err != nil {
		return err
	}

	cmd := exec.Command("systemctl", "is-active", "--quiet", "vault-agent-eos.service")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("vault agent service is not active")
	}
	if _, err := os.Stat(VaultAgentTokenPath); err != nil {
		return fmt.Errorf("vault token sink is missing")
	}
	return nil
}

func EnsureAppRoleFiles(log *zap.Logger) error {
	paths := []string{"/etc/vault/role_id", "/etc/vault/secret_id"}
	for _, path := range paths {
		if _, err := os.Stat(path); err != nil {
			return fmt.Errorf("required AppRole file missing: %s", path)
		}
	}
	return nil
}

func reloadAndStartService(log *zap.Logger) error {
	log.Info("🔄 Reloading systemd and starting Vault Agent service...")

	cmds := [][]string{
		{"systemctl", "daemon-reexec"},
		{"systemctl", "daemon-reload"},
		{"systemctl", "enable", "--now", "vault-agent-eos.service"},
	}

	for _, args := range cmds {
		cmd := exec.Command(args[0], args[1:]...)
		_, err := cmd.CombinedOutput()
		if err != nil {
			log.Error("failed to run")
			return err
		}
	}

	// 🔁 Restart the service after setup and reload
	if err := exec.Command("systemctl", "restart", "vault-agent-eos.service").Run(); err != nil {
		log.Error("failed to restart Vault Agent")
		return err
	}

	log.Info("✅ Vault Agent service started")
	return nil
}

func EnsureAppRole(client *api.Client, log *zap.Logger) error {
	// Fast-exit if creds already on disk
	if _, err := os.Stat(AppRoleIDPath); err == nil {
		log.Info("🔐 AppRole credentials already present — skipping creation")
		return nil
	}

	log.Info("Creating AppRole 'eos'...")

	// Enable auth method (idempotent)
	if err := client.Sys().EnableAuthWithOptions("approle", &api.EnableAuthOptions{Type: "approle"}); err != nil {
		log.Warn("Auth method approle may already be enabled", zap.Error(err))
	}

	// Create or update the AppRole
	_, err := client.Logical().Write(rolePath, map[string]interface{}{
		"policies":      []string{EosVaultPolicy},
		"token_ttl":     "60m",
		"token_max_ttl": "120m",
	})
	if err != nil {
		return fmt.Errorf("failed to create AppRole %q: %w", rolePath, err)
	}

	// Generate and write credentials
	roleID, err := client.Logical().Read(rolePath + "/role-id")
	if err != nil {
		return fmt.Errorf("failed to read role_id: %w", err)
	}
	secretID, err := client.Logical().Write(rolePath+"/secret-id", nil)
	if err != nil {
		return fmt.Errorf("failed to generate secret_id: %w", err)
	}

	if err := os.WriteFile(AppRoleIDPath, []byte(roleID.Data["role_id"].(string)+"\n"), 0640); err != nil {
		return fmt.Errorf("failed to write role_id: %w", err)
	}
	if err := os.WriteFile(AppSecretIDPath, []byte(secretID.Data["secret_id"].(string)+"\n"), 0640); err != nil {
		return fmt.Errorf("failed to write secret_id: %w", err)
	}

	log.Info("✅ AppRole created and credentials written", zap.String("role_id_path", AppRoleIDPath), zap.String("secret_id_path", AppSecretIDPath))
	return nil
}
