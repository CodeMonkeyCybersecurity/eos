/* pkg/vault/agent.go */

package vault

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

// setupVaultAgent configures the Vault Agent to run as the eos user.
func setupVaultAgent(password string) error {
	fmt.Println("🔧 Setting up Vault Agent to run as 'eos'...")

	if err := writeAgentConfig(); err != nil {
		zap.L().Error("Failed to write agent config", zap.Error(err))
		return err
	}
	if err := writeAgentPassword(password); err != nil {
		zap.L().Error("Failed to write agent password", zap.Error(err))
		return err
	}
	if err := writeSystemdUnit(); err != nil {
		zap.L().Error("Failed to write systemd unit", zap.Error(err))
		return err
	}
	if err := prepareRuntimeDir(); err != nil {
		zap.L().Error("Failed to prepare runtime directory", zap.Error(err))
		return err
	}
	if err := reloadAndStartService(); err != nil {
		zap.L().Error("Failed to reload/start service", zap.Error(err))
		return err
	}

	fmt.Println("✅ Vault Agent for eos is running and ready.")
	return nil
}

// --- Helper Functions ---

func writeAgentConfig() error {
	content := `
pid_file = "/run/eos/vault-agent.pid"
auto_auth {
  method "userpass" {
    mount_path = "auth/userpass"
    config = {
      username = "eos"
      password_file = "/etc/vault-agent-eos.pass"
    }
  }
  sink "file" {
    config = {
      path = "/run/eos/.vault-token"
    }
  }
}
vault {
  address = "http://127.0.0.1:8179"
}
cache {
  use_auto_auth_token = true
}`
	configPath := "/etc/vault-agent-eos.hcl"
	if err := os.WriteFile(configPath, []byte(strings.TrimSpace(content)+"\n"), 0644); err != nil {
		return fmt.Errorf("failed to write Vault Agent config to %s: %w", configPath, err)
	}
	fmt.Printf("✅ Vault Agent config written to %s\n", configPath)
	return nil
}

func writeAgentPassword(password string) error {
	passPath := "/etc/vault-agent-eos.pass"
	if err := os.WriteFile(passPath, []byte(password+"\n"), 0600); err != nil {
		return fmt.Errorf("failed to write Vault Agent password to %s: %w", passPath, err)
	}
	fmt.Printf("✅ Vault Agent password file written to %s\n", passPath)
	return nil
}

func writeSystemdUnit() error {
	unit := `
[Unit]
Description=Vault Agent (EOS)
After=network.target

[Service]
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
		return fmt.Errorf("failed to write systemd unit file to %s: %w", unitPath, err)
	}
	fmt.Printf("✅ Systemd unit file written to %s\n", unitPath)
	return nil
}

func prepareRuntimeDir() error {
	dir := "/run/eos"
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("failed to create %s: %w", dir, err)
	}
	if err := os.Chown(dir, 0, 0); err != nil {
		return fmt.Errorf("failed to change ownership of %s: %w", dir, err)
	}
	return nil
}

func reloadAndStartService() error {
	fmt.Println("🔄 Reloading systemd and starting Vault Agent service...")
	cmds := [][]string{
		{"systemctl", "daemon-reexec"},
		{"systemctl", "daemon-reload"},
		{"systemctl", "enable", "--now", "vault-agent-eos.service"},
	}
	for _, args := range cmds {
		cmd := exec.Command(args[0], args[1:]...)
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to run %v: %w, output: %s", args, err, string(output))
		}
	}
	return nil
}

// ApplyAdminPolicy applies a full-access policy from the Policies map to the eos user.
func ApplyAdminPolicy(creds UserpassCreds, client *api.Client) error {
	fmt.Println("Creating full-access policy for eos.")

	policyName := EosVaultPolicy
	policy, ok := Policies[policyName]
	if !ok {
		return fmt.Errorf("policy %q not found in Policies map", policyName)
	}

	// Apply policy using the Vault API.
	if err := client.Sys().PutPolicy(policyName, policy); err != nil {
		zap.L().Error("Failed to apply policy via API", zap.Error(err))
		return err
	}
	zap.L().Info("✅ Custom policy applied via API", zap.String("policy", policyName))

	// Update the eos user with the policy.
	_, err := client.Logical().Write("auth/userpass/users/eos", map[string]interface{}{
		"password": creds.Password,
		"policies": policyName,
	})
	if err != nil {
		zap.L().Error("Failed to update eos user with policy", zap.Error(err))
		return err
	}
	zap.L().Info("✅ eos user updated with full privileges", zap.String("policy", policyName))
	return nil
}
