package vault

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func setupVaultAgent(password string) error {
	fmt.Println("🔧 Setting up Vault Agent to run as 'eos'...")

	if err := writeAgentConfig(); err != nil {
		return err
	}
	if err := writeAgentPassword(password); err != nil {
		return err
	}
	if err := writeSystemdUnit(); err != nil {
		return err
	}
	if err := prepareRuntimeDir(); err != nil {
		return err
	}
	if err := reloadAndStartService(); err != nil {
		return err
	}

	fmt.Println("✅ Vault Agent for eos is running and ready.")
	return nil
}

// --- Helpers ---

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
	return os.WriteFile("/etc/vault-agent-eos.hcl", []byte(strings.TrimSpace(content)+"\n"), 0644)
}

func writeAgentPassword(password string) error {
	return os.WriteFile("/etc/vault-agent-eos.pass", []byte(password+"\n"), 0600)
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
	return os.WriteFile("/etc/systemd/system/vault-agent-eos.service", []byte(strings.TrimSpace(unit)+"\n"), 0644)
}

func prepareRuntimeDir() error {
	if err := os.MkdirAll("/run/eos", 0750); err != nil {
		return fmt.Errorf("create /run/eos: %w", err)
	}
	return os.Chown("/run/eos", 0, 0)
}

func reloadAndStartService() error {
	fmt.Println("🔄 Reloading systemd and starting Vault Agent service...")
	cmds := [][]string{
		{"systemctl", "daemon-reexec"},
		{"systemctl", "daemon-reload"},
		{"systemctl", "enable", "--now", "vault-agent-eos.service"},
	}
	for _, args := range cmds {
		if err := exec.Command(args[0], args[1:]...).Run(); err != nil {
			return fmt.Errorf("failed to run %v: %w", args, err)
		}
	}
	return nil
}
