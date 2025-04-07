// pkg/vault/agent.go

package vault

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func SetupVaultAgentService(password string) error {
	fmt.Println("🔧 Setting up Vault Agent to run as 'eos'...")

	// 1. Vault Agent Config
	agentConfig := `/etc/vault-agent-eos.hcl`
	agentConfigContent := `
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
}
`
	if err := os.WriteFile(agentConfig, []byte(strings.TrimSpace(agentConfigContent)+"\n"), 0644); err != nil {
		return fmt.Errorf("failed to write Vault Agent config: %w", err)
	}

	// 2. Password File
	passFile := "/etc/vault-agent-eos.pass"
	if err := os.WriteFile(passFile, []byte(password+"\n"), 0600); err != nil {
		return fmt.Errorf("failed to write Vault password file: %w", err)
	}

	// 3. Systemd Unit
	unitFile := `/etc/systemd/system/vault-agent-eos.service`
	unitContent := `
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
WantedBy=multi-user.target
`
	if err := os.WriteFile(unitFile, []byte(strings.TrimSpace(unitContent)+"\n"), 0644); err != nil {
		return fmt.Errorf("failed to write systemd unit file: %w", err)
	}

	// 4. Ensure runtime dir
	if err := os.MkdirAll("/run/eos", 0750); err != nil {
		return fmt.Errorf("failed to create /run/eos: %w", err)
	}
	if err := os.Chown("/run/eos", 0, 0); err != nil {
		return fmt.Errorf("failed to chown /run/eos: %w", err)
	}

	// 5. Reload systemd and start agent
	fmt.Println("🔄 Reloading systemd and starting Vault Agent service...")
	if err := exec.Command("systemctl", "daemon-reexec").Run(); err != nil {
		return fmt.Errorf("failed to daemon-reexec: %w", err)
	}
	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		return fmt.Errorf("failed to daemon-reload: %w", err)
	}
	if err := exec.Command("systemctl", "enable", "--now", "vault-agent-eos.service").Run(); err != nil {
		return fmt.Errorf("failed to enable/start Vault Agent service: %w", err)
	}

	fmt.Println("✅ Vault Agent for eos is running and ready.")
	return nil
}
