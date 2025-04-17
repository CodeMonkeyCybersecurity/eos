/* pkg/vault/agent_config.go */

package vault

import (
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/vault/api"

	"go.uber.org/zap"
)

func writeSystemdUnit() error {
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
		return fmt.Errorf("failed to write systemd unit file to %s: %w", unitPath, err)
	}
	fmt.Printf("✅ Systemd unit file written to %s\n", unitPath)
	return nil
}

func EnsureAgentConfig(vaultAddr string, log *zap.Logger) error {
	const configPath = "/etc/vault-agent-eos.hcl"

	// ✅ Check for existing config first
	if _, err := os.Stat(configPath); err == nil {
		log.Info("✅ Vault Agent config already exists — skipping rewrite", zap.String("path", configPath))
		return nil
	}

	// ✅ Check AppRole files exist
	if _, err := os.Stat("/etc/vault/role_id"); err != nil {
		return fmt.Errorf("role_id not found: %w", err)
	}
	if _, err := os.Stat("/etc/vault/secret_id"); err != nil {
		return fmt.Errorf("secret_id not found: %w", err)
	}

	log.Info("✍️ Writing Vault Agent config file", zap.String("path", configPath))

	// Use dynamic Vault address and listener
	content := fmt.Sprintf(`
pid_file = "/run/eos/vault-agent.pid"

auto_auth {
  method "approle" {
    config = {
      role_id_file_path   = "/etc/vault/role_id"
      secret_id_file_path = "/etc/vault/secret_id"
    }
  }
  sink "file" {
    config = {
      path = "/run/eos/vault-agent-eos.token"
    }
  }
}

vault {
  address = "%s"
}

listener "tcp" {
  address     = "127.0.0.1:8179"
  tls_disable = true
}

cache {
  use_auto_auth_token = true
}`, vaultAddr)

	if err := os.WriteFile(configPath, []byte(strings.TrimSpace(content)+"\n"), 0644); err != nil {
		return fmt.Errorf("failed to write Vault Agent config to %s: %w", configPath, err)
	}

	log.Info("✅ Vault Agent config written successfully", zap.String("path", configPath))
	return nil
}

// --- Helper Functions ---

func writeAgentPassword(password string) error {
	passPath := "/etc/vault-agent-eos.pass"
	if err := os.WriteFile(passPath, []byte(password+"\n"), 0600); err != nil {
		return fmt.Errorf("failed to write Vault Agent password to %s: %w", passPath, err)
	}
	fmt.Printf("✅ Vault Agent password file written to %s\n", passPath)
	return nil
}

// ApplyAdminPolicy applies a full-access policy from the Policies map to the eos user.
func ApplyAdminPolicy(creds UserpassCreds, client *api.Client, log *zap.Logger) error {
	fmt.Println("Creating full-access policy for eos.")

	policyName := EosVaultPolicy
	policy, ok := Policies[policyName]
	if !ok {
		return fmt.Errorf("policy %q not found in Policies map", policyName)
	}

	// Apply policy using the Vault API.
	if err := client.Sys().PutPolicy(policyName, policy); err != nil {
		log.Error("Failed to apply policy via API", zap.Error(err))
		return err
	}
	log.Info("✅ Custom policy applied via API", zap.String("policy", policyName))

	// Update the eos user with the policy.
	_, err := client.Logical().Write("auth/userpass/users/eos", map[string]interface{}{
		"password": creds.Password,
		"policies": policyName,
	})
	if err != nil {
		log.Error("Failed to update eos user with policy", zap.Error(err))
		return err
	}
	log.Info("✅ eos user updated with full privileges", zap.String("policy", policyName))
	return nil
}
