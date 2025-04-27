// pkg/vault/lifecycle_agent.go

package vault

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

/**/
func EnsureAgent(client *api.Client, password string, log *zap.Logger, opts shared.AppRoleOptions) error {
	// ─────────── REMINDERS WITH AGENT SETUP ───────────
	// if err := stepWriteAgentConfig(log); …
	//if err := stepInstallVaultAgentSystemd(log); err != nil { ... }        // step 5 cont.
	//if err := stepWaitForAgentToken(log); err != nil { ... }

	log.Info("🔧 Starting Vault Agent setup for user 'eos'",
		zap.Bool("userpass", password != ""),
		zap.Bool("force_recreate", opts.ForceRecreate),
		zap.Bool("refresh_creds", opts.RefreshCreds),
	)

	// Step 1: Provision AppRole
	log.Info("🔐 Provisioning AppRole credentials",
		zap.String("role_id_path", shared.RoleIDPath),
		zap.String("secret_id_path", shared.SecretIDPath),
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
		zap.String("agent_config_path", shared.VaultAgentConfigPath),
	)
	if err := RenderAgentConfig(addr, roleID, secretID, log); err != nil {
		log.Error("❌ Failed to render Vault Agent config", zap.Error(err))
		return fmt.Errorf("render agent config: %w", err)
	}
	log.Info("✅ Vault Agent config rendered")

	// Step 3: Write optional userpass password (if provided)
	if password != "" {
		log.Info("🔑 Writing Vault Agent userpass password",
			zap.String("path", shared.VaultAgentPassPath),
		)
		if err := writeAgentPassword(password, log); err != nil {
			log.Error("❌ Failed to write agent password", zap.Error(err))
			return fmt.Errorf("write agent password: %w", err)
		}
		log.Info("✅ Agent password file written")
	}

	// Step 4: Write systemd unit
	log.Info("⚙️ Writing systemd unit for Vault Agent", zap.String("unit_path", shared.VaultAgentServicePath))
	if err := WriteAgentSystemdUnit(log); err != nil {
		log.Error("❌ Failed to write systemd unit", zap.Error(err))
		return fmt.Errorf("write systemd unit: %w", err)
	}
	log.Info("✅ Vault Agent systemd unit written")

	// Step 5: Enable & start agent service
	log.Info("🚀 Enabling and starting Vault Agent systemd service")
	if err := system.ReloadDaemonAndEnable(log, shared.VaultAgentService); err != nil {
		log.Error("❌ Failed to enable/start Vault Agent service", zap.Error(err))
		return fmt.Errorf("enable agent service: %w", err)
	}

	log.Info("✅ Vault Agent is now running as systemd service", zap.String("service", shared.VaultAgentService))
	return nil
}

/**/

/**/

/**/

/**/
// NewClient returns a Vault client that
// trusts /opt/vault/tls/tls.crt unless the user already provided a CA.

/**/
func writeAgentPassword(password string, log *zap.Logger) error {
	log.Debug("🔏 Writing Vault Agent password to file", zap.String("path", shared.VaultAgentPassPath))

	if err := os.WriteFile(shared.VaultAgentPassPath, []byte(password+"\n"), 0600); err != nil {
		log.Error("❌ Failed to write password file", zap.String("path", shared.VaultAgentPassPath), zap.Error(err))
		return fmt.Errorf("failed to write Vault Agent password to %s: %w", shared.VaultAgentPassPath, err)
	}

	log.Info("✅ Vault Agent password file written", zap.String("path", shared.VaultAgentPassPath))
	return nil
}

/**/

/**/
// TODO
//  writes out your `agentSystemDUnit` template from types.go.
// -> InstallSystemdUnit(name string, content []byte) error
// ### Decision: Systemd Services for Vault and Vault Agent
// - **Always install** both `vault.service` and `vault-agent-eos.service` systemd units.
// - **Enable and start immediately** to ensure a seamless, minimal-friction install experience.
//   - Removes ambiguity around install vs runtime status.
// - **Run both services as the `eos` system user**:
//   - Ensures all privileged EOS-managed processes run through a consistent, auditable identity.
//   - Simplifies security hardening by centralizing control under one trusted user.
//   - All escalated privileges will be gated through `sudo -u eos`.
// - **vault-agent-eos.service should be included by default**.
//   - Vault Agent is essential to EOS’s secrets flow: it logs in via AppRole and provides sink token access to the CLI.
//   - Including it aligns with the goal of making secrets access secure and invisible.
// - `vault-agent-eos.service` should use `After=vault.service` and `Requires=vault.service`
// - This ensures the Vault service is active before the agent attempts to fetch a token.
// ---
/**/

/**/

/**/

/**/
// GetPrivilegedVaultClient returns a Vault client authenticated as 'eos' system user
func GetPrivilegedVaultClient(log *zap.Logger) (*api.Client, error) {
	token, err := readTokenFromSink(shared.VaultAgentTokenPath)
	if err != nil {
		return nil, err
	}
	client, err := NewClient(log)
	if err != nil {
		return nil, err
	}
	client.SetToken(token)
	return client, nil
}

/**/

/**/

/**/
