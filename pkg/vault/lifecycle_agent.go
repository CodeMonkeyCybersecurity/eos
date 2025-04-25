// pkg/vault/lifecycle_agent.go

package vault

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

// ## 12. Install and Start vault-agent-eos.service

// - `RenderVaultAgentServiceUnit() ([]byte, error)`
// - `InstallSystemdUnit(name string, content []byte) error`
// - `StartAndEnableService(name string) error`

// ---

//
// ========================== ENSURE ==========================
//

// EnsureAgent configures & launches the Vault Agent under the eos system‑user.
// `password` is only used by the userpass method; for AppRole you can pass ""
// and `opts` comes from DefaultAppRoleOptions().
// EnsureAgent configures & launches the Vault Agent under the eos system‑user.
// `password` is only used by the userpass method; for AppRole you can pass ""
// and `opts` comes from DefaultAppRoleOptions().

// TODO
// PLACEHOLDER TO ENSURE THIS IS IMPLEMENTED
// ## 5. Install and Start vault.service

// - `RenderVaultServiceUnit() ([]byte, error)`
// - `InstallSystemdUnit(name string, content []byte) error`
// - `StartAndEnableService(name string) error`

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

//
// ========================== LIFECYCLE_AGENT ==========================
//

/**/
// ## 11. Render Vault Agent Config
/**/

/**/
// TODO: WriteVaultAgentConfig(config []byte) error
/**/

/**/
// ## 12. Install and Start vault-agent-eos.service
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
/**/

/**/
// -> StartAndEnableService(name string) error
// utils.ReloadDaemonAndEnable reloads systemd, then enables & starts the given unit.
// It returns an error if either step fails.
func ReloadDaemonAndEnable(log *zap.Logger, unit string) error {
	// 1) reload systemd
	if out, err := exec.Command("systemctl", "daemon-reload").CombinedOutput(); err != nil {
		log.Warn("systemd daemon-reload failed",
			zap.Error(err),
			zap.ByteString("output", out),
		)
		return fmt.Errorf("daemon-reload: %w", err)
	}

	// 2) enable & start the unit
	if out, err := exec.Command("systemctl", "enable", "--now", unit).CombinedOutput(); err != nil {
		log.Warn("failed to enable/start service",
			zap.String("unit", unit),
			zap.Error(err),
			zap.ByteString("output", out),
		)
		return fmt.Errorf("enable --now %s: %w", unit, err)
	}

	log.Info("✅ systemd unit enabled & started",
		zap.String("unit", unit),
	)
	return nil
}

/**/

/**/
/* ## 13. Wait for Vault Agent Token */
// TODO:
// WaitForAgentToken(path string) error
// Function WaitForAgentToken(path string) should:
// 	•	Poll for existence and permissions
// 	•	Retry with timeout
// 	•	Log helpful error if timeout fails
//     - EOS will poll the token sink file every 500ms for up to 30s.
//     - If the token is missing, unreadable, or has incorrect permissions, a clear error will be logged with remediation suggestions.
/**/

/**/
// TODO:
// ValidateAgentToken(client *api.Client, token string) error
/**/

/**/
// TODO
// SetVaultToken(token string) error  // Configures Vault client to use the agent token
/**/

/**/
func EnsureAgent(client *api.Client, password string, log *zap.Logger, opts AppRoleOptions) error {
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
	if err := WriteSystemdUnit(log); err != nil {
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
func EnsureAgentConfig(vaultAddr string, log *zap.Logger) error {

	// ✅ Check for existing config first
	if _, err := os.Stat(shared.VaultAgentConfigPath); err == nil {
		log.Info("✅ Vault Agent config already exists — skipping rewrite", zap.String("path", shared.VaultAgentConfigPath))
		return nil
	}

	// ✅ Check AppRole files exist
	if _, err := os.Stat(shared.RoleIDPath); err != nil {
		return fmt.Errorf("role_id not found: %w", err)
	}
	if _, err := os.Stat(shared.SecretIDPath); err != nil {
		return fmt.Errorf("secret_id not found: %w", err)
	}

	log.Info("✍️ Writing Vault Agent config file", zap.String("path", shared.VaultAgentConfigPath))

	// Use dynamic Vault address and listener
	content := fmt.Sprintf(`
pid_file = "%s"

auto_auth {
  method "approle" {
    config = {
      role_id_file_path   = "%s"
      secret_id_file_path = "%s"
    }
  }
  sink "file" {
    config = {
      path = "%s"
    }
  }
}

vault {
  address = "%s"
}

listener "tcp" {
  address     = "%s"
  tls_disable = true
}

cache {
  use_auto_auth_token = true
}`, shared.AgentPID, shared.RoleIDPath, shared.SecretIDPath, shared.VaultAgentTokenPath, vaultAddr, shared.VaultDefaultPort)

	if err := os.WriteFile(shared.VaultAgentConfigPath, []byte(strings.TrimSpace(content)+"\n"), 0644); err != nil {
		return fmt.Errorf("failed to write Vault Agent config to %s: %w", shared.VaultAgentConfigPath, err)
	}

	log.Info("✅ Vault Agent config written successfully", zap.String("path", shared.VaultAgentConfigPath))
	return nil
}

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
func WriteSystemdUnit(log *zap.Logger) error {
	unit := fmt.Sprintf(agentSystemDUnit,
		// %s User,   VaultAgentUser
		// %s Group,  VaultAgentGroup
		// %o RuntimeDirectoryMode, xdg.VaultRuntimePerms
		// %s ExecStartPre owner, VaultAgentUser
		// %s ExecStartPre group, VaultAgentGroup
		// %o ExecStartPre mode,  xdg.VaultRuntimePerms
		// %s ExecStartPre path,  EosRunDir
		// %s ExecStart   config,  shared.VaultAgentConfigPath
		shared.VaultAgentUser,
		shared.VaultAgentGroup,
		shared.VaultRuntimePerms,
		shared.VaultAgentUser,
		shared.VaultAgentGroup,
		shared.VaultRuntimePerms,
		shared.EosRunDir,
		shared.VaultAgentConfigPath,
	)

	log.Debug("✍️  Writing systemd unit", zap.String("path", shared.VaultAgentServicePath))
	if err := os.WriteFile(shared.VaultAgentServicePath,
		[]byte(strings.TrimSpace(unit)+"\n"),
		shared.FilePermStandard,
	); err != nil {
		return fmt.Errorf("write unit file: %w", err)
	}
	log.Info("✅ Systemd unit written", zap.String("path", shared.VaultAgentServicePath))
	return nil
}

/**/

/**/
// readTokenFromSink reads the Vault Agent token (run as 'eos' system user)
func readTokenFromSink(path string) (string, error) {
	if path == "" {
		path = shared.VaultAgentTokenPath
	}
	out, err := exec.Command("sudo", "-u", shared.EosIdentity, "cat", path).Output()
	if err != nil {
		return "", fmt.Errorf("failed to read token from Vault Agent sink at %s: %w", path, err)
	}
	return strings.TrimSpace(string(out)), nil
}

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
func RenderAgentConfig(addr, roleID, secretID string, log *zap.Logger) error {
	log.Info("🧩 Rendering Vault Agent HCL template",
		zap.String("VAULT_ADDR", addr),
		zap.String("role_id_path", shared.RoleIDPath),
		zap.String("secret_id_path", shared.SecretIDPath),
		zap.String("config_path", shared.VaultAgentConfigPath),
	)

	// Ensure secrets directory exists
	if err := os.MkdirAll(filepath.Dir(shared.RoleIDPath), shared.FilePermOwnerRWX); err != nil {
		log.Error("❌ Failed to create secrets directory", zap.String("dir", filepath.Dir(shared.RoleIDPath)), zap.Error(err))
		return err
	}
	log.Info("✅ Ensured secrets directory exists", zap.String("dir", filepath.Dir(shared.RoleIDPath)))

	// Ensure role_id exists or re-write it
	if _, err := os.Stat(shared.RoleIDPath); os.IsNotExist(err) {
		log.Warn("🔧 role_id file missing — re-creating", zap.String("path", shared.RoleIDPath))
		if err := os.WriteFile(shared.RoleIDPath, []byte(roleID), shared.OwnerReadOnly); err != nil {
			log.Error("❌ Failed to write role_id", zap.String("path", shared.RoleIDPath), zap.Error(err))
			return err
		}
		log.Info("✅ Wrote role_id", zap.String("path", shared.RoleIDPath), zap.String("perm", "0400"))
	} else {
		log.Info("📄 role_id file already exists", zap.String("path", shared.RoleIDPath))
	}

	// Ensure secret_id exists or re-write it
	if _, err := os.Stat(shared.SecretIDPath); os.IsNotExist(err) {
		log.Warn("🔧 secret_id file missing — re-creating", zap.String("path", shared.SecretIDPath))
		if err := os.WriteFile(shared.SecretIDPath, []byte(secretID), shared.OwnerReadOnly); err != nil {
			log.Error("❌ Failed to write secret_id", zap.String("path", shared.SecretIDPath), zap.Error(err))
			return err
		}
		log.Info("✅ Wrote secret_id", zap.String("path", shared.SecretIDPath), zap.String("perm", "0400"))
	} else {
		log.Info("📄 secret_id file already exists", zap.String("path", shared.SecretIDPath))
	}

	// Build template data
	data := struct {
		Addr, CACert, RoleFile, SecretFile, TokenSink string
	}{
		Addr:       addr,
		CACert:     shared.VaultAgentCACopyPath,
		RoleFile:   shared.RoleIDPath,
		SecretFile: shared.SecretIDPath,
		TokenSink:  shared.VaultAgentTokenPath,
	}

	// Write HCL config to disk
	log.Info("📄 Writing Vault Agent config file", zap.String("path", shared.VaultAgentConfigPath))
	tpl := template.Must(template.New("agent.hcl").Parse(shared.AgentConfigTmpl))
	f, err := os.Create(shared.VaultAgentConfigPath)
	if err != nil {
		log.Error("❌ Failed to create Vault Agent config file", zap.String("path", shared.VaultAgentConfigPath), zap.Error(err))
		return fmt.Errorf("create %s: %w", shared.VaultAgentConfigPath, err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			log.Warn("⚠️ Failed to close Vault Agent config file", zap.String("path", shared.VaultAgentConfigPath), zap.Error(cerr))
		}
	}()

	if err := tpl.Execute(f, data); err != nil {
		log.Error("❌ Failed to render Vault Agent template", zap.Error(err))
		return fmt.Errorf("execute template: %w", err)
	}

	if err := os.Chmod(shared.VaultAgentConfigPath, shared.FilePermStandard); err != nil {
		log.Warn("⚠️ Failed to set permissions on Vault Agent config", zap.String("path", shared.VaultAgentConfigPath), zap.Error(err))
	} else {
		log.Info("✅ Set permissions on Vault Agent config", zap.String("perm", fmt.Sprintf("%#o", shared.FilePermStandard)))
	}

	log.Info("✅ Vault Agent HCL successfully rendered", zap.String("output", shared.VaultAgentConfigPath))
	return nil
}

/**/
