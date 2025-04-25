// pkg/vault/lifecycle_vault_user.go

package vault

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

// ## 11. Render Vault Agent Config

// - `RenderVaultAgentConfig(roleID, secretID string) ([]byte, error)`
// - `WriteVaultAgentConfig(config []byte) error`

/**/
// TODO: ensure all this fx is covered
// Checks for a system user and creates it if missing.
//
// -> `EnsureEosUserExists(log *zap.Logger) error`   // Handles user creation (if not present) ✅ (split out user creation)
// 	- EOS ensures the `eos` system user exists and has appropriate sudo access to:
// 	- `systemctl start vault*`
// 	- `cat 	VaultAgentTokenPath = filepath.Join(EosRunDir, "vault_agent_eos.token")`
// 	- The fallback file must be readable by the `eos` user (owned by `eos:eos`, mode 0600).
// 	- EOS will log an error and suggest corrective `chmod`/`chown` steps if this is not the case.
// 	- If the user or sudoers config is missing, EOS CLI will fail gracefully with a remediation suggestion.
// 	Check sudoers entry via visudo -c or file scan
// 	•	Optionally write a template to /etc/sudoers.d/eos (with --grant-sudo)
// 	•	Log this action or provide user with a suggested copy-paste block
//     - EOS ensures the `eos` system user exists and has appropriate sudo access to:
//     - `systemctl start vault*`
//     - `cat 	VaultAgentTokenPath = filepath.Join(EosRunDir, "vault_agent_eos.token")`
//     - The fallback file must be readable by the `eos` user (owned by `eos:eos`, mode 0600).
//     - EOS will log an error and suggest corrective `chmod`/`chown` steps if this is not the case.
//     - If the user or sudoers config is missing, EOS CLI will fail gracefully with a remediation suggestion.
//     Check sudoers entry via visudo -c or file scan
// 	•	Optionally write a template to /etc/sudoers.d/eos (with --grant-sudo)
// 	•	Log this action or provide user with a suggested copy-paste block

// ### Decision: EOS Internal Privilege Escalation

// - EOS CLI will internally use `sudo -u eos` when privileged actions are required (e.g., unseal Vault, access token sink, start systemd units).
// - EOS will only attempt to read the agent token once Vault Agent is confirmed active and the token file exists with mode 0600 and user `eos`.
// - In cases where token reading fails, CLI will report and fallback to prompting for manual root token (with `--force` override if needed).

// - Users **should not** be required to prefix `sudo eos ...`.
// - This model mirrors the ergonomic style of `docker`, but avoids persistent daemons and overexposed sockets.
// - Privilege boundaries are enforced in code (e.g., `RunAsEos(...)`) and can be audited centrally.
// - CLI fallback or override (`--no-sudo`, `--as-user=...`) may be added later for advanced users.
// - EOS uses `exec.Command("sudo", "-u", shared.EosIdentity, ...)` for privileged actions.
// - The password prompt, permission checks, and session expiry logic are all handled by `sudo`, not EOS.
// - EOS never sees or stores user credentials.
// - Users may be prompted for their password (by the shell) if their sudo timestamp is expired.
// - EOS will provide optional log lines to explain "why" escalation is occurring (for transparency).
// - This approach keeps EOS minimal, idiomatic, and fully in line with Unix principles.

// alice ALL=(eos) NOPASSWD: /usr/bin/systemctl start vault*, /bin/cat /etc/vault-agent-eos.token
// 	•	Fine-grained access can be granted by restricting allowed commands eg.:
// alice ALL=(eos) NOPASSWD: /usr/bin/systemctl start vault*, /bin/cat /etc/vault-agent-eos.token

// 	•	EOS CLI uses sudo -u eos internally; all permission enforcement and password prompting are delegated to the operating system.
// 	•	No group-based permissions are used or required, avoiding the risks of group-based privilege escalation (as seen with the docker group).
// 	•	Root users retain full access but should still delegate to the eos user when operating EOS, to maintain consistent privilege boundaries.
// ---

// OrchestrateVaultUserLifecycle ensures the eos user, Vault directories,
// sudoers permissions, auth methods, and AppRole are all configured correctly.
// TODO: ensure this is addressed:
// a high-level wrapper: EnsureVaultUserLifecycle()
// This can encapsulate:
// •	system.EnsureEosUser(...)
// •	EnsureVaultDirs(...)
// •	EnsureSudoersEntryForEos(...)
// •	EnsureVaultAuthMethods(...)
// •	EnsureAppRole(...)
// Make this the go-to for Step 2. Keep EnsureVault(...) clean by calling this inline.
func OrchestrateVaultUserLifecycle(log *zap.Logger, client *api.Client) error {
	if err := system.EnsureEosUser(true, false, log); err != nil {
		return err
	}
	if err := EnsureVaultDirs(log); err != nil {
		return err
	}
	if err := system.EnsureSudoersEntryForEos(log, true); err != nil {
		return err
	}
	if err := EnsureVaultAuthMethods(client, log); err != nil {
		return err
	}

	if err := TestSudoAccess(log); err != nil {
		return err

	}
	_, _, err := EnsureAppRole(client, log, DefaultAppRoleOptions())
	return err
}

// TODO, put logic in here
// 2. move auth logic from OrchestrateVaultUserLifecycle into here to avoid complexity
func EnableAuthMethods(map[string]string) {

}

/**/
// TODO: Suggested Fix: Extract a shared writeAppRoleCredFile(path, data string) helper and use it in both WriteAppRoleFiles and refreshAppRoleCreds.
// TODO: DRY these functions:
// EnsureAppRoleAuth
// EnsureVaultAuthMethods
// EnsureAuthMethod
// EnableUserPass
// enableAuth
// EnsureAppRole and its helpers:
// readAppRoleCredsFromDisk,
// refreshAppRoleCreds ,
// ensureOwnedDir,
// writeOwnedFile
// Enables the AppRole auth method and provisions the eos‑role.
func EnsureAppRoleAuth(client *api.Client, log *zap.Logger) error {
	// 1) Enable the approle auth method if not already
	log.Info("➕ Enabling AppRole auth method")
	if err := client.Sys().EnableAuthWithOptions("approle", &api.EnableAuthOptions{Type: "approle"}); err != nil {
		if !strings.Contains(err.Error(), "path is already in use") {
			return fmt.Errorf("failed to enable approle auth: %w", err)
		}
	}
	log.Info("✅ AppRole auth method is enabled")

	// 2) Create the role
	log.Info("🛠 Provisioning AppRole", zap.String("role", shared.RoleName))
	_, err := client.Logical().Write(shared.RolePath, map[string]interface{}{
		"policies":      []string{shared.EosVaultPolicy},
		"token_ttl":     "4h",
		"token_max_ttl": "24h",
		"secret_id_ttl": "24h",
	})
	if err != nil {
		return fmt.Errorf("failed to create AppRole %s: %w", shared.RoleName, err)
	}
	log.Info("✅ AppRole provisioned", zap.String("role", shared.RoleName))
	return nil
}

/**/

/**/
func EnsureVaultAuthEnabled(client *api.Client, method, path string, log *zap.Logger) error {
	existing, err := client.Sys().ListAuth()
	if err != nil {
		return err
	}
	if _, ok := existing[path]; ok {
		return nil
	}
	return client.Sys().EnableAuthWithOptions(strings.TrimSuffix(path, "/"), &api.EnableAuthOptions{Type: method})
}

/**/

/**/
// TODO: ensure proper funtionality covererd in here
//  10. Create AppRole for EOS
// -> SaveAppRoleCredentials(roleID, secretID string, log *zap.Logger) error
//   → Writes to `/var/lib/eos/secrets/eos-approle.json` if --dev-mode
// ### Decision: EOS Vault AppRole and Token Strategy
// - EOS creates an AppRole named `eos-approle` at `auth/approle/role/eos-approle`
// - Role uses:
//   - 30m token TTL, renewable up to 24h
//   - `secret_id_bound_cidrs` and/or `bind_secret_id = true`
// - EOS uploads a policy named `eos-policy` that grants:
//   - CRUD on `secret/infra/*`, `secret/ldap/*`, `secret/init/vault-init`
//   - List and lookup metadata under those prefixes
// - EOS Vault Agent stores its token at:
//   - `	VaultAgentTokenPath = filepath.Join(EosRunDir, "vault_agent_eos.token")`
//   - Owned by `eos:eos`, mode `0600`
// - EOS CLI reads this token via `sudo -u eos cat 	VaultAgentTokenPath = filepath.Join(EosRunDir, "vault_agent_eos.token")`
// - Token provisioning is handled during setup; EOS may rotate these later via `eos vault rotate`
// - - EOS will only attempt to read the agent token once Vault Agent is confirmed active and the token file exists with mode 0600 and user `eos`.
// - In cases where token reading fails, CLI will report and fallback to prompting for manual root token (with `--force` override if needed).
/**/

/**/
// -> EnsureEosAppRole
func EnsureAppRole(client *api.Client, log *zap.Logger, opts AppRoleOptions) (roleID string, secretID string, err error) {
	// Skip if credentials already exist and ForceRecreate is false
	if !opts.ForceRecreate {
		if _, err := os.Stat(shared.RoleIDPath); err == nil {
			log.Info("🔐 AppRole credentials already present — skipping creation",
				zap.String("role_id_path", shared.RoleIDPath),
				zap.Bool("refresh", opts.RefreshCreds),
			)
			if opts.RefreshCreds {
				log.Info("🔄 Refreshing AppRole credentials...")
				roleID, secretID, err := refreshAppRoleCreds(client, log)
				return roleID, secretID, err
			}
			return readAppRoleCredsFromDisk(log)
		}
	}

	log.Info("🛠️ Creating or updating Vault AppRole",
		zap.String("role_path", shared.RolePath),
		zap.Strings("policies", []string{shared.EosVaultPolicy}),
	)

	// Enable auth method
	log.Debug("📡 Enabling AppRole auth method if needed...")
	if err := client.Sys().EnableAuthWithOptions("approle", &api.EnableAuthOptions{Type: "approle"}); err != nil {
		log.Warn("⚠️ AppRole auth method may already be enabled", zap.Error(err))
	}

	// Write role config
	log.Debug("📦 Writing AppRole definition to Vault...")
	if _, err := client.Logical().Write(shared.RolePath, map[string]interface{}{
		"policies":      []string{shared.EosVaultPolicy},
		"token_ttl":     "60m",
		"token_max_ttl": "120m",
	}); err != nil {
		log.Error("❌ Failed to write AppRole definition", zap.String("path", shared.RolePath), zap.Error(err))
		return "", "", fmt.Errorf("failed to create AppRole %q: %w", shared.RolePath, err)
	}
	log.Info("✅ AppRole written to Vault", zap.String("role_path", shared.RolePath))

	// Read credentials from Vault
	log.Debug("🔑 Fetching AppRole credentials from Vault...")
	roleResp, err := client.Logical().Read(shared.RolePath + "/role-id")
	if err != nil {
		log.Error("❌ Failed to read AppRole role_id", zap.String("path", shared.RolePath+"/role-id"), zap.Error(err))
		return "", "", fmt.Errorf("failed to read role_id: %w", err)
	}

	secretResp, err := client.Logical().Write(shared.RolePath+"/secret-id", nil)
	if err != nil {
		log.Error("❌ Failed to generate AppRole secret_id", zap.String("path", shared.RolePath+"/secret-id"), zap.Error(err))
		return "", "", fmt.Errorf("failed to generate secret_id: %w", err)
	}

	rawRoleID, ok := roleResp.Data["role_id"].(string)
	if !ok || rawRoleID == "" {
		log.Error("❌ Invalid or missing role_id in Vault response", zap.Any("data", roleResp.Data))
		return "", "", fmt.Errorf("invalid role_id in Vault response")
	}

	rawSecretID, ok := secretResp.Data["secret_id"].(string)
	if !ok || rawSecretID == "" {
		log.Error("❌ Invalid or missing secret_id in Vault response", zap.Any("data", secretResp.Data))
		return "", "", fmt.Errorf("invalid secret_id in Vault response")
	}

	// Persist them to disk for the agent
	if err := WriteAppRoleFiles(rawRoleID, rawSecretID, log); err != nil {
		log.Error("❌ Failed to write AppRole credentials to disk", zap.Error(err))
		return "", "", err
	}

	log.Info("✅ AppRole provisioning complete",
		zap.String("role_id", rawRoleID),
		zap.String("secret_id", "[redacted]"),
	)

	return rawRoleID, rawSecretID, nil
}

/**/

// WriteAppRoleFiles writes the role_id & secret_id into /etc/vault and
// ensures the directory is 0700, owned by eos:eos.
func WriteAppRoleFiles(roleID, secretID string, log *zap.Logger) error {
	dir := filepath.Dir(shared.RoleIDPath)
	log.Info("📁 Ensuring AppRole directory", zap.String("path", dir))
	if err := system.EnsureOwnedDir(dir, 0o700, shared.EosUser); err != nil {
		return err
	}

	pairs := map[string]string{
		shared.RoleIDPath:   roleID + "\n",
		shared.SecretIDPath: secretID + "\n",
	}
	for path, data := range pairs {
		log.Debug("✏️  Writing AppRole file", zap.String("path", path))
		if err := system.WriteOwnedFile(path, []byte(data), 0o600, shared.EosUser); err != nil {
			return err
		}
	}

	log.Info("✅ AppRole credentials written",
		zap.String("role_file", shared.RoleIDPath),
		zap.String("secret_file", shared.SecretIDPath))
	return nil
}

/**/
func readAppRoleCredsFromDisk(log *zap.Logger) (string, string, error) {
	roleIDBytes, err := os.ReadFile(shared.RoleIDPath)
	if err != nil {
		return "", "", fmt.Errorf("read role_id from disk: %w", err)
	}
	secretIDBytes, err := os.ReadFile(shared.SecretIDPath)
	if err != nil {
		return "", "", fmt.Errorf("read secret_id from disk: %w", err)
	}
	roleID := strings.TrimSpace(string(roleIDBytes))
	secretID := strings.TrimSpace(string(secretIDBytes))

	log.Info("📄 Loaded AppRole credentials from disk",
		zap.String("role_id_path", shared.RoleIDPath),
		zap.String("secret_id_path", shared.SecretIDPath),
	)
	return roleID, secretID, nil
}

/**/

/**/
func refreshAppRoleCreds(client *api.Client, log *zap.Logger) (string, string, error) {
	log.Debug("🔑 Requesting AppRole credentials from Vault...")

	// Read role_id from Vault
	roleID, err := client.Logical().Read(shared.RolePath + "/role-id")
	if err != nil {
		log.Error("❌ Failed to read AppRole role_id",
			zap.String("path", shared.RolePath+"/role-id"),
			zap.Error(err),
		)
		return "", "", err
	}

	// Generate secret_id
	secretID, err := client.Logical().Write(shared.RolePath+"/secret-id", nil)
	if err != nil {
		log.Error("❌ Failed to generate AppRole secret_id",
			zap.String("path", shared.RolePath+"/secret-id"),
			zap.Error(err),
		)
		return "", "", err
	}

	// Safely extract role_id
	rawRoleID, ok := roleID.Data["role_id"].(string)
	if !ok || rawRoleID == "" {
		log.Error("❌ Invalid or missing role_id in Vault response",
			zap.Any("data", roleID.Data),
		)
		return "", "", fmt.Errorf("invalid role_id in Vault response")
	}

	// Safely extract secret_id
	rawSecretID, ok := secretID.Data["secret_id"].(string)
	if !ok || rawSecretID == "" {
		log.Error("❌ Invalid or missing secret_id in Vault response",
			zap.Any("data", secretID.Data),
		)
		return "", "", fmt.Errorf("invalid secret_id in Vault response")
	}

	// Ensure directory exists (logged elsewhere if needed)
	log.Debug("💾 Writing AppRole credentials to disk")

	// Write role_id
	if err := system.WriteOwnedFile(shared.RoleIDPath, []byte(rawRoleID+"\n"), 0o640, shared.EosUser); err != nil {
		log.Error("❌ Failed to write role_id",
			zap.String("path", shared.RoleIDPath),
			zap.Error(err),
		)
		return "", "", err
	}

	// Write secret_id
	if err := system.WriteOwnedFile(shared.SecretIDPath, []byte(rawSecretID+"\n"), 0o640, shared.EosUser); err != nil {
		log.Error("❌ Failed to write secret_id",
			zap.String("path", shared.SecretIDPath),
			zap.Error(err),
		)
		return "", "", err
	}

	log.Info("✅ AppRole credentials written to disk",
		zap.String("role_id_path", shared.RoleIDPath),
		zap.String("secret_id_path", shared.SecretIDPath),
	)
	return rawRoleID, rawSecretID, nil
}

/**/

/**/
func TestSudoAccess(log *zap.Logger) error {
	cmd := exec.Command("sudo", "-u", shared.EosIdentity, "cat", shared.VaultAgentTokenPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Warn("❌ sudo -u eos failed", zap.Error(err), zap.String("output", string(out)))
		return fmt.Errorf("sudo check failed")
	}
	log.Info("✅ sudo test succeeded")
	return nil
}

/**/
