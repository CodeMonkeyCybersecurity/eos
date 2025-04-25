// pkg/vault/phase_policy

package vault

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

// TODO, put logic in here
// 2. move auth logic from OrchestrateVaultUserLifecycle into here to avoid complexity
func EnableAuthMethods(map[string]string) {

}

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
// ## 9. Upload EOS Vault Policy
// EnsurePolicy writes the eos-policy defined in pkg/vault/types.go
// - `EnsureEosPolicy(client *api.Client, log *zap.Logger) error`

// EnsurePolicy writes the eos-policy defined in pkg/vault/types.go
func EnsurePolicy(client *api.Client, log *zap.Logger) error {
	log.Info("📝 Preparing to write Vault policy", zap.String("policy", shared.EosVaultPolicy))

	// 1️⃣ Retrieve the policy from internal map
	pol, ok := shared.Policies[shared.EosVaultPolicy]
	if !ok {
		log.Error("❌ Policy not found in internal map", zap.String("policy", shared.EosVaultPolicy))
		return fmt.Errorf("internal error: policy %q not found in shared.Policies map", shared.EosVaultPolicy)
	}

	// 2️⃣ Log metadata about the policy string
	log.Debug("📄 Policy loaded", zap.String("preview", truncatePolicy(pol)), zap.Int("length", len(pol)))

	// 3️⃣ Write policy to Vault
	log.Info("📡 Writing policy to Vault")
	if err := client.Sys().PutPolicy(shared.EosVaultPolicy, pol); err != nil {
		log.Error("❌ Failed to write policy", zap.String("policy", shared.EosVaultPolicy), zap.Error(err))
		return fmt.Errorf("failed to write policy %s: %w", shared.EosVaultPolicy, err)
	}

	// 4️⃣ Validate policy by re-fetching it from Vault
	log.Info("🔍 Verifying policy write")
	storedPol, err := client.Sys().GetPolicy(shared.EosVaultPolicy)
	if err != nil {
		log.Error("❌ Failed to retrieve policy for verification", zap.Error(err))
		return fmt.Errorf("failed to verify written policy: %w", err)
	}

	if strings.TrimSpace(storedPol) != strings.TrimSpace(pol) {
		log.Warn("⚠️ Policy mismatch detected after write",
			zap.String("expected_preview", truncatePolicy(pol)),
			zap.String("stored_preview", truncatePolicy(storedPol)))
		return fmt.Errorf("written policy does not match expected content")
	}

	log.Info("✅ Policy successfully written and verified", zap.String("policy", shared.EosVaultPolicy))
	return nil
}

// truncatePolicy returns a trimmed preview for debug logging
func truncatePolicy(policy string) string {
	policy = strings.TrimSpace(policy)
	if len(policy) > 100 {
		return policy[:100] + "..."
	}
	return policy
}

// ApplyAdminPolicy applies a full-access policy from the Policies map to the eos user.
func ApplyAdminPolicy(creds shared.UserpassCreds, client *api.Client, log *zap.Logger) error {
	fmt.Println("Creating full-access policy for eos.")

	policyName := shared.EosVaultPolicy
	policy, ok := shared.Policies[policyName]
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
	_, err := client.Logical().Write(shared.EosVaultUserPath, map[string]interface{}{
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
func EnsureVaultUserLifecycle(log *zap.Logger, client *api.Client) error {
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

/**/
// -> EnsureEosAppRole
func EnsureAppRole(client *api.Client, log *zap.Logger, opts shared.AppRoleOptions) (roleID string, secretID string, err error) {
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

/* Enable UserPass */
func EnableUserPass(client *api.Client) error {
	return enableAuth(client, "userpass")
}
