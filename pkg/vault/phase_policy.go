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

/**/
// ## 9. Upload EOS Vault Policy
// EnsurePolicy writes the eos-policy defined in pkg/vault/types.go
// - `EnsureEosPolicy(client *api.Client, log *zap.Logger) error`

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

/**/

/**/
func TestSudoAccess(log *zap.Logger) error {
	cmd := exec.Command("sudo", "-u", shared.EosID, "cat", shared.VaultAgentTokenPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Warn("❌ sudo -u eos failed", zap.Error(err), zap.String("output", string(out)))
		return fmt.Errorf("sudo check failed")
	}
	log.Info("✅ sudo test succeeded")
	return nil
}

/**/
