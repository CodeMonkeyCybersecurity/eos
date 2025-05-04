// pkg/vault/phase10_enable_userpass.go

package vault

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

//--------------------------------------------------------------------
// 10. Create Userpass Auth for EOS User
//--------------------------------------------------------------------

// PhaseEnableUserpass sets up the userpass auth method and creates the eos user.
func PhaseEnableUserpass(_ *api.Client, log *zap.Logger, password string) error {
	zap.L().Info("🧑‍💻 [Phase 10] Enabling userpass auth method and EOS user")

	// ✅ Get privileged client
	client, err := GetPrivilegedVaultClient()
	if err != nil {
		zap.L().Error("❌ Failed to get privileged Vault client", zap.Error(err))
		return fmt.Errorf("get privileged vault client: %w", err)
	}

	// Validate password
	if password == "" {
		zap.L().Warn("⚠️ No password provided, prompting user interactively...")
		password, err = crypto.PromptPassword("Enter password for EOS Vault user: ")
		if err != nil {
			return fmt.Errorf("failed to read password interactively: %w", err)
		}
	} else {
		if err := crypto.ValidateStrongPassword(password); err != nil {
			return fmt.Errorf("provided password failed validation: %w", err)
		}
	}

	if err := EnableUserpassAuth(client); err != nil {
		return fmt.Errorf("enable userpass auth: %w", err)
	}

	if err := EnsureUserpassUser(client, log, password); err != nil {
		return fmt.Errorf("ensure userpass user: %w", err)
	}

	zap.L().Info("✅ Userpass auth method and EOS user configured")
	return nil
}

// EnableUserpassAuth enables the userpass auth method if it is not already mounted.
func EnableUserpassAuth(client *api.Client) error {
	zap.L().Info("📡 Enabling userpass auth method if needed...")

	err := client.Sys().EnableAuthWithOptions("userpass", &api.EnableAuthOptions{Type: "userpass"})
	if err == nil {
		zap.L().Info("✅ Userpass auth method enabled")
		return nil
	}

	if strings.Contains(err.Error(), "path is already in use") {
		zap.L().Warn("⚠️ Userpass auth method already enabled", zap.Error(err))
		return nil
	}

	zap.L().Error("❌ Failed to enable userpass auth method", zap.Error(err))
	return fmt.Errorf("enable userpass auth: %w", err)
}

// EnsureUserpassUser ensures the eos user exists under userpass auth.
func EnsureUserpassUser(client *api.Client, log *zap.Logger, password string) error {
	zap.L().Info("👤 Ensuring EOS user exists under userpass auth")

	path := "auth/userpass/users/eos"

	// Check if user already exists
	secret, err := client.Logical().Read(path)
	if err == nil && secret != nil {
		zap.L().Warn("⚠️ EOS user already exists under userpass auth; skipping creation")
		return nil
	}

	userData := map[string]interface{}{
		"password": password,
		"policies": []string{"eos-policy"},
	}

	if _, err := client.Logical().Write(path, userData); err != nil {
		return fmt.Errorf("create userpass user: %w", err)
	}

	zap.L().Info("✅ EOS user created under userpass auth")

	// Save password fallback
	if err := WriteUserpassCredentialsFallback(password); err != nil {
		return fmt.Errorf("write userpass fallback: %w", err)
	}

	return nil
}
func WriteUserpassCredentialsFallback(password string) error {
	zap.L().Info("💾 Saving EOS userpass password to fallback and Vault")

	fallbackFile := shared.EosUserVaultFallback + "/userpass-password"
	fallbackDir := filepath.Dir(fallbackFile)

	if err := os.MkdirAll(fallbackDir, 0o700); err != nil {
		return fmt.Errorf("create fallback directory: %w", err)
	}

	if err := system.WriteOwnedFile(fallbackFile, []byte(password+"\n"), 0o600, shared.EosID); err != nil {
		return fmt.Errorf("write fallback file: %w", err)
	}
	zap.L().Info("✅ Userpass password written to fallback file", zap.String("path", fallbackFile))

	secrets := map[string]interface{}{
		"eos-userpass-password": password,
	}

	uid, gid, err := system.LookupUser(shared.EosID)
	if err != nil {
		return fmt.Errorf("lookup eos uid/gid: %w", err)
	}

	if err := system.ChownRecursive(shared.SecretsDir, uid, gid); err != nil {
		zap.L().Warn("⚠️ Failed to enforce EOS ownership after writing userpass fallback", zap.Error(err))
	}

	// ✅ Use privileged client here
	client, err := GetPrivilegedVaultClient()
	if err != nil {
		return fmt.Errorf("get privileged vault client for fallback write: %w", err)
	}
	if err := WriteKVv2(client, "secret", "eos/userpass-password", secrets); err != nil {
		return fmt.Errorf("write password to vault kv: %w", err)
	}

	zap.L().Info("✅ Userpass password written to Vault KV", zap.String("path", "secret/eos/userpass-password"))

	return nil
}
