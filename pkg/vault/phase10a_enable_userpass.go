// pkg/vault/phase10_enable_userpass.go

package vault

import (
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

//--------------------------------------------------------------------
// 10. Create Userpass Auth for EOS User
//--------------------------------------------------------------------

// PhaseEnableUserpass sets up the userpass auth method and creates the eos user.
func PhaseEnableUserpass(client *api.Client, log *zap.Logger, password string) error {
	log.Info("🧑‍💻 [Phase 10] Enabling userpass auth method and EOS user")

	if err := EnableUserpassAuth(client, log); err != nil {
		return fmt.Errorf("enable userpass auth: %w", err)
	}

	if err := EnsureUserpassUser(client, log, password); err != nil {
		return fmt.Errorf("ensure userpass user: %w", err)
	}

	log.Info("✅ Userpass auth method and EOS user configured")
	return nil
}

// EnableUserpassAuth enables the userpass auth method if it is not already mounted.
func EnableUserpassAuth(client *api.Client, log *zap.Logger) error {
	log.Info("📡 Enabling userpass auth method if needed...")

	err := client.Sys().EnableAuthWithOptions("userpass", &api.EnableAuthOptions{Type: "userpass"})
	if err == nil {
		log.Info("✅ Userpass auth method enabled")
		return nil
	}

	if strings.Contains(err.Error(), "path is already in use") {
		log.Warn("⚠️ Userpass auth method already enabled", zap.Error(err))
		return nil
	}

	log.Error("❌ Failed to enable userpass auth method", zap.Error(err))
	return fmt.Errorf("enable userpass auth: %w", err)
}

// EnsureUserpassUser ensures the eos user exists under userpass auth.
func EnsureUserpassUser(client *api.Client, log *zap.Logger, password string) error {
	log.Info("👤 Ensuring EOS user exists under userpass auth")

	path := "auth/userpass/users/eos"

	// Check if user already exists
	secret, err := client.Logical().Read(path)
	if err == nil && secret != nil {
		log.Warn("⚠️ EOS user already exists under userpass auth; skipping creation")
		return nil
	}

	userData := map[string]interface{}{
		"password": password,
		"policies": []string{"eos-policy"},
	}

	if _, err := client.Logical().Write(path, userData); err != nil {
		return fmt.Errorf("create userpass user: %w", err)
	}

	log.Info("✅ EOS user created under userpass auth")

	// Save password fallback
	if err := WriteUserpassCredentialsFallback(password, log); err != nil {
		return fmt.Errorf("write userpass fallback: %w", err)
	}

	return nil
}

// WriteUserpassCredentialsFallback saves the EOS userpass password to Vault and fallback disk.
func WriteUserpassCredentialsFallback(password string, log *zap.Logger) error {
	log.Info("💾 Saving EOS userpass password to fallback and Vault")

	// Write to fallback file
	if err := system.WriteOwnedFile(shared.EosUserVaultFallback+"/userpass-password", []byte(password+"\n"), 0o600, shared.EosUser); err != nil {
		return fmt.Errorf("write fallback file: %w", err)
	}
	log.Info("✅ Userpass password written to fallback file", zap.String("path", shared.EosUserVaultFallback+"/userpass-password"))

	// Prepare KV payload
	secrets := map[string]interface{}{
		"eos-userpass-password": password,
	}

	// Write to Vault KV
	client, err := NewClient(log)
	if err != nil {
		return fmt.Errorf("get vault client for fallback write: %w", err)
	}
	if err := WriteKVv2(client, "secret", "eos/userpass-password", secrets, log); err != nil {
		return fmt.Errorf("write password to vault kv: %w", err)
	}

	log.Info("✅ Userpass password written to Vault KV", zap.String("path", "secret/eos/userpass-password"))

	return nil
}
