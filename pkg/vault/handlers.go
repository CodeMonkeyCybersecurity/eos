/* pkg/vault/handlers.go */

package vault

import (
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

/* enableFeature is a generic Logical().Write wrapper for enabling things like audit devices, etc. */
func enableFeature(client *api.Client, path string, payload map[string]interface{}, successMsg string) error {
	fmt.Printf("\n🔧 Enabling feature at %s...\n", path)

	_, err := client.Logical().Write(path, payload)
	if err != nil {
		if strings.Contains(err.Error(), "already enabled") || strings.Contains(err.Error(), "already exists") {
			fmt.Printf("⚠️ Feature already enabled at %s\n", path)
			return nil
		}
		return fmt.Errorf("failed to enable feature at %s: %w", path, err)
	}

	fmt.Println(successMsg)
	return nil
}

/* Enable AppRole auth, create a role, read the role ID */
func enableAuth(client *api.Client, method string) error {
	err := client.Sys().EnableAuthWithOptions(method, &api.EnableAuthOptions{Type: method})
	if err != nil && !strings.Contains(err.Error(), "already in use") {
		return fmt.Errorf("failed to enable auth method %s: %w", method, err)
	}
	fmt.Printf("✅ %s auth enabled.\n", method)
	return nil
}

func enableMount(client *api.Client, path, engineType string, options map[string]string, msg string) error {
	err := client.Sys().Mount(path, &api.MountInput{
		Type:    engineType,
		Options: options,
	})
	if err != nil && !strings.Contains(err.Error(), "existing mount at") {
		return fmt.Errorf("failed to mount %s: %w", engineType, err)
	}
	fmt.Println(msg)
	return nil
}

func EnsureVaultReady(log *zap.Logger) (*api.Client, error) {
	client, err := NewClient(log)
	if err != nil {
		return nil, fmt.Errorf("vault client error: %w", err)
	}

	// Call SetupVault to initialize/unseal Vault.
	client, _, err = SetupVault(client, log)
	if err != nil {
		return nil, fmt.Errorf("vault not ready: %w", err)
	}
	return client, nil
}

//
// === Secure Vault Loaders ===
//

// ReadVaultSecureData loads bootstrap Vault secrets (vault_init, userpass creds).
func ReadVaultSecureData(client *api.Client, log *zap.Logger) (*api.InitResponse, UserpassCreds, []string, string) {
	log.Info("🔐 Starting secure Vault bootstrap sequence")

	if err := system.EnsureEosUser(true, false, log); err != nil {
		log.Fatal("❌ Failed to ensure eos system user", zap.Error(err))
	}

	vaultInitPath := DiskPath("vault_init", log)
	log.Info("📄 Reading vault_init.json from fallback", zap.String("path", vaultInitPath))
	initResPtr, err := ReadFallbackJSON[api.InitResponse](vaultInitPath, log)
	if err != nil {
		log.Fatal("❌ Failed to read vault_init.json", zap.Error(err))
	}
	initRes := *initResPtr
	log.Info("✅ Loaded vault_init.json", zap.Int("num_keys", len(initRes.KeysB64)))

	log.Info("📄 Reading eos userpass fallback file", zap.String("path", EosUserVaultFallback))
	credsPtr, err := ReadFallbackJSON[UserpassCreds](EosUserVaultFallback, log)
	if err != nil {
		log.Fatal("❌ Failed to read vault_userpass.json", zap.Error(err))
	}
	creds := *credsPtr

	if creds.Password == "" {
		log.Fatal("❌ Loaded Vault credentials but password is empty — aborting.")
	}
	log.Info("✅ Loaded eos Vault credentials")

	hashedKeys := crypto.HashStrings(initRes.KeysB64)
	hashedRoot := crypto.HashString(initRes.RootToken)

	log.Info("🔑 Derived Vault hash summaries",
		zap.Int("key_count", len(hashedKeys)),
		zap.String("root_token_hash", hashedRoot),
	)

	log.Info("🔒 Vault bootstrap sequence complete")
	return initResPtr, creds, hashedKeys, hashedRoot
}

func RequireVault(client *api.Client, log *zap.Logger) error {
	if client == nil {
		log.Error("❌ Vault client is nil", zap.String("reason", "Vault is required but not initialized"))
		return fmt.Errorf("vault is required for this command, but not available")
	}

	log.Debug("✅ Vault client is present and usable")
	return nil
}
