/* pkg/eoscli/handler.go */

package eoscli

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/hashicorp/vault/api"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var vaultCheck sync.Once

// Wrap adds automatic logger injection and scoped metadata based on calling package.
func Wrap(fn func(cmd *cobra.Command, args []string) error) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		start := time.Now()
		log := contextualLogger()
		log.Info("Command started", zap.Time("start_time", start))

		// ✅ Ensure Vault is ready BEFORE we run the command
		vaultCheck.Do(func() {
			log.Info("🔒 Checking Vault sealed state...")
			_, err := vault.EnsureVaultReady()
			if err != nil {
				log.Warn("⚠️ Vault is not fully prepared (sealed or missing fallback)", zap.Error(err))
				log.Warn("Continuing anyway — downstream commands may fail if Vault is required.")
			}
		})

		// Now run the command itself
		err := fn(cmd, args)
		duration := time.Since(start)

		if err != nil {
			log.Error("Command failed", zap.Duration("duration", duration), zap.Error(err))
		} else {
			log.Info("Command completed", zap.Duration("duration", duration))
		}

		return err
	}
}

//
// === Secure Vault Loaders ===
//

// ReadVaultSecureData loads bootstrap Vault secrets (vault_init, userpass creds).
func ReadVaultSecureData(client *api.Client) (*api.InitResponse, vault.UserpassCreds, []string, string) {
	if err := EnsureEosUser(); err != nil {
		log.Fatal("❌ Failed to ensure eos system user", zap.Error(err))
	}

	fmt.Println("🔐 Secure Vault setup in progress...")
	fmt.Println("This will revoke the root token and promote the eos admin user.")

	// Load vault_init.json from fallback file
	initResPtr, err := vault.ReadFallbackJSON[api.InitResponse](vault.DiskPath("vault_init"))
	if err != nil {
		log.Fatal("❌ Failed to read vault_init.json", zap.Error(err))
	}
	initRes := *initResPtr

	// Load eos user creds from fallback file
	credsPtr, err := vault.ReadFallbackJSON[vault.UserpassCreds](vault.EosUserFallbackFile)
	if err != nil {
		log.Fatal("❌ Failed to read vault_userpass.json", zap.Error(err))
	}
	creds := *credsPtr

	if creds.Password == "" {
		log.Fatal("❌ Loaded Vault credentials but password is empty — aborting.")
	}

	hashedKeys := crypto.HashStrings(initRes.KeysB64)
	hashedRoot := crypto.HashString(initRes.RootToken)

	return initResPtr, creds, hashedKeys, hashedRoot
}

func RequireVault(client *api.Client) error {
	if client == nil {
		return fmt.Errorf("vault is required for this command, but not available")
	}
	return nil
}
