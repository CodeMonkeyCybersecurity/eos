/* pkg/eoscli/handler.go */

package eoscli

import (
	"fmt"
	"log"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/hashicorp/vault/api"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// Wrap adds automatic logger injection and scoped metadata based on calling package.
func Wrap(fn func(cmd *cobra.Command, args []string) error) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		start := time.Now()
		log := contextualLogger()
		log.Info("Command started", zap.Time("start_time", start))

		// ✅ Ensure Vault is ready BEFORE we run the command
		if err := vault.EnsureVaultUnsealed(); err != nil {
			log.Error("Vault could not be unsealed", zap.Error(err))
			return err
		}

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

	var initRes *api.InitResponse
	if err := vault.Read(client, "vault_init", &initRes); err != nil {
		log.Fatal("❌ Failed to read vault_init", zap.String("path", vault.DiskPath("vault_init")), zap.Error(err))
	}

	var creds vault.UserpassCreds
	if err := vault.Read(client, "bootstrap/eos-user", &creds); err != nil {
		log.Fatal("❌ Failed to load eos userpass credentials", zap.Error(err))
	}

	if creds.Password == "" {
		log.Fatal("❌ Loaded Vault credentials but password is empty — aborting.")
	}

	hashedKeys := crypto.HashStrings(initRes.KeysB64)
	hashedRoot := crypto.HashString(initRes.RootToken)

	return initRes, creds, hashedKeys, hashedRoot
}
