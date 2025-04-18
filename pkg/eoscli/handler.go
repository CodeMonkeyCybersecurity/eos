/* pkg/eoscli/handler.go */

package eoscli

import (
	"fmt"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/hashicorp/vault/api"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var vaultCheck sync.Once

/* Wrap adds automatic logger injection and scoped metadata based on calling package. */
func Wrap(fn func(cmd *cobra.Command, args []string) error) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		start := time.Now()
		log := contextualLogger()
		log.Info("Command started", zap.Time("start_time", start))

		var err error

		defer logger.LogCommandLifecycle(cmd.Name())(&err)

		vaultCheck.Do(func() {
			vault.EnsureVaultClient(log)

			log.Info("🔒 Checking Vault sealed state...")
			if _, vaultErr := vault.EnsureVaultReady(log); vaultErr != nil {
				log.Warn("⚠️ Vault is not fully prepared...", zap.Error(vaultErr))
				log.Warn("Continuing anyway — downstream commands may fail if Vault is required.")
			}
		})

		err = fn(cmd, args)
		return err
	}
}

//
// === Secure Vault Loaders ===
//

// ReadVaultSecureData loads bootstrap Vault secrets (vault_init, userpass creds).
func ReadVaultSecureData(client *api.Client, log *zap.Logger) (*api.InitResponse, vault.UserpassCreds, []string, string) {
	if err := system.EnsureEosUser(true, false, log); err != nil {
		log.Fatal("❌ Failed to ensure eos system user", zap.Error(err))
	}

	fmt.Println("🔐 Secure Vault setup in progress...")
	fmt.Println("This will revoke the root token and promote the eos admin user.")

	// Load vault_init.json from fallback file
	initResPtr, err := vault.ReadFallbackJSON[api.InitResponse](vault.DiskPath("vault_init", log), log)
	if err != nil {
		log.Fatal("❌ Failed to read vault_init.json", zap.Error(err))
	}
	initRes := *initResPtr

	// Load eos user creds from fallback file
	credsPtr, err := vault.ReadFallbackJSON[vault.UserpassCreds](vault.EosUserVaultFallback, log)
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
