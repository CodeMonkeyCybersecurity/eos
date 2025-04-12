/* cmd/enable/vault */

package enable

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var EnableVaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Enables Vault with sane and secure defaults",
	Long: `This command assumes "github.com/CodeMonkeyCybersecurity/eos install vault" has been run.
It initializes and unseals Vault, sets up auditing, KV v2, 
AppRole, userpass, and creates an eos user with a random password.`,
	RunE: eos.Wrap(func(cmd *cobra.Command, args []string) error {
		/* Ensure Vault is installed */
		log.Info("[0/7] Starting Vault enable workflow")
		if err := vault.InstallVaultViaDnf(); err != nil {
			log.Error("Failed to install Vault", zap.Error(err))
			return err
		}
		addr, err := vault.SetVaultEnv()
		if err != nil {
			log.Error("Failed to set VAULT_ADDR", zap.Error(err))
			return err
		}
		log.Info("Set VAULT_ADDR from hostname", zap.String("VAULT_ADDR", addr))
		client, err := vault.NewClient()
		if err != nil {
			log.Fatal("Failed to create Vault client", zap.Error(err))
		}

		client, initRes, err := vault.SetupVault(client)
		if err != nil {
			log.Error("Failed to initialise and unseal Vault", zap.Error(err))
			return err
		}
		if initRes == nil {
			log.Warn("Vault already initialized — skipping root-token workflows")
			return fmt.Errorf("vault already initialized: no root token available")
		}

		/* Enable file audit */
		log.Info("[1/7] Enabling file audit")
		if err := vault.EnableFileAudit(client, log); err != nil {
			log.Error("Failed to enable file audit", zap.Error(err))
			return err
		}
		log.Info("✅ File audit enabled successfully")

		/* Enable KV v2 */
		log.Info("[2/7] Enabling KV v2 secrets engine")
		if err := vault.EnableKV2(client, log); err != nil {
			log.Error("KV v2 setup failed", zap.Error(err))
		}

		/* Test KV write/read */
		log.Info("[3/7] Testing KV put/get")
		if err := vault.TestKVSecret(client); err != nil {
			log.Error("KV secret test failed", zap.Error(err))
		}

		/* Enable AppRole */
		log.Info("[4/7] Enabling AppRole auth method")
		if err := vault.EnableAppRole(client); err != nil {
			log.Error("AppRole setup failed", zap.Error(err))
			return err
		}

		// 8. Enable userpass
		log.Info("[5/7] Enabling userpass auth method")
		if err := vault.EnableUserPass(client); err != nil {
			log.Error("Userpass setup failed", zap.Error(err))
			return err
		}

		// 9. Create eos user
		log.Info("[6/7] Creating eos user and storing secrets")
		if err := vault.CreateEosAndSecret(client, initRes); err != nil {
			log.Error("Failed to create eos user or store secrets", zap.Error(err))
			return err
		}

		log.Info("[7/7] Vault enable workflow complete")
		log.Info("\n✅ Vault enable steps completed successfully!")
		log.Info("🔑 Vault has been initialized and unsealed.")
		log.Info("🔐 The eos user's Vault password is stored at /var/lib/eos/secrets/vault-userpass.yaml")
		log.Info("📄 Unseal keys and root token are stored in Vault and also in vault-init.json")
		log.Info("🛡️  It will be deleted after you run: eos secure vault")
		log.Info("🔑  Please copy the unseal keys and root token to a password manager now.")
		log.Info("⚠️ IMPORTANT: Open the Vault Web UI and confirm that:")
		log.Info("   - The eos user exists and can log in")
		log.Info("   - The unseal keys and root token are backed up")
		log.Info("💾 Then move the keys to a password manager and run:")
		log.Info("      eos secure vault")
		log.Info("   to promote the eos user and revoke the root token.")
		log.Info("💬 Or run 'eos secure vault --dry-run' to preview changes before committing.")
		log.Info("📦 A local backup of your Vault init data was written to vault-init.json")

		return nil
	}),
}

func init() {
	EnableCmd.AddCommand(EnableVaultCmd)
}
