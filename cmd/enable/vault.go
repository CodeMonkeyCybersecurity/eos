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
		log.Info("[0/7] Starting Vault enable workflow")

		// 0. Ensure Vault is installed
		if err := vault.InstallVaultViaDnf(log); err != nil {
			log.Error("Failed to install Vault", zap.Error(err))
			return err
		}

		// 1. Set VAULT_ADDR
		addr, err := vault.EnsureVaultAddr(log)
		if err != nil {
			log.Error("Failed to set VAULT_ADDR", zap.Error(err))
			return err
		}
		log.Info("Set VAULT_ADDR from hostname", zap.String("VAULT_ADDR", addr))

		// 2. Ensure Vault Agent is running (before attempting client connection)
		if err := vault.EnsureVaultAgentRunning(log); err != nil {
			log.Warn("Vault Agent not ready, some operations may fail", zap.Error(err))
		}

		// 3. Get Vault client
		client, err := vault.NewClient(log)
		if err != nil {
			log.Fatal("Failed to create Vault client", zap.Error(err))
		}

		client, initRes, err := vault.SetupVault(client, log)
		if err != nil {
			log.Error("Failed to initialize and unseal Vault", zap.Error(err))
			return err
		}
		if initRes == nil {
			log.Warn("Vault already initialized — skipping root-token workflows")
			return fmt.Errorf("vault already initialized: no root token available")
		}

		// Remaining steps
		log.Info("[1/7] Enabling file audit")
		if err := vault.EnableFileAudit(client, log); err != nil {
			log.Error("Failed to enable file audit", zap.Error(err))
			return err
		}
		log.Info("✅ File audit enabled successfully")

		log.Info("[2/7] Enabling KV v2 secrets engine")
		if err := vault.EnableKV2(client, log); err != nil {
			log.Error("KV v2 setup failed", zap.Error(err))
		}

		log.Info("[3/7] Testing KV put/get")
		report, _ := vault.Check(client, log, nil, "")
		if report == nil || !report.KVWorking {
			log.Error("KV secret test failed or unavailable")
		}

		log.Info("[4/7] Ensuring AppRole auth method")
		if err := vault.EnsureAppRole(client, log); err != nil {
			log.Error("AppRole setup failed", zap.Error(err))
			return err
		}

		log.Info("[5/7] Enabling userpass auth method")
		if err := vault.EnableUserPass(client); err != nil {
			log.Error("Userpass setup failed", zap.Error(err))
			return err
		}

		log.Info("[6/7] Ensuring eos user exists and storing secrets")
		if err := vault.EnsureEosVaultUser(client, log); err != nil {
			log.Error("Failed to create eos user or store secrets", zap.Error(err))
			return err
		}

		log.Info("[7/7] Vault enable workflow complete")
		fmt.Println("\n✅ Vault enable steps completed successfully!")
		return nil
	}),
}

func init() {
	EnableCmd.AddCommand(EnableVaultCmd)
}
