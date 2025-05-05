package secure

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eosio"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// SecureVaultCmd performs post-init hardening of Vault.
// This includes AppRole setup, Vault Agent token validation,
// and optional root token revocation.
var SecureVaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Applies hardening and provisioning to a running Vault instance",
	RunE: eoscli.Wrap(func(ctx *eosio.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := ctx.Log.Named("secure-vault")

		zap.L().Info("🔐 Connecting to Vault")
		client, err := vault.EnsureVaultReady()
		if err != nil {
			return logger.LogErrAndWrap("secure vault: connect failed", err)
		}

		if vault.IsVaultSealed(client) {
			return fmt.Errorf("vault is sealed — please run `eos enable vault` before `secure vault`")
		}

		// 1️⃣ Ensure EOS Policy
		zap.L().Info("📜 Ensuring eos-policy exists")
		if err := vault.EnsurePolicy(); err != nil {
			return logger.LogErrAndWrap("secure vault: ensure policy", err)
		}

		if err := vault.EnableVault(client, log); err != nil {
			return logger.LogErrAndWrap("secure vault: enable auth methods", err)
		}

		// 3️⃣ Re-provision AppRole
		zap.L().Info("🔁 Re-confirming AppRole settings")
		roleID, secretID, err := vault.EnsureAppRole(client, shared.DefaultAppRoleOptions())
		if err != nil {
			return logger.LogErrAndWrap("secure vault: create approle", err)
		}
		if err := vault.WriteAppRoleFiles(roleID, secretID); err != nil {
			return logger.LogErrAndWrap("secure vault: write approle creds", err)
		}
		zap.L().Info("✅ AppRole credentials written", zap.String("role_id", roleID), zap.String("secret_id", secretID))

		// 4️⃣ Validate Vault Agent token
		zap.L().Info("🤖 Validating Vault Agent token")
		token, err := vault.WaitForAgentToken(shared.VaultTokenSinkPath, shared.MaxWait)
		if err != nil {
			return fmt.Errorf("vault-agent token check failed: %w", err)
		}
		if err := vault.VerifyRootToken(client, token); err != nil {
			return fmt.Errorf("invalid Vault agent token: %w", err)
		}
		vault.SetVaultToken(client, token)

		// 5️⃣ Optionally revoke root token
		shouldRevoke, err := cmd.Flags().GetBool("revoke-root")
		if err != nil {
			return fmt.Errorf("could not read --revoke-root flag: %w", err)
		}
		if shouldRevoke {
			zap.L().Warn("🚨 Revoking root token (irreversible)")
			if err := vault.RevokeRootToken(client, ""); err != nil {
				return logger.LogErrAndWrap("secure vault: revoke root", err)
			}
		}

		// 📋 Final summary
		zap.L().Info("🔒 Vault hardening completed successfully",
			zap.Bool("vault_hardened", true),
			zap.Bool("root_token_revoked", shouldRevoke),
		)

		return nil
	}),
}

func init() {
	SecureVaultCmd.Flags().Bool("revoke-root", false, "Revoke the root token after agent token is validated")
	SecureCmd.AddCommand(SecureVaultCmd)
}
