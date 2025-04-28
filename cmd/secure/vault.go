package secure

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
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
	RunE: eoscli.Wrap(func(ctx *eoscli.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := ctx.Log.Named("secure-vault")

		log.Info("🔐 Connecting to Vault")
		client, err := vault.EnsureVaultReady(log)
		if err != nil {
			return logger.LogErrAndWrap(log, "secure vault: connect failed", err)
		}

		if vault.IsVaultSealed(client, log) {
			return fmt.Errorf("vault is sealed — please run `eos enable vault` before `secure vault`")
		}

		// 1️⃣ Ensure EOS Policy
		log.Info("📜 Ensuring eos-policy exists")
		if err := vault.EnsurePolicy(client, log); err != nil {
			return logger.LogErrAndWrap(log, "secure vault: ensure policy", err)
		}

		// 2️⃣ Enable auth methods if needed
		log.Info("🪪 Ensuring AppRole auth method is enabled")
		opts := vault.EnableOptions{
			Password: "", // TODO: replace with real password fallback
		}
		if err := vault.EnableVault(client, log, opts); err != nil {
			return logger.LogErrAndWrap(log, "secure vault: enable auth methods", err)
		}

		// 3️⃣ Re-provision AppRole
		log.Info("🔁 Re-confirming AppRole settings")
		roleID, secretID, err := vault.EnsureAppRole(client, log, vault.DefaultAppRoleOptions())
		if err != nil {
			return logger.LogErrAndWrap(log, "secure vault: create approle", err)
		}
		if err := vault.WriteAppRoleFiles(roleID, secretID, log); err != nil {
			return logger.LogErrAndWrap(log, "secure vault: write approle creds", err)
		}
		log.Info("✅ AppRole credentials written", zap.String("role_id", roleID), zap.String("secret_id", secretID))

		// 4️⃣ Validate Vault Agent token
		log.Info("🤖 Validating Vault Agent token")
		token, err := vault.WaitForAgentToken(shared.VaultTokenSinkPath, log)
		if err != nil {
			return fmt.Errorf("vault-agent token check failed: %w", err)
		}
		if err := vault.VerRootToken(client, token); err != nil {
			return fmt.Errorf("invalid Vault agent token: %w", err)
		}
		vault.SetVaultToken(client, token)

		// 5️⃣ Optionally revoke root token
		shouldRevoke, err := cmd.Flags().GetBool("revoke-root")
		if err != nil {
			return fmt.Errorf("could not read --revoke-root flag: %w", err)
		}
		if shouldRevoke {
			log.Warn("🚨 Revoking root token (irreversible)")
			if err := vault.RevokeRootToken(client, "", log); err != nil {
				return logger.LogErrAndWrap(log, "secure vault: revoke root", err)
			}
		}

		// 📋 Final summary
		log.Info("🔒 Vault hardening completed successfully",
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
