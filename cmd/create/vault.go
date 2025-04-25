// cmd/create/vault.go
package create

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// CreateVaultCmd sets up HashiCorp Vault with TLS, HCL config, and systemd unit.
// It does not perform initialization or unseal — run `eos enable vault` afterward.
// This phase ensures Vault is installed, running, and ready for secure provisioning.
var CreateVaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Installs Vault with TLS and systemd service (no init/unseal)",
	RunE: eos.Wrap(func(ctx *eos.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := zap.L()

		log.Info("🚀 [1/6] Verifying platform requirements")
		if err := platform.RequireLinuxDistro([]string{"debian", "rhel"}, log); err != nil {
			log.Fatal("Unsupported OS/distro", zap.Error(err))
		}

		log.Info("🌍 Resolving Vault environment address")
		addr, err := vault.EnsureVaultEnv(log)
		if err != nil {
			return logger.LogErrAndWrap(log, "create vault: set VAULT_ADDR", err)
		}
		log.Info("✅ VAULT_ADDR resolved", zap.String("VAULT_ADDR", addr))

		log.Info("👤 [2/6] Ensuring eos system user")
		if err := system.EnsureEosUser(true, false, log); err != nil {
			return logger.LogErrAndWrap(log, "create vault: ensure eos user", err)
		}

		log.Info("📁 [3/6] Preparing Vault filesystem")
		if err := vault.EnsureVaultDirs(log); err != nil {
			return logger.LogErrAndWrap(log, "create vault: ensure dirs", err)
		}

		log.Info("🔐 [4/6] Generating TLS certificates")
		log.Warn("⚠️ Vault TLS cert will be self-signed. Use --cert/--key to override.")
		log.Warn("⚠️ This certificate is valid only for local development. Do not use in production.")
		// Consider user confirmation in interactive mode later
		if err := vault.GenerateVaultTLSCert(log); err != nil {
			return logger.LogErrAndWrap(log, "create vault: generate TLS", err)
		}
		if err := vault.TrustVaultCA(log); err != nil {
			return logger.LogErrAndWrap(log, "create vault: trust CA", err)
		}

		log.Info("⚙️ [5/6] Writing vault.hcl config")
		if err := vault.WriteVaultHCL(log); err != nil {
			return logger.LogErrAndWrap(log, "create vault: write config", err)
		}

		log.Info("🧱 [6/6] Starting Vault systemd service")
		if err := vault.StartVaultService(log); err != nil {
			return logger.LogErrAndWrap(log, "create vault: start service", err)
		}
		log.Info("✅ Phase 6 complete: Vault initialized and ready to unseal")

		log.Info("🩺 Verifying Vault health after service start")
		if status, err := vault.CheckVaultHealth(log); err != nil {
			log.Error("🚨 Vault service started but health check failed", zap.String("status", status), zap.Error(err))
			return fmt.Errorf("vault health check: %w", err)
		}

		// It does not initialize or unseal Vault — see `enable vault` for that.
		log.Info("ℹ️  Note: Vault is not yet initialized or unsealed. Run `eos enable vault` next.")

		log.Info("✅ Vault installation complete — ready for initialization (`enable vault`)")
		return nil
	}),
}

func init() {
	CreateCmd.AddCommand(CreateVaultCmd)
}
