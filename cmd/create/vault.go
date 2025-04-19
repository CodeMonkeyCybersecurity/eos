// cmd/create/vault.go
package create

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var CreateVaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Installs and initializes HashiCorp Vault in production mode",
	RunE: eos.Wrap(func(ctx *eos.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := zap.L()

		// 0️⃣  Must be Debian or RHEL
		if err := platform.RequireLinuxDistro([]string{"debian", "rhel"}, log); err != nil {
			log.Fatal("Unsupported OS/distro for Vault deployment", zap.Error(err))
		}

		// 1️⃣  Auto‐detect & export VAULT_ADDR
		addr, err := vault.EnsureVaultEnv(log)
		if err != nil {
			log.Error("Failed to set VAULT_ADDR", zap.Error(err))
			return err
		}
		log.Info("✅ VAULT_ADDR resolved", zap.String("VAULT_ADDR", addr))

		// 2️⃣  Write the agent HCL template
		log.Info("📝 Writing Vault Agent configuration", zap.String("templateAddr", addr))
		if err := vault.EnsureAgentConfig(addr, log); err != nil {
			log.Error("Failed to write Vault Agent config", zap.Error(err))
			return err
		}

		// 3️⃣  Trust our self‑signed CA system‑wide
		distro := platform.DetectLinuxDistro(log)
		log.Info("🔐 Adding Vault CA to system trust", zap.String("distro", distro))
		switch distro {
		case "debian", "ubuntu":
			log.Debug("📥 Invoking Debian CA trust helper")
			if err := vault.TrustVaultCADebian(log); err != nil {
				log.Error("Could not trust Vault CA on Debian/Ubuntu", zap.Error(err))
				return fmt.Errorf("debian CA trust: %w", err)
			}
		default:
			log.Debug("📥 Invoking RHEL CA trust helper")
			if err := vault.TrustVaultCA(log); err != nil {
				log.Error("Could not trust Vault CA on RHEL‑family", zap.Error(err))
				return fmt.Errorf("rhel CA trust: %w", err)
			}
		}
		log.Info("✅ Vault CA is now trusted system‑wide")

		// 4️⃣  Fire off the full Vault installation+init
		log.Info("🔐 Running full Vault setup via EnsureVault(...)")
		if err := vault.EnsureVault("bootstrap/test", map[string]string{"status": "ok"}, log); err != nil {
			log.Error("Vault setup failed", zap.Error(err))
			return err
		}
		log.Info("✅ Vault install & initialization complete")
		return nil
	}),
}

func init() {
	CreateCmd.AddCommand(CreateVaultCmd)
}
