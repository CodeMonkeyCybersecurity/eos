package create

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/ldap"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var CreateLDAPCmd = &cobra.Command{
	Use:   "ldap",
	Short: "Create and store LDAP configuration securely",
	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		otelzap.Ctx(rc.Ctx).Info("Starting LDAP creation workflow")

		// Step 1: Load config via layered fallback
		cfg, source, err := ldap.ReadConfig(rc)
		if err != nil {
			otelzap.Ctx(rc.Ctx).Error("Failed to load LDAP config", zap.Error(err))
			return err
		}
		otelzap.Ctx(rc.Ctx).Info("Loaded LDAP config", zap.String("source", source), zap.String("fqdn", cfg.FQDN))

		// Step 2: Optional connection test
		if !noTest {
			if err := ldap.CheckConnection(rc, cfg); err != nil {
				otelzap.Ctx(rc.Ctx).Error("LDAP connection test failed", zap.Error(err))
				return err
			}
			otelzap.Ctx(rc.Ctx).Info("LDAP connection test passed")
		} else {
			otelzap.Ctx(rc.Ctx).Warn("Skipping LDAP connection test")
		}

		// Step 3: Write to Vault
		if err := vault.Write(rc, nil, ldap.VaultLDAPPath, cfg); err != nil {
			otelzap.Ctx(rc.Ctx).Error("Failed to write LDAP config to Vault", zap.String("path", ldap.VaultLDAPPath), zap.Error(err))
			return err
		}
		otelzap.Ctx(rc.Ctx).Info("LDAP config written to Vault", zap.String("path", ldap.VaultLDAPPath))

		return nil
	}),
}

var noTest bool

func init() {
	CreateCmd.AddCommand(CreateLDAPCmd)
}
