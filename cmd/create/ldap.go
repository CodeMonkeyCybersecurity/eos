package create

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/ldap"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var CreateLDAPCmd = &cobra.Command{
	Use:   "ldap",
	Short: "Create and store LDAP configuration securely",
	RunE: func(cmd *cobra.Command, args []string) error {
		zap.L().Info("Starting LDAP creation workflow")

		// Step 1: Load config via layered fallback
		cfg, source, err := ldap.ReadConfig()
		if err != nil {
			zap.L().Error("Failed to load LDAP config", zap.Error(err))
			return err
		}
		zap.L().Info("Loaded LDAP config", zap.String("source", source), zap.String("fqdn", cfg.FQDN))

		// Step 2: Optional connection test
		if !noTest {
			if err := ldap.CheckConnection(cfg); err != nil {
				zap.L().Error("LDAP connection test failed", zap.Error(err))
				return err
			}
			zap.L().Info("LDAP connection test passed")
		} else {
			zap.L().Warn("Skipping LDAP connection test")
		}

		// Step 3: Write to Vault
		if err := vault.Write(nil, ldap.VaultLDAPPath, cfg); err != nil {
			zap.L().Error("Failed to write LDAP config to Vault", zap.String("path", ldap.VaultLDAPPath), zap.Error(err))
			return err
		}
		zap.L().Info("LDAP config written to Vault", zap.String("path", ldap.VaultLDAPPath))

		return nil
	},
}

var noTest bool

func init() {
	CreateCmd.AddCommand(CreateLDAPCmd)
}
