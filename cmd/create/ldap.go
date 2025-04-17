package create

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/ldap"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var CreateLDAPCmd = &cobra.Command{
	Use:   "ldap",
	Short: "Create and store LDAP configuration securely",
	RunE: func(cmd *cobra.Command, args []string) error {

		log.Info("Starting LDAP creation workflow")

		// Step 1: Load config via layered fallback
		cfg, source, err := ldap.ReadLDAPConfig()
		if err != nil {
			return fmt.Errorf("failed to load LDAP config: %w", err)
		}
		log.Info("Loaded LDAP config", zap.String("source", source), zap.String("fqdn", cfg.FQDN))

		// Step 2: Optional connection test
		if !noTest {
			if err := ldap.CheckConnection(cfg); err != nil {
				return fmt.Errorf("LDAP connection test failed: %w", err)
			}
			log.Info("LDAP connection test passed")
		} else {
			log.Warn("Skipping LDAP connection test")
		}

		// Step 3: Write to Vault
		if err := vault.Write(nil, ldap.VaultLDAPPath, cfg, log); err != nil {
			return fmt.Errorf("failed to write LDAP config to Vault: %w", err)
		}
		log.Info("LDAP config written to Vault", zap.String("path", "eos/ldap/config"))

		return nil
	},
}

var noTest bool

func init() {
	CreateCmd.AddCommand(CreateLDAPCmd)
}
