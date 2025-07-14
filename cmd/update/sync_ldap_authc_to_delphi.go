// cmd/delphi/sync/ldap.go

package update

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/delphi"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"

	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

var SyncDelphiLDAPCmd = &cobra.Command{
	Use:   "ldap",
	Short: "Sync LDAP configuration into Delphi (Wazuh)",
	Long: `Automates LDAP integration into Wazuh (Delphi), including:
- certificate download
- config.yml updates
- roles_mapping.yml updates
- role sync
- securityadmin reload`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		cfg, err := delphi.PromptLDAPDetails(rc)
		if err != nil {
			return fmt.Errorf("failed to collect LDAP details: %w", err)
		}

		if err := delphi.CheckLDAPGroupsExist(cfg); err != nil {
			return fmt.Errorf("LDAP group validation failed: %w", err)
		}

		if err := delphi.DownloadAndPlaceCert(cfg.FQDN); err != nil {
			return fmt.Errorf("failed to download LDAP cert: %w", err)
		}

		if err := delphi.PatchConfigYML(cfg); err != nil {
			return fmt.Errorf("failed to patch config.yml: %w", err)
		}

		if err := delphi.PatchRolesMappingYML(cfg); err != nil {
			return fmt.Errorf("failed to patch roles_mapping.yml: %w", err)
		}

		if err := delphi.RunSecurityAdmin("config.yml"); err != nil {
			return fmt.Errorf("failed to apply config.yml: %w", err)
		}

		if err := delphi.RunSecurityAdmin("roles_mapping.yml"); err != nil {
			return fmt.Errorf("failed to apply roles_mapping.yml: %w", err)
		}

		if err := delphi.RestartDashboard(); err != nil {
			return fmt.Errorf("failed to restart wazuh-dashboard: %w", err)
		}

		logger.Info("terminal prompt:  LDAP configuration synced to Delphi successfully!")
		logger.Info("terminal prompt:  Please test logging in to the Wazuh dashboard using your LDAP credentials.")
		return nil
	}),
}

func init() {
	UpdateCmd.AddCommand(SyncDelphiLDAPCmd)
}
