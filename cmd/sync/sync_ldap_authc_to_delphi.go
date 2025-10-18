// cmd/wazuh/sync/ldap.go

package sync

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/wazuh"

	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

var SyncWazuhLDAPCmd = &cobra.Command{
	Use:   "ldap",
	Short: "Sync LDAP configuration into Wazuh (Wazuh)",
	Long: `Automates LDAP integration into Wazuh (Wazuh), including:
- certificate download
- config.yml updates
- roles_mapping.yml updates
- role sync
- securityadmin reload`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		cfg, err := wazuh.PromptLDAPDetails(rc)
		if err != nil {
			return fmt.Errorf("failed to collect LDAP details: %w", err)
		}

		if err := wazuh.CheckLDAPGroupsExist(cfg); err != nil {
			return fmt.Errorf("LDAP group validation failed: %w", err)
		}

		if err := wazuh.DownloadAndPlaceCert(cfg.FQDN); err != nil {
			return fmt.Errorf("failed to download LDAP cert: %w", err)
		}

		if err := wazuh.PatchConfigYML(rc, cfg); err != nil {
			return fmt.Errorf("failed to patch config.yml: %w", err)
		}

		if err := wazuh.PatchRolesMappingYML(rc, cfg); err != nil {
			return fmt.Errorf("failed to patch roles_mapping.yml: %w", err)
		}

		if err := wazuh.RunSecurityAdmin("config.yml"); err != nil {
			return fmt.Errorf("failed to apply config.yml: %w", err)
		}

		if err := wazuh.RunSecurityAdmin("roles_mapping.yml"); err != nil {
			return fmt.Errorf("failed to apply roles_mapping.yml: %w", err)
		}

		if err := wazuh.RestartDashboard(); err != nil {
			return fmt.Errorf("failed to restart wazuh-dashboard: %w", err)
		}

		logger.Info("terminal prompt:  LDAP configuration synced to Wazuh successfully!")
		logger.Info("terminal prompt:  Please test logging in to the Wazuh dashboard using your LDAP credentials.")
		return nil
	}),
}

func init() {
	SyncCmd.AddCommand(SyncWazuhLDAPCmd)
}
