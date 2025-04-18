// cmd/delphi/sync/ldap.go

package sync

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/delphi"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"

	"github.com/spf13/cobra"
)

var liveRun bool

var SyncDelphiLDAPCmd = &cobra.Command{
	Use:   "ldap",
	Short: "Sync LDAP configuration into Delphi (Wazuh)",
	Long: `Automates LDAP integration into Wazuh (Delphi), including:
- certificate download
- config.yml updates
- roles_mapping.yml updates
- role sync
- securityadmin reload`,
	RunE: eos.Wrap(func(ctx *eos.RuntimeContext, cmd *cobra.Command, args []string) error {
		cfg, err := delphi.PromptLDAPDetails(log)
		if err != nil {
			return fmt.Errorf("failed to collect LDAP details: %w", err)
		}

		if err := delphi.CheckLDAPGroupsExist(cfg, log); err != nil {
			return fmt.Errorf("LDAP group validation failed: %w", err)
		}

		if err := delphi.DownloadAndPlaceCert(cfg.FQDN, log); err != nil {
			return fmt.Errorf("failed to download LDAP cert: %w", err)
		}

		if err := delphi.PatchConfigYML(cfg, log); err != nil {
			return fmt.Errorf("failed to patch config.yml: %w", err)
		}

		if err := delphi.PatchRolesMappingYML(cfg, log); err != nil {
			return fmt.Errorf("failed to patch roles_mapping.yml: %w", err)
		}

		if err := delphi.RunSecurityAdmin("config.yml", log); err != nil {
			return fmt.Errorf("failed to apply config.yml: %w", err)
		}

		if err := delphi.RunSecurityAdmin("roles_mapping.yml", log); err != nil {
			return fmt.Errorf("failed to apply roles_mapping.yml: %w", err)
		}

		if err := delphi.RestartDashboard(log); err != nil {
			return fmt.Errorf("failed to restart wazuh-dashboard: %w", err)
		}

		fmt.Println("✅ LDAP configuration synced to Delphi successfully!")
		fmt.Println("🔐 Please test logging in to the Wazuh dashboard using your LDAP credentials.")
		return nil
	}),
}

func init() {
	SyncCmd.AddCommand(SyncDelphiLDAPCmd)
	SyncDelphiLDAPCmd.Flags().BoolVar(&liveRun, "live-run", false, "Actually apply changes (default is dry-run)")
}
