// cmd/delphi/inspect/api.go
package inspect

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/delphi"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/utils"
	"github.com/spf13/cobra"
)

var (
	showPermissions bool
	showVersion     bool
)

var InspectAPICmd = &cobra.Command{
	Use:   "api",
	Short: "Inspect API details from Delphi (Wazuh)",
	RunE: eos.Wrap(func(cmd *cobra.Command, args []string) error {
		cfg, err := delphi.LoadDelphiConfig()
		if err != nil {
			fmt.Printf("❌ Error loading Delphi config: %v\n", err)
			os.Exit(1)
		}

		// ✅ Step 2: Toggle ShowSecrets and confirm config
		delphi.ShowSecrets = showSecrets
		cfg = delphi.ConfirmDelphiConfig(cfg)

		// ✅ Step 3: Authenticate if needed
		if cfg.Token == "" {
			token, err := delphi.Authenticate(cfg)
			if err != nil {
				fmt.Printf("❌ Authentication failed: %v\n", err)
				os.Exit(1)
			}
			cfg.Token = token
			_ = delphi.SaveDelphiConfig(cfg)
		}

		// ✅ Step 4: Secret access control
		if !utils.EnforceSecretsAccess(log, showSecrets) {
			return err
		}

		// ✅ Step 5: Execute inspection
		if showPermissions {
			body, code := delphi.GetUserDetails(cfg)
			delphi.HandleAPIResponse("API User Permissions", []byte(body), code)
		} else if showVersion {
			body, code := delphi.AuthenticatedGetJSON(cfg, "/manager/status")
			delphi.HandleAPIResponse("Wazuh Manager Version", []byte(body), code)
		} else {
			fmt.Println("⚠️  No flags provided. Use --permissions or --version to query specific information.")
		}
		return nil
	}),
}

func init() {
	InspectCmd.AddCommand(InspectAPICmd)
	InspectAPICmd.Flags().BoolVar(&showSecrets, "show-secrets", false, "Display sensitive fields like password and token")
	InspectAPICmd.Flags().BoolVar(&showPermissions, "permissions", false, "Display user permissions")
	InspectAPICmd.Flags().BoolVar(&showVersion, "version", false, "Display Wazuh manager version")
}
