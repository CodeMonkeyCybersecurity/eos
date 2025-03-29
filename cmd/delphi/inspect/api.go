// cmd/delphi/inspect/api.go
package inspect

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/config"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/delphi"
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
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := config.LoadDelphiConfig()
		if err != nil {
			fmt.Printf("❌ Error loading Delphi config: %v\n", err)
			os.Exit(1)
		}
		cfg = config.ConfirmDelphiConfig(cfg)

		if cfg.Token == "" {
			token, err := delphi.Authenticate(cfg)
			if err != nil {
				fmt.Printf("❌ Authentication failed: %v\n", err)
				os.Exit(1)
			}
			cfg.Token = token
			_ = config.SaveDelphiConfig(cfg)
		}

		if !utils.EnforceSecretsAccess(log, showSecrets) {
			return
		}

		if showPermissions {
			body, code := delphi.GetUserDetails(cfg)
			delphi.HandleAPIResponse("API User Permissions", body, code)
		} else if showVersion {
			body, code := delphi.AuthenticatedGetJSON(cfg, "/manager/status")
			delphi.HandleAPIResponse("Wazuh Manager Version", body, code)
		} else {
			fmt.Println("⚠️  No flags provided. Use --permissions or --version to query specific information.")
		}
	},
}

func init() {
	InspectAPICmd.Flags().BoolVar(&showPermissions, "permissions", false, "Display user permissions")
	InspectAPICmd.Flags().BoolVar(&showVersion, "version", false, "Display Wazuh manager version")
}
