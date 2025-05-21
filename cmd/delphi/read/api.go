// cmd/delphi/inspect/api.go
package read

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/debian"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/delphi"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eosio"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var (
	showPermissions bool
	showVersion     bool
)

var InspectAPICmd = &cobra.Command{
	Use:   "api",
	Short: "Inspect API details from Delphi (Wazuh)",
	RunE: eos.Wrap(func(ctx *eosio.RuntimeContext, cmd *cobra.Command, args []string) error {

		// ✅ Step 2: Toggle ShowSecrets and confirm config
		delphi.ShowSecrets = showSecrets
		cfg, err := delphi.ResolveConfig()
		if err != nil {
			zap.L().Fatal("Failed to resolve Delphi config", zap.Error(err))
		}

		// ✅ Step 3: Authenticate if needed
		if cfg.Token == "" {
			token, err := delphi.Authenticate(cfg)
			if err != nil {
				fmt.Printf("❌ Authentication failed: %v\n", err)
				os.Exit(1)
			}
			cfg.Token = token
			if err := delphi.WriteConfig(cfg); err != nil {
				zap.L().Warn("Failed to write config", zap.Error(err))
			}
		}

		// ✅ Step 4: Secret access control
		if !debian.EnforceSecretsAccess(showSecrets) {
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
	ReadCmd.AddCommand(InspectAPICmd)
	InspectAPICmd.Flags().BoolVar(&showSecrets, "show-secrets", false, "Display sensitive fields like password and token")
	InspectAPICmd.Flags().BoolVar(&showPermissions, "permissions", false, "Display user permissions")
	InspectAPICmd.Flags().BoolVar(&showVersion, "version", false, "Display Wazuh manager version")
}
