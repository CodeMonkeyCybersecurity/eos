// cmd/delphi/inspect/api.go
package inspect

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/delphi"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/utils"
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
	RunE: eos.Wrap(func(ctx *eos.RuntimeContext, cmd *cobra.Command, args []string) error {

		// ✅ Step 2: Toggle ShowSecrets and confirm config
		delphi.ShowSecrets = showSecrets
		cfg, err := delphi.ResolveConfig(log)
		if err != nil {
			log.Fatal("Failed to resolve Delphi config", zap.Error(err))
		}

		// ✅ Step 3: Authenticate if needed
		if cfg.Token == "" {
			token, err := delphi.Authenticate(cfg)
			if err != nil {
				fmt.Printf("❌ Authentication failed: %v\n", err)
				os.Exit(1)
			}
			cfg.Token = token
			_ = delphi.WriteConfig(cfg, log)
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
