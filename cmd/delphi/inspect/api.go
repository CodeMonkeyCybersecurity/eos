// cmd/delphi/inspect/api.go
package inspect

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/delphi"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var (
	showPermissions bool
	showVersion     bool
)

var InspectAPICmd = &cobra.Command{
	Use:   "api",
	Short: "Inspect API details from Delphi (Wazuh)",
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {

		// ✅ Step 2: Toggle ShowSecrets and confirm config
		delphi.ShowSecrets = showSecrets
		cfg, err := delphi.ResolveConfig(rc)
		if err != nil {
			otelzap.Ctx(rc.Ctx).Fatal("Failed to resolve Delphi config", zap.Error(err))
		}

		// ✅ Step 3: Authenticate if needed
		if cfg.Token == "" {
			token, err := delphi.Authenticate(rc, cfg)
			if err != nil {
				fmt.Printf("❌ Authentication failed: %v\n", err)
				os.Exit(1)
			}
			cfg.Token = token
			if err := delphi.WriteConfig(rc, cfg); err != nil {
				otelzap.Ctx(rc.Ctx).Warn("Failed to write config", zap.Error(err))
			}
		}

		// ✅ Step 4: Secret access control
		if !eos_unix.EnforceSecretsAccess(rc.Ctx, showSecrets) {
			return err
		}

		// ✅ Step 5: Execute inspection
		if showPermissions {
			body, code := delphi.GetUserDetails(rc, cfg)
			delphi.HandleAPIResponse("API User Permissions", []byte(body), code)
		} else if showVersion {
			body, code := delphi.AuthenticatedGetJSON(rc, cfg, "/manager/status")
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
