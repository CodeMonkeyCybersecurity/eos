// cmd/wazuh/read/api.go
package read

import (
	"os"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/wazuh"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// TODO move to pkg/ to DRY up this code base but putting it with other similar functions
var (
	showPermissions bool
	showVersion     bool
)

var ReadAPICmd = &cobra.Command{
	Use:   "api",
	Short: "Read API details from Wazuh (Wazuh)",
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {

		//  Step 2: Toggle ShowSecrets and confirm config
		wazuh.ShowSecrets = showSecrets
		cfg, err := wazuh.ResolveConfig(rc)
		if err != nil {
			otelzap.Ctx(rc.Ctx).Fatal("Failed to resolve Wazuh config", zap.Error(err))
		}

		//  Step 3: Authenticate if needed
		if cfg.Token == "" {
			token, err := wazuh.Authenticate(rc, cfg)
			if err != nil {
				otelzap.Ctx(rc.Ctx).Info("terminal prompt: Authentication failed", zap.Error(err))
				os.Exit(1)
			}
			cfg.Token = token
			if err := wazuh.WriteConfig(rc, cfg); err != nil {
				otelzap.Ctx(rc.Ctx).Warn("Failed to write config", zap.Error(err))
			}
		}

		//  Step 4: Secret access control
		if !eos_unix.EnforceSecretsAccess(rc.Ctx, showSecrets) {
			return err
		}

		//  Step 5: Execute read operation
		if showPermissions {
			body, code := wazuh.GetUserDetails(rc, cfg)
			wazuh.HandleAPIResponse("API User Permissions", []byte(body), code)
		} else if showVersion {
			body, code := wazuh.AuthenticatedGetJSON(rc, cfg, "/manager/status")
			wazuh.HandleAPIResponse("Wazuh Manager Version", []byte(body), code)
		} else {
			otelzap.Ctx(rc.Ctx).Info("terminal prompt: No flags provided. Use --permissions or --version to query specific information.")
		}
		return nil
	}),
}

func init() {
	readWazuhCmd.AddCommand(ReadAPICmd)
	ReadAPICmd.Flags().BoolVar(&showSecrets, "show-secrets", false, "Display sensitive fields like password and token")
	ReadAPICmd.Flags().BoolVar(&showPermissions, "permissions", false, "Display user permissions")
	ReadAPICmd.Flags().BoolVar(&showVersion, "version", false, "Display Wazuh manager version")
}
