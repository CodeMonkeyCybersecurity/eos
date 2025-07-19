// cmd/read/keycloak.go
package read

import (
	"fmt"
	"io"
	"net/http"
	"os"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/exportutil"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// TODO move to pkg/ to DRY up this code base but putting it with other similar functions
var (
	realm, kcAdminURL, kcToken, outFile string
	withClients, withGroupsAndRoles     bool
)

var KeycloakCmd = &cobra.Command{
	Use:        "keycloak",
	Short:      "Export a Keycloak realm (partial-export) to JSON (DEPRECATED - use 'authentik' instead)",
	Deprecated: "Keycloak support is deprecated. Use 'eos read authentik' for reading Authentik configurations instead.",
	Long: `DEPRECATED: This command is deprecated and will be removed in a future version.
Use 'eos read authentik' for reading Authentik configurations instead.

Keycloak has been replaced with Authentik for identity and access management.

Migration:
  # Instead of: eos read keycloak --realm=master
  # Use:        eos read authentik --tenant=default

This command will still work for existing Keycloak installations but shows a deprecation warning.

---

Export a Keycloak realm configuration to JSON format.

This command performs a partial export of a Keycloak realm, which includes
the realm settings, authentication flows, identity providers, and optionally
clients, groups, and roles.

Features:
  - Exports realm configuration via Keycloak Admin API
  - Optionally includes clients configuration
  - Optionally includes groups and roles
  - Saves to timestamped JSON file
  - Supports custom output paths

Examples:
  # Export realm with all components
  eos read keycloak --realm demo --kc-admin-url https://sso.example.com
  
  # Export realm without clients
  eos read keycloak --realm demo --clients=false
  
  # Export with environment variables
  export KC_ADMIN_URL=https://sso.example.com
  export KC_ADMIN_TOKEN=your-bearer-token
  eos read keycloak --realm demo
  
  # Export to custom path
  eos read keycloak --realm demo --out /path/to/realm-export.json`,
	Example: `eos inspect keycloak --realm demo \
  --kc-admin-url https://sso.dev.local \
  KC_ADMIN_TOKEN=$(cat /run/secrets/kc_token) eos …`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, _ *cobra.Command, _ []string) error {
		l := otelzap.Ctx(rc.Ctx)
		if kcAdminURL == "" || kcToken == "" {
			return fmt.Errorf("kc-admin-url and kc-token are required (can come from env)")
		}
		url := fmt.Sprintf("%s/admin/realms/%s/partial-export?exportClients=%t&exportGroupsAndRoles=%t",
			kcAdminURL, realm, withClients, withGroupsAndRoles)

		req, _ := http.NewRequestWithContext(rc.Ctx, http.MethodPost, url, nil)
		req.Header.Set("Authorization", "Bearer "+kcToken)
		req.Header.Set("Content-Type", "application/json")

		l.Info("Keycloak export", zap.String("url", url), zap.String("token", kcToken[:6]+"…"))

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		defer func() {
			if err := resp.Body.Close(); err != nil {
				l.Warn("Failed to close response body", zap.Error(err))
			}
		}()
		if resp.StatusCode != http.StatusOK {
			buf, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			return fmt.Errorf("keycloak export failed: %s – %s", resp.Status, string(buf))
		}

		if outFile == "" {
			if err := exportutil.EnsureDir(); err != nil {
				return err
			}
			outFile, err = exportutil.Build("keycloak", "json")
			if err != nil {
				return err
			}
		}
		fd, err := os.OpenFile(outFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		defer func() {
			if err := fd.Close(); err != nil {
				l.Warn("Failed to close file", zap.String("file", outFile), zap.Error(err))
			}
		}()
		n, err := io.Copy(fd, resp.Body)
		if err != nil {
			return err
		}
		l.Info("Realm exported",
			zap.String("file", outFile),
			zap.Int64("bytes", n),
		)
		return nil
	}),
}

func init() {
	KeycloakCmd.Flags().StringVar(&realm, "realm", "", "Realm name (required)")
	if err := KeycloakCmd.MarkFlagRequired("realm"); err != nil {
		panic(fmt.Sprintf("Failed to mark realm flag as required: %v", err))
	}

	KeycloakCmd.Flags().BoolVar(&withClients, "clients", true, "Include clients")
	KeycloakCmd.Flags().BoolVar(&withGroupsAndRoles, "groups-roles", true, "Include groups & roles")

	KeycloakCmd.Flags().StringVar(&kcAdminURL, "kc-admin-url", os.Getenv("KC_ADMIN_URL"), "Admin base URL")
	KeycloakCmd.Flags().StringVar(&kcToken, "kc-token", os.Getenv("KC_ADMIN_TOKEN"), "Bearer token")

	KeycloakCmd.Flags().StringVar(&outFile, "out", "", "Override output path")
}
