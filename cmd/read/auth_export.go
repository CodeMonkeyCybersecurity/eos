// cmd/read/auth_export.go

package read

import (
	"fmt"
	"os"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

var (
	authType, authURL, authToken, authOut string
	authRealm, authKcAdminURL, authKcToken string // Legacy Keycloak support
	authAkBaseURL, authAkToken             string // Authentik support
	authWithClients, authWithGroupsAndRoles bool   // Keycloak specific
)

var AuthExportCmd = &cobra.Command{
	Use:   "auth",
	Short: "Export authentication configuration (Authentik blueprints or Keycloak realm)",
	Long: `Export authentication system configuration to local files.

Supports both Authentik (recommended) and Keycloak (deprecated) systems:

Authentik Export:
  - Exports complete Authentik configuration as blueprints
  - Saves to timestamped YAML file
  - Includes flows, policies, property mappings, and providers

Keycloak Export (Deprecated):
  - Performs partial export of Keycloak realm
  - Saves to timestamped JSON file  
  - Optionally includes clients, groups, and roles

Examples:
  # Export Authentik configuration (recommended)
  eos read auth --type authentik --url https://id.example.com --token $AK_TOKEN
  
  # Export Keycloak realm (deprecated)
  eos read auth --type keycloak --realm demo --url https://sso.example.com --token $KC_TOKEN
  
  # Using environment variables
  export AUTH_URL=https://id.example.com
  export AUTH_TOKEN=your-token
  eos read auth --type authentik`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		l := otelzap.Ctx(rc.Ctx)

		// Auto-detect auth type if not specified
		if authType == "" {
			// Try to detect from URL or environment
			if authAkBaseURL != "" || os.Getenv("AK_URL") != "" {
				authType = "authentik"
			} else if authKcAdminURL != "" || os.Getenv("KC_ADMIN_URL") != "" {
				authType = "keycloak"
			} else {
				// Default to Authentik for new deployments
				authType = "authentik"
				l.Info("No auth type specified, defaulting to Authentik (recommended)")
			}
		}

		switch authType {
		case "authentik":
			return exportAuthentik(rc)
		case "keycloak":
			l.Warn("Keycloak support is deprecated. Please migrate to Authentik.")
			return exportKeycloak(rc)
		default:
			return fmt.Errorf("unsupported auth type: %s (supported: authentik, keycloak)", authType)
		}
	}),
}

func exportAuthentik(rc *eos_io.RuntimeContext) error {
	url := authURL
	token := authToken
	if url == "" {
		url = authAkBaseURL
	}
	if token == "" {
		token = authAkToken
	}

	if url == "" || token == "" {
		return fmt.Errorf("URL and token are required for Authentik export (use --url and --token or AK_URL/AK_TOKEN env vars)")
	}

	// Use the existing AuthentikCmd logic
	akBaseURL = url
	akToken = token
	akOut = authOut

	return AuthentikCmd.RunE(AuthentikCmd, []string{})
}

func exportKeycloak(rc *eos_io.RuntimeContext) error {
	url := authURL
	token := authToken
	if url == "" {
		url = authKcAdminURL
	}
	if token == "" {
		token = authKcToken
	}

	if url == "" || token == "" || authRealm == "" {
		return fmt.Errorf("URL, token, and realm are required for Keycloak export (use --url, --token, --realm or KC_ADMIN_URL/KC_ADMIN_TOKEN env vars)")
	}

	// Use the existing KeycloakCmd logic
	kcAdminURL = url
	kcToken = token
	realm = authRealm
	outFile = authOut

	return KeycloakCmd.RunE(KeycloakCmd, []string{})
}

func init() {
	// General flags
	AuthExportCmd.Flags().StringVar(&authType, "type", "", "Auth system type: authentik (recommended) or keycloak (deprecated)")
	AuthExportCmd.Flags().StringVar(&authURL, "url", os.Getenv("AUTH_URL"), "Authentication system base URL")
	AuthExportCmd.Flags().StringVar(&authToken, "token", os.Getenv("AUTH_TOKEN"), "API token")
	AuthExportCmd.Flags().StringVar(&authOut, "out", "", "Override output path")

	// Authentik-specific flags
	AuthExportCmd.Flags().StringVar(&authAkBaseURL, "ak-url", os.Getenv("AK_URL"), "Authentik base URL")
	AuthExportCmd.Flags().StringVar(&authAkToken, "ak-token", os.Getenv("AK_TOKEN"), "Authentik API token")

	// Keycloak-specific flags (deprecated)
	AuthExportCmd.Flags().StringVar(&authRealm, "realm", "", "Keycloak realm name (required for Keycloak)")
	AuthExportCmd.Flags().StringVar(&authKcAdminURL, "kc-admin-url", os.Getenv("KC_ADMIN_URL"), "Keycloak admin URL")
	AuthExportCmd.Flags().StringVar(&authKcToken, "kc-token", os.Getenv("KC_ADMIN_TOKEN"), "Keycloak bearer token")
	AuthExportCmd.Flags().BoolVar(&authWithClients, "clients", true, "Include clients (Keycloak only)")
	AuthExportCmd.Flags().BoolVar(&authWithGroupsAndRoles, "groups-roles", true, "Include groups & roles (Keycloak only)")
}