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

var (
	realm, kcAdminURL, kcToken, outFile string
	withClients, withGroupsAndRoles     bool
)

var KeycloakCmd = &cobra.Command{
	Use:   "keycloak",
	Short: "Export a Keycloak realm (partial-export) to JSON",
	RunE:  eos.Wrap(runKeycloakExport),
	Example: `eos inspect keycloak --realm demo \
  --kc-admin-url https://sso.dev.local \
  KC_ADMIN_TOKEN=$(cat /run/secrets/kc_token) eos …`,
}

func init() {
	KeycloakCmd.Flags().StringVar(&realm, "realm", "", "Realm name (required)")
	KeycloakCmd.MarkFlagRequired("realm")

	KeycloakCmd.Flags().BoolVar(&withClients, "clients", true, "Include clients")
	KeycloakCmd.Flags().BoolVar(&withGroupsAndRoles, "groups-roles", true, "Include groups & roles")

	KeycloakCmd.Flags().StringVar(&kcAdminURL, "kc-admin-url", os.Getenv("KC_ADMIN_URL"), "Admin base URL")
	KeycloakCmd.Flags().StringVar(&kcToken, "kc-token", os.Getenv("KC_ADMIN_TOKEN"), "Bearer token")

	KeycloakCmd.Flags().StringVar(&outFile, "out", "", "Override output path")
}

func runKeycloakExport(rc *eos_io.RuntimeContext, _ *cobra.Command, _ []string) error {
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
	defer resp.Body.Close()
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
	defer fd.Close()
	n, err := io.Copy(fd, resp.Body)
	if err != nil {
		return err
	}
	l.Info("Realm exported",
		zap.String("file", outFile),
		zap.Int64("bytes", n),
	)
	return nil
}
