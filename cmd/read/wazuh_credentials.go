// cmd/wazuh/read/credentials.go
package read

import (
	"encoding/json"
	"net/http"
	"os"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/wazuh"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var ReadCredentialsCmd = &cobra.Command{
	Use:   "credentials",
	Short: "List all Wazuh (Wazuh) user credentials",
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {

		cfg, err := wazuh.ResolveConfig(rc)
		if err != nil {
			otelzap.Ctx(rc.Ctx).Fatal("Failed to resolve Wazuh config", zap.Error(err))
		}

		if !eos_unix.EnforceSecretsAccess(rc.Ctx, showSecrets) {
			return nil
		}

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

		resp, err := wazuh.AuthenticatedGet(cfg, "/security/users")
		if err != nil {
			otelzap.Ctx(rc.Ctx).Info("terminal prompt: Failed to fetch users", zap.Error(err))
			os.Exit(1)
		}
		defer shared.SafeClose(rc.Ctx, resp.Body)

		if resp.StatusCode != http.StatusOK {
			otelzap.Ctx(rc.Ctx).Info("terminal prompt: Failed with status code", zap.Int("code", resp.StatusCode))
			os.Exit(1)
		}

		var result struct {
			Data struct {
				Users []struct {
					Username string `json:"username"`
					Role     string `json:"role"`
					Active   bool   `json:"active"`
				} `json:"affected_items"`
			} `json:"data"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			otelzap.Ctx(rc.Ctx).Info("terminal prompt: Failed to parse response", zap.Error(err))
			os.Exit(1)
		}

		otelzap.Ctx(rc.Ctx).Info("terminal prompt: Wazuh API Users")
		for _, user := range result.Data.Users {
			status := "disabled"
			if user.Active {
				status = "active"
			}
			otelzap.Ctx(rc.Ctx).Info("terminal prompt: User",
				zap.String("username", user.Username),
				zap.String("role", user.Role),
				zap.String("status", status))
		}
		return nil
	}),
}

func init() {
	readWazuhCmd.AddCommand(ReadCredentialsCmd)
	ReadCredentialsCmd.Flags().BoolVar(&showSecrets, "show-secrets", false, "Display sensitive fields like password and token")
}
