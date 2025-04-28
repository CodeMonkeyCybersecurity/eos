// cmd/delphi/inspect/credentials.go
package read

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/delphi"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/utils"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var InspectCredentialsCmd = &cobra.Command{
	Use:   "credentials",
	Short: "List all Delphi (Wazuh) user credentials",
	RunE: eos.Wrap(func(ctx *eos.RuntimeContext, cmd *cobra.Command, args []string) error {

		cfg, err := delphi.ResolveConfig(log)
		if err != nil {
			log.Fatal("Failed to resolve Delphi config", zap.Error(err))
		}

		if !utils.EnforceSecretsAccess(log, showSecrets) {
			return nil
		}

		if cfg.Token == "" {
			token, err := delphi.Authenticate(cfg, log)
			if err != nil {
				fmt.Printf("❌ Authentication failed: %v\n", err)
				os.Exit(1)
			}
			cfg.Token = token
			if err := delphi.WriteConfig(cfg, log); err != nil {
				log.Warn("Failed to write config", zap.Error(err))
			}
		}

		resp, err := delphi.AuthenticatedGet(cfg, "/security/users")
		if err != nil {
			fmt.Printf("❌ Failed to fetch users: %v\n", err)
			os.Exit(1)
		}
		defer shared.SafeClose(resp.Body, log)

		if resp.StatusCode != http.StatusOK {
			fmt.Printf("❌ Failed with status code: %d\n", resp.StatusCode)
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
			fmt.Printf("❌ Failed to parse response: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("🔐 Delphi API Users:")
		for _, user := range result.Data.Users {
			status := "disabled"
			if user.Active {
				status = "active"
			}
			fmt.Printf("  • %-15s | Role: %-10s | Status: %s\n", user.Username, user.Role, status)
		}
		return nil
	}),
}

func init() {
	ReadCmd.AddCommand(InspectCredentialsCmd)
	InspectCredentialsCmd.Flags().BoolVar(&showSecrets, "show-secrets", false, "Display sensitive fields like password and token")
}
