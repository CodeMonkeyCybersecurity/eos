// cmd/delphi/inspect/credentials.go
package inspect

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/delphi"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/utils"
	"github.com/spf13/cobra"
)

var InspectCredentialsCmd = &cobra.Command{
	Use:   "credentials",
	Short: "List all Delphi (Wazuh) user credentials",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := delphi.LoadDelphiConfig()
		if err != nil {
			fmt.Printf("❌ Error loading Delphi config: %v\n", err)
			os.Exit(1)
		}

		cfg = delphi.ConfirmDelphiConfig(cfg)

		if !utils.EnforceSecretsAccess(log, showSecrets) {
			return
		}

		if cfg.Token == "" {
			token, err := delphi.Authenticate(cfg)
			if err != nil {
				fmt.Printf("❌ Authentication failed: %v\n", err)
				os.Exit(1)
			}
			cfg.Token = token
			_ = delphi.SaveDelphiConfig(cfg)
		}

		resp, err := delphi.AuthenticatedGet(cfg, "/security/users")
		if err != nil {
			fmt.Printf("❌ Failed to fetch users: %v\n", err)
			os.Exit(1)
		}
		defer resp.Body.Close()

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
	},
}

func init() {
	InspectCmd.AddCommand(InspectCredentialsCmd)
	InspectCredentialsCmd.Flags().BoolVar(&showSecrets, "show-secrets", false, "Display sensitive fields like password and token")
}
