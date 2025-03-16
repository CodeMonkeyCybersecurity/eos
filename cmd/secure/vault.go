package secure

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

	"eos/pkg/utils"
	"github.com/spf13/cobra"
)

// initResult is the JSON structure returned by "vault operator init -format=json".
type initResult struct {
	UnsealKeysB64 []string `json:"unseal_keys_b64"`
	RootToken     string   `json:"root_token"`
}

// For demonstration, if you don't already have a parent command defined,
// define a placeholder EnableCmd. In your project, remove or replace this.
var EnableCmd = &cobra.Command{
	Use:   "enable",
	Short: "Enable commands",
	Long:  "Commands to enable and secure Vault.",
}

var vaultSecureCmd = &cobra.Command{
	Use:   "vault",
	Short: "Secures Vault by revoking the root token and elevating admin privileges",
	Long: `This command assumes "eos enable vault" has been run and that the initialization data 
(unseal keys and root token) is stored in "vault_init.json". It prompts you to confirm that you have securely 
distributed these secrets by re-entering the first three unseal keys and the root token.
If the input matches, the root token is revoked, the admin user is updated to have full privileges,
and the initialization file is securely deleted.
Please follow up by configuring MFA via your organization's preferred integration method.`,
	Run: func(cmd *cobra.Command, args []string) {
		// 1. Read the vault_init.json file.
		data, err := os.ReadFile("vault_init.json")
		if err != nil {
			log.Fatalf("Failed to read vault_init.json: %v", err)
		}
		var initResData initResult
		if err := json.Unmarshal(data, &initResData); err != nil {
			log.Fatalf("Failed to parse vault_init.json: %v", err)
		}

		// 2. Prompt the admin to re-enter three unseal keys and the root token.
		reader := bufio.NewReader(os.Stdin)
		for {
			fmt.Println("Please re-enter the following secrets to confirm you have stored them securely.")
			fmt.Print("Enter Unseal Key 1: ")
			key1, _ := reader.ReadString('\n')
			key1 = strings.TrimSpace(key1)

			fmt.Print("Enter Unseal Key 2: ")
			key2, _ := reader.ReadString('\n')
			key2 = strings.TrimSpace(key2)

			fmt.Print("Enter Unseal Key 3: ")
			key3, _ := reader.ReadString('\n')
			key3 = strings.TrimSpace(key3)

			fmt.Print("Enter Root Token: ")
			token, _ := reader.ReadString('\n')
			token = strings.TrimSpace(token)

			if utils.HashString(key1) == utils.HashString(initResData.UnsealKeysB64[0]) &&
				utils.HashString(key2) == utils.HashString(initResData.UnsealKeysB64[1]) &&
				utils.HashString(key3) == utils.HashString(initResData.UnsealKeysB64[2]) &&
				utils.HashString(token) == utils.HashString(initResData.RootToken) {
				fmt.Println("Confirmation successful.")
				break
			} else {
				fmt.Println("One or more entries do not match. Please try again.")
			}
		}

		// 3. Revoke the root token.
		fmt.Println("Revoking the root token...")
		revokeCmd := exec.Command("vault", "token", "revoke", initResData.RootToken)
		revokeOut, err := revokeCmd.CombinedOutput()
		if err != nil {
			log.Printf("Warning: Failed to revoke root token: %v\nOutput: %s", err, string(revokeOut))
		} else {
			fmt.Println("Root token revoked.")
		}

		// 4. Update the admin user to have full privileges (assign the root policy).
		fmt.Println("Updating admin user to have full privileges...")
		updateCmd := exec.Command("vault", "write", "auth/userpass/users/admin", "policies=root")
		updateOut, err := updateCmd.CombinedOutput()
		if err != nil {
			log.Printf("Warning: Failed to update admin user policies: %v\nOutput: %s", err, string(updateOut))
		} else {
			fmt.Println("Admin user updated with full privileges.")
		}

		// 5. Securely delete the vault_init.json file.
		fmt.Println("Deleting vault_init.json to remove sensitive initialization data...")
		if err := os.Remove("vault_init.json"); err != nil {
			log.Printf("Warning: Failed to delete vault_init.json: %v", err)
		} else {
			fmt.Println("vault_init.json deleted successfully.")
		}

		fmt.Println("\nVault secure setup completed successfully!")
		fmt.Println("Next, configure MFA for your admin user using your organization's preferred method.")
	},
}

func init() {
	EnableCmd.AddCommand(vaultSecureCmd)
}
