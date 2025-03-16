package secure

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"
	"eos/pkg/utils"

)

// initResult is the JSON structure returned by "vault operator init -format=json".
type initResult struct {
	UnsealKeysB64 []string `json:"unseal_keys_b64"`
	RootToken     string   `json:"root_token"`
}

var vaultSecureCmd = &cobra.Command{
	Use:   "vault",
	Short: "Secures Vault by revoking the root token and elevating admin privileges",
	Long: `This command secures your Vault setup after "eos enable vault" has been run.
It reads the stored initialization data (vault_init.json), prompts you to confirm that you have securely 
distributed the unseal keys and root token, then revokes the root token and updates the admin user to have
full (root-level) privileges. Finally, it deletes the stored initialization file.
Please follow up by configuring MFA via your organization's preferred integration method.`,
	Run: func(cmd *cobra.Command, args []string) {
		// 1. Read the vault_init.json file.
		data, err := os.ReadFile("vault_init.json")
		if err != nil {
			log.Fatalf("Failed to read vault_init.json: %v", err)
		}
		var initRes initResult
		if err := json.Unmarshal(data, &initRes); err != nil {
			log.Fatalf("Failed to parse vault_init.json: %v", err)
		}

		// After reading and parsing vault_init.json, hash them
		hashedKey1 := utils.HashString(initRes.UnsealKeysB64[0])
		hashedKey2 := utils.HashString(initRes.UnsealKeysB64[1])
		hashedKey3 := utils.HashString(initRes.UnsealKeysB64[2])
		hashedRoot := utils.HashString(initRes.RootToken)

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

			if utils.HashString(inputKey1) == hashedKey1 &&
			   utils.HashString(inputKey2) == hashedKey2 &&
			   utils.HashString(inputKey3) == hashedKey3 &&
			   utils.HashString(inputRoot) == hashedRoot {
			    fmt.Println("Confirmation successful.")
			    // Now you can delete vault_init.json and (optionally) zero out any in-memory plaintext.
			} else {
			    fmt.Println("One or more entries do not match. Please try again.")
			}
		}

		// 3. Revoke the root token.
		fmt.Println("Revoking the root token...")
		revokeCmd := exec.Command("vault", "token", "revoke", initRes.RootToken)
		revokeOut, err := revokeCmd.CombinedOutput()
		if err != nil {
			log.Printf("Warning: Failed to revoke root token: %v\nOutput: %s", err, string(revokeOut))
		} else {
			fmt.Println("Root token revoked.")
		}

		// 4. Update the admin user to have full privileges.
		// We assume that an admin user was created via userpass. We'll update its policies to "root".
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

		// 6. Provide instructions to configure MFA.
		fmt.Println("\nNext Steps:")
		fmt.Println("Please configure multi-factor authentication (MFA) for your admin user using your organization's preferred method.")
		fmt.Println("Refer to Vault's documentation for integrating MFA (e.g., via OIDC, LDAP, or a third-party MFA solution).")
		fmt.Println("\nVault secure setup completed successfully!")
	},
}

func init() {
	SecureCmd.AddCommand(vaultSecureCmd)
}
