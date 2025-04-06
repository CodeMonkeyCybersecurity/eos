// cmd/secure/vault.go

package secure

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/utils"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// initResult is the JSON structure returned by "vault operator init -format=json".
type initResult struct {
	UnsealKeysB64 []string `json:"unseal_keys_b64"`
	RootToken     string   `json:"root_token"`
}

var SecureVaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Secures Vault by revoking the root token and elevating admin privileges",
	Long: `This command secures your Vault setup after "github.com/CodeMonkeyCybersecurity/eos enable vault" has been run.
It reads the stored initialization data (vault_init.json), prompts you to confirm that you have securely 
distributed the unseal keys and root token, then revokes the root token and updates the admin user to have
full (root-level) privileges. Finally, it deletes the stored initialization file.
Please follow up by configuring MFA via your organization's preferred integration method.`,
	Run: func(cmd *cobra.Command, args []string) {

		hostname := utils.GetInternalHostname()
		vaultAddr := fmt.Sprintf("http://%s:8179", hostname)
		os.Setenv("VAULT_ADDR", vaultAddr)
		fmt.Printf("VAULT_ADDR is set to %s\n", vaultAddr)

		// 0. Check for root privileges.
		if os.Geteuid() != 0 {
			fmt.Println("This command must be run with sudo or as root.")
			return
		}

		fmt.Println("Secure Vault setup in progress...")
		fmt.Println("This process will revoke the root token and elevate admin privileges.")
		// 1. Check if the vault_init.json file exists and read it.
		// Check if the file exists.

		if _, err := os.Stat("vault_init.json"); os.IsNotExist(err) {
			log.Fatal("vault_init.json not found", zap.Error(err))
		}

		// Read the vault_init.json file.
		data, err := os.ReadFile("vault_init.json")
		if err != nil {
			log.Fatal("Failed to read vault_init.json", zap.Error(err))
		}

		var initRes initResult
		if err := json.Unmarshal(data, &initRes); err != nil {
			log.Fatal("Failed to unmarshal vault_init.json", zap.Error(err))
		}

		// Build a slice of the stored hashed unseal keys (all five).
		var storedHashes []string
		for _, key := range initRes.UnsealKeysB64 {
			storedHashes = append(storedHashes, utils.HashString(key))
		}

		// Compute the hash for the stored root token.
		hashedRoot := utils.HashString(initRes.RootToken)

		// 2. Prompt the admin to re-enter three unseal keys (in any order) and the root token.
		reader := bufio.NewReader(os.Stdin)
		for {
			fmt.Println("Please re-enter three unique unseal keys (in any order) from the stored set and the root token to confirm secure storage.")

			fmt.Print("Enter Unseal Key 1: ")
			input1, _ := reader.ReadString('\n')
			input1 = strings.TrimSpace(input1)

			fmt.Print("Enter Unseal Key 2: ")
			input2, _ := reader.ReadString('\n')
			input2 = strings.TrimSpace(input2)

			fmt.Print("Enter Unseal Key 3: ")
			input3, _ := reader.ReadString('\n')
			input3 = strings.TrimSpace(input3)

			fmt.Print("Enter Root Token: ")
			inputRoot, _ := reader.ReadString('\n')
			inputRoot = strings.TrimSpace(inputRoot)

			// Ensure the three unseal keys are unique.
			inputs := []string{input1, input2, input3}
			uniqueInputs := make(map[string]bool)
			for _, key := range inputs {
				uniqueInputs[key] = true
			}
			if len(uniqueInputs) != 3 {
				fmt.Println("The unseal keys must be unique. Please try again.")
				continue
			}

			// Compute hashes for the input values.
			inputHash1 := utils.HashString(input1)
			inputHash2 := utils.HashString(input2)
			inputHash3 := utils.HashString(input3)
			inputRootHash := utils.HashString(inputRoot)

			// Check that each provided key's hash is present in the stored hashes.
			matchCount := 0
			for _, inpHash := range []string{inputHash1, inputHash2, inputHash3} {
				for _, storedHash := range storedHashes {
					if inpHash == storedHash {
						matchCount++
						break
					}
				}
			}

			if matchCount != 3 || inputRootHash != hashedRoot {
				fmt.Println("Oops, one or more values are incorrect. Please try again.")
				continue
			}

			fmt.Println("Confirmation successful.")
			break
		}

		// 3. Create and write a custom full-access policy, then update the admin user.
		fmt.Println("Creating custom full-access policy for admin...")

		// Define the policy content.
		policyContent := `
		path "*" {
		  capabilities = ["create", "read", "update", "delete", "list"]
		}
`

		// Use an absolute path
		policyFile := "/tmp/admin-full.hcl"
		if err := os.WriteFile(policyFile, []byte(policyContent), 0600); err != nil {
			log.Fatal("Failed to write policy file", zap.Error(err))
		}

		fmt.Printf("Policy file written to: %s\n", policyFile)
		fmt.Println("Writing custom policy to Vault...")

		// Write the policy to Vault using the full path.
		policyCmd := exec.Command("vault", "policy", "write", "admin-full", policyFile)
		policyOut, err := policyCmd.CombinedOutput()
		if err != nil {
			log.Fatal("Failed to write policy to Vault: %v\nOutput: %s", zap.Error(err), zap.String("output", string(policyOut)))
		}
		fmt.Println("Custom full-access policy 'admin-full' created successfully.")

		// Now update the admin user to use the new policy.
		fmt.Println("Updating admin user to have full privileges using 'admin-full' policy...")
		updateCmd := exec.Command("vault", "write", "auth/userpass/users/admin", "policies=admin-full")
		updateOut, err := updateCmd.CombinedOutput()
		if err != nil {
			fmt.Println("Vault returned:")
			fmt.Println(string(updateOut))
			log.Fatal("Failed to update admin user", zap.Error(err))
		} else {
			fmt.Println("Admin user updated with full privileges (admin-full policy).")
		}

		// Optionally, delete the temporary policy file.
		if err := os.Remove(policyFile); err != nil {
			log.Warn("Warning: Failed to delete temporary policy file", zap.Error(err))
		} else {
			fmt.Println("Temporary policy file deleted.")
		}

		// 4. Revoke the root token.
		fmt.Println("Revoking the root token...")
		revokeCmd := exec.Command("vault", "token", "revoke", initRes.RootToken)
		revokeOut, err := revokeCmd.CombinedOutput()
		if err != nil {
			log.Warn("Warning: Failed to revoke root token: %v\nOutput: %s", zap.Error(err), zap.String("output", string(revokeOut)))
		} else {
			fmt.Println("Root token revoked.")
		}

		// 5. Securely delete the vault_init.json file.
		fmt.Println("Deleting vault_init.json to remove sensitive initialization data...")
		if err := os.Remove("vault_init.json"); err != nil {
			log.Warn("Warning: Failed to delete vault_init.json", zap.Error(err))
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
	SecureCmd.AddCommand(SecureVaultCmd)
}
