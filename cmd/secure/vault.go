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
		// Check if the file exists.
		if _, err := os.Stat("vault_init.json"); os.IsNotExist(err) {
		    log.Fatalf("vault_init.json not found. Please run 'eos enable vault' first to generate initialization data.")
		}
		
		// Read the vault_init.json file.
		data, err := os.ReadFile("vault_init.json")
		if err != nil {
		    log.Fatalf("Failed to read vault_init.json: %v", err)
		}
		
		var initRes initResult
		if err := json.Unmarshal(data, &initRes); err != nil {
		    log.Fatalf("Failed to parse vault_init.json: %v", err)
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
		policyFile := "/var/snap/vault/common/admin-full.hcl"
		if err := os.WriteFile(policyFile, []byte(policyContent), 0600); err != nil {
		    log.Fatalf("Failed to write policy file: %v", err)
		}
		
		fmt.Printf("Policy file written to: %s\n", policyFile)

		
		// Write the policy to Vault using the full path.
		policyCmd := exec.Command("vault", "policy", "write", "admin-full", policyFile)
		policyOut, err := policyCmd.CombinedOutput()
		if err != nil {
		    log.Fatalf("Failed to write policy to Vault: %v\nOutput: %s", err, string(policyOut))
		}
		fmt.Println("Custom full-access policy 'admin-full' created successfully.")
		
		// Now update the admin user to use the new policy.
		fmt.Println("Updating admin user to have full privileges using 'admin-full' policy...")
		updateCmd := exec.Command("vault", "write", "auth/userpass/users/admin", "policies=admin-full")
		updateOut, err := updateCmd.CombinedOutput()
		if err != nil {
		    log.Printf("Warning: Failed to update admin user policies: %v\nOutput: %s", err, string(updateOut))
		} else {
		    fmt.Println("Admin user updated with full privileges (admin-full policy).")
		}
			
		// Optionally, delete the temporary policy file.
		if err := os.Remove(policyFile); err != nil {
		    log.Printf("Warning: Failed to delete temporary policy file: %v", err)
		} else {
		    fmt.Println("Temporary policy file deleted.")
		}
		
		// 4. Revoke the root token.
		fmt.Println("Revoking the root token...")
		revokeCmd := exec.Command("vault", "token", "revoke", initRes.RootToken)
		revokeOut, err := revokeCmd.CombinedOutput()
		if err != nil {
			log.Printf("Warning: Failed to revoke root token: %v\nOutput: %s", err, string(revokeOut))
		} else {
			fmt.Println("Root token revoked.")
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
