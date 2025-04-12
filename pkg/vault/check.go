/* pkg/vault/check.go */

package vault

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/utils"
	"github.com/hashicorp/vault/api"
)

// CheckVaultProcesses prints if any Vault-related processes are still running.
func CheckVaultProcesses() {
	output, err := utils.GrepProcess("vault")
	if err != nil {
		fmt.Println("⚠️ Failed to check Vault processes:", err)
		return
	}

	if strings.TrimSpace(output) != "" {
		fmt.Println("⚠️ Potential Vault processes still running:\n", output)
	} else {
		fmt.Println("✅ No Vault processes detected — system appears clean.")
	}
}

// IsVaultAvailable returns true if Vault is installed and initialized.
func IsVaultAvailable(client *api.Client) bool {
	installed := isInstalled()
	initialized, err := isVaultInitialized(client)
	return installed && err == nil && initialized
}

func isInstalled() bool {
	_, err := exec.LookPath("vault")
	return err == nil
}

func isVaultInitialized(client *api.Client) (bool, error) {
	status, err := client.Sys().Health()
	if err != nil {
		return false, err
	}
	return status.Initialized, nil
}

// CheckVaultSecrets verifies that entered unseal keys and root token match the stored hashes.
// CheckVaultSecrets verifies that entered unseal keys and root token match the stored hashes.
func CheckVaultSecrets(storedHashes []string, hashedRoot string) {

	for {
		fmt.Println("🔐 Please re-enter three unique base64-encoded unseal keys (any order) and the root token:")

		keys, err := interaction.PromptSecrets("Enter Unseal Key", 3)
		if err != nil {
			fmt.Println("❌ Oh no, that didn't work! Please try again.")
			continue
		}

		rootInput, err := interaction.PromptSecrets("Enter Root Token", 1)
		if err != nil || len(rootInput) == 0 {
			fmt.Println("❌ Oh no, that didn't work! Please try again.")
			continue
		}
		root := rootInput[0]

		// Prevent duplicated keys
		if !crypto.AllUnique(keys) {
			fmt.Println("❌ Oh no, that didn't work! Please try again.")
			continue
		}

		// Hash and verify all
		hashedInputs := crypto.HashStrings(keys)
		if !crypto.AllHashesPresent(hashedInputs, storedHashes) || crypto.HashString(root) != hashedRoot {
			fmt.Println("❌ Oh no, that didn't work! Please try again.")
			continue
		}

		fmt.Println("✅ Confirmation successful.")
		break
	}
}

// TestKVSecret writes and reads a test secret from the KV engine.
func TestKVSecret(client *api.Client) error {
	fmt.Println("\nWriting and reading test secret...")

	kv := client.KVv2("secret")

	if _, err := kv.Put(context.Background(), "hello", map[string]interface{}{"value": "world"}); err != nil {
		return fmt.Errorf("failed to write test secret: %w", err)
	}

	secret, err := kv.Get(context.Background(), "hello")
	if err != nil {
		return fmt.Errorf("failed to read test secret: %w", err)
	}

	fmt.Println("✅ Test secret value:", secret.Data["value"])
	return nil
}

func IsVaultSealed(client *api.Client) bool {
	health, err := client.Sys().Health()
	if err != nil {
		// fallback: assume not sealed (or log?)
		return false
	}
	return health.Sealed
}
