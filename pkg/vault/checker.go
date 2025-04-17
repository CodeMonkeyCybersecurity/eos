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
	"go.uber.org/zap"
)

// CheckVaultProcesses prints if any Vault-related processes are still running.
func CheckVaultProcesses(log *zap.Logger) {
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
func IsVaultAvailable(client *api.Client, log *zap.Logger) bool {
	installed := isInstalled(log)
	initialized, err := isVaultInitialized(client, log)
	return installed && err == nil && initialized
}

func isInstalled(log *zap.Logger) bool {
	_, err := exec.LookPath("vault")
	if err != nil {
		log.Warn("Vault binary not found in PATH", zap.Error(err))
		return false
	}
	log.Info("✅ Vault binary found in PATH")
	return true
}

func isVaultInitialized(client *api.Client, log *zap.Logger) (bool, error) {
	status, err := client.Sys().Health()
	if err != nil {
		log.Warn("Failed to query Vault health", zap.Error(err))
		return false, err
	}
	log.Info("Vault health check complete", zap.Bool("initialized", status.Initialized), zap.Bool("sealed", status.Sealed))
	return status.Initialized, nil
}

// CheckVaultSecrets verifies that entered unseal keys and root token match the stored hashes.
func CheckVaultSecrets(storedHashes []string, hashedRoot string, log *zap.Logger) {

	for {
		fmt.Println("🔐 Please re-enter three unique base64-encoded unseal keys (any order) and the root token:")

		keys, err := interaction.PromptSecrets("Enter Unseal Key", 3, log)
		if err != nil {
			fmt.Println("❌ Oh no, that didn't work! Please try again.")
			continue
		}

		rootInput, err := interaction.PromptSecrets("Enter Root Token", 1, log)
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
func TestKVSecret(client *api.Client, log *zap.Logger) error {
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

func IsVaultSealed(client *api.Client, log *zap.Logger) bool {
	health, err := client.Sys().Health()
	if err != nil {
		// fallback: assume not sealed (or log?)
		return false
	}
	return health.Sealed
}
