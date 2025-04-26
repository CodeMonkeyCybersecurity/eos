// pkg/vault/phase_init.go

package vault

import (
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

func PromptToSaveVaultInitData(init *api.InitResponse, log *zap.Logger) error {
	fmt.Println("\n⚠️  WARNING: This is the only time you will see these unseal keys and root token.")
	fmt.Println("You MUST securely back them up. Losing them means permanent loss of access.")
	fmt.Print("\nType 'yes' to confirm you've saved the keys somewhere safe: ")

	var response string
	fmt.Scanln(&response)
	if strings.ToLower(strings.TrimSpace(response)) != "yes" {
		return fmt.Errorf("user did not confirm secure storage of unseal material")
	}

	log.Info("✅ User confirmed Vault init material has been backed up securely")
	return nil
}

func ConfirmUnsealMaterialSaved(init *api.InitResponse, log *zap.Logger) error {
	fmt.Println("\n🔐 Please re-enter 3 of your unseal keys and the root token to confirm you've saved them.")

	keys, err := crypto.PromptSecrets("Unseal Key", 3, log)
	if err != nil {
		return fmt.Errorf("failed to read unseal keys: %w", err)
	}
	root, err := crypto.PromptSecrets("Root Token", 1, log)
	if err != nil {
		return fmt.Errorf("failed to read root token: %w", err)
	}

	if crypto.HashString(root[0]) != crypto.HashString(init.RootToken) {
		return fmt.Errorf("root token did not match original")
	}

	matchCount := 0
	for _, entered := range keys {
		for _, known := range init.KeysB64 {
			if crypto.HashString(entered) == crypto.HashString(known) {
				matchCount++
				break
			}
		}
	}

	if matchCount < 3 {
		return fmt.Errorf("less than 3 unseal keys matched")
	}

	log.Info("✅ User successfully confirmed unseal material")
	return nil
}

// ConfirmSecureStorage prompts user to re-enter keys to confirm they've been saved.
func ConfirmSecureStorage(original *api.InitResponse, log *zap.Logger) error {
	fmt.Println("🔒 Please re-enter 3 unseal keys and the root token to confirm you've saved them.")

	rekeys, err := crypto.PromptSecrets("Unseal Key", 3, log)
	if err != nil {
		return err
	}
	reroot, err := crypto.PromptSecrets("Root Token", 1, log)
	if err != nil {
		return err
	}

	// Match at least 3 keys
	matched := 0
	for _, input := range rekeys {
		for _, ref := range original.KeysB64 {
			if crypto.HashString(input) == crypto.HashString(ref) {
				matched++
				break
			}
		}
	}
	if matched < 3 || crypto.HashString(reroot[0]) != crypto.HashString(original.RootToken) {
		return fmt.Errorf("reconfirmation failed: keys or token do not match")
	}

	log.Info("✅ Reconfirmation of unseal material passed")
	return nil
}
