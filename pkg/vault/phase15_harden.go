// pkg/vault/phase15_harden.go

package vault

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

// TODO:
// func RevokeRootToken(client *api.Client, token string) error {
// 	client.SetToken(token)

// 	err := client.Auth().Token().RevokeSelf("")
// 	if err != nil {
// 		return fmt.Errorf("failed to revoke root token: %w", err)
// 	}

// 	zap.L().Info("✅ Root token revoked")
// 	return nil
// }

// ConfirmSecureStorage prompts user to re-enter keys to confirm they've been saved.
func ConfirmSecureStorage(original *api.InitResponse) error {
	fmt.Println("🔒 Please re-enter 3 unseal keys and the root token to confirm you've saved them.")

	rekeys, err := interaction.PromptSecrets("Unseal Key", 3)
	if err != nil {
		return err
	}
	reroot, err := interaction.PromptSecrets("Root Token", 1)
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

	zap.L().Info("✅ Reconfirmation of unseal material passed")
	return nil
}
