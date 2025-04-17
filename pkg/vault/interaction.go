/* pkg/vault/interaction.go */

package vault

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

func PromptForUnsealAndRoot(log *zap.Logger) api.InitResponse {
	fmt.Println("🔐 Please enter 3 unseal keys and the root token")
	keys, _ := interaction.PromptSecrets("Unseal Key", 3, log)
	root, _ := interaction.PromptSecrets("Root Token", 1, log)

	return api.InitResponse{
		KeysB64:   keys,
		RootToken: root[0],
	}
}

func LoadInitResultOrPrompt(client *api.Client, log *zap.Logger) (*api.InitResponse, error) {
	initResPtr, err := ReadFallbackJSON[api.InitResponse](DiskPath("vault_init", log), log)
	if err != nil {
		log.Warn("Vault fallback read failed", zap.Error(err))
		return PromptForInitResult(log)
	}
	return initResPtr, nil
}

func PromptForInitResult(log *zap.Logger) (*api.InitResponse, error) {
	fmt.Println("🔐 Please enter 3 unseal keys and the root token")
	keys, err := interaction.PromptSecrets("Unseal Key", 3, log)
	if err != nil {
		return nil, fmt.Errorf("failed to read unseal keys: %w", err)
	}
	root, err := interaction.PromptSecrets("Root Token", 1, log)
	if err != nil {
		return nil, fmt.Errorf("failed to read root token: %w", err)
	}
	return &api.InitResponse{
		KeysB64:   keys,
		RootToken: root[0],
	}, nil
}
