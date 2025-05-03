// pkg/vault/interaction

package vault

import (
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
	"golang.org/x/term"
)

// PromptForEosPassword securely prompts for and confirms the eos Vault password.
// Returns an error if input reading fails or confirmation mismatches.
func PromptForEosPassword() (*shared.UserpassCreds, error) {
	password, err := interaction.PromptSecret("🔐 Enter eos Vault password")
	if err != nil {
		return nil, fmt.Errorf("failed to read password: %w", err)
	}

	confirm, err := interaction.PromptSecret("🔐 Confirm password")
	if err != nil {
		return nil, fmt.Errorf("failed to read password confirmation: %w", err)
	}

	if password != confirm {
		return nil, fmt.Errorf("passwords do not match")
	}

	return &shared.UserpassCreds{Password: password}, nil
}

// PromptForInitResult prompts interactively for unseal keys and a root token.
// Returns an error if any prompt fails or input is blank.
func PromptForInitResult() (*api.InitResponse, error) {
	zap.L().Info("Prompting for unseal keys and root token (fallback path)")
	fmt.Println("🔐 Please enter 3 unseal keys and the root token")

	if !term.IsTerminal(int(os.Stdin.Fd())) {
		zap.L().Error("❌ Cannot prompt for secret input: not a TTY")
		return nil, fmt.Errorf("secret prompt failed: no terminal available")
	}

	var keys []string
	for i := 1; i <= 3; i++ {
		key, err := interaction.PromptSecret(fmt.Sprintf("Unseal Key %d", i))
		if err != nil {
			return nil, fmt.Errorf("failed to read unseal key %d: %w", i, err)
		}
		if strings.TrimSpace(key) == "" {
			return nil, fmt.Errorf("unseal key %d is blank", i)
		}
		keys = append(keys, key)
	}

	rootToken, err := interaction.PromptSecret("Root Token")
	if err != nil {
		return nil, fmt.Errorf("failed to read root token: %w", err)
	}
	if strings.TrimSpace(rootToken) == "" {
		return nil, fmt.Errorf("root token cannot be blank")
	}

	return &api.InitResponse{
		KeysB64:   keys,
		RootToken: rootToken,
	}, nil
}

// PromptUnsealKeys requests 3 unseal keys interactively with hidden input.
func PromptUnsealKeys() ([]string, error) {
	zap.L().Info("🔐 Please enter 3 base64-encoded unseal keys")
	return interaction.PromptSecrets("Unseal Key", 3)
}
