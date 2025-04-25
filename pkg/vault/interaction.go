/* pkg/vault/interaction.go */

package vault

import (
	"bufio"
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared" // <-- Add this
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

func PromptForUnsealAndRoot(log *zap.Logger) api.InitResponse {
	fmt.Println("🔐 Please enter 3 unseal keys and the root token")
	keys, _ := crypto.PromptSecrets("Unseal Key", 3, log)
	root, _ := crypto.PromptSecrets("Root Token", 1, log)

	return api.InitResponse{
		KeysB64:   keys,
		RootToken: root[0],
	}
}

func PromptForInitResult(log *zap.Logger) (*api.InitResponse, error) {
	fmt.Println("🔐 Please enter 3 unseal keys and the root token")
	keys, err := crypto.PromptSecrets("Unseal Key", 3, log)
	if err != nil {
		return nil, fmt.Errorf("failed to read unseal keys: %w", err)
	}
	root, err := crypto.PromptSecrets("Root Token", 1, log)
	if err != nil {
		return nil, fmt.Errorf("failed to read root token: %w", err)
	}
	return &api.InitResponse{
		KeysB64:   keys,
		RootToken: root[0],
	}, nil
}

func PromptForEosPassword(log *zap.Logger) (*shared.UserpassCreds, error) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("🔐 Enter eos Vault password: ")
	password, err := readPassword(reader)
	if err != nil {
		return nil, err
	}

	fmt.Print("🔐 Confirm password: ")
	confirm, err := readPassword(reader)
	if err != nil {
		return nil, err
	}

	if password != confirm {
		return nil, fmt.Errorf("passwords do not match")
	}

	return &shared.UserpassCreds{Password: password}, nil
}

func readPassword(reader *bufio.Reader) (string, error) {
	pw, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return string(pw[:len(pw)-1]), nil
}
