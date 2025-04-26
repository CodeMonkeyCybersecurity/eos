// pkg/vault/phase_init.go

package vault

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

// ValidateRootToken checks if the root token is valid via a simple self-lookup.
func ValidateRootToken(client *api.Client, token string) error {
	client.SetToken(token)
	secret, err := client.Auth().Token().LookupSelf()
	if err != nil || secret == nil {
		return fmt.Errorf("token validation failed: %w", err)
	}
	return nil
}

// SetVaultToken configures the Vault client to use a provided token.
func SetVaultToken(client *api.Client, token string) {
	client.SetToken(token)
}

// WaitForAgentToken polls for a token to appear at a given path, with a timeout.
func WaitForAgentToken(path string, log *zap.Logger) (string, error) {
	log.Info("⏳ Waiting for Vault agent token", zap.String("path", path))

	const maxWait = 30 * time.Second
	const interval = 500 * time.Millisecond
	start := time.Now()

	for time.Since(start) < maxWait {
		content, err := os.ReadFile(path)
		if err == nil && len(content) > 0 {
			token := strings.TrimSpace(string(content))
			log.Info("✅ Agent token found", zap.String("token_path", path))
			return token, nil
		}
		time.Sleep(interval)
	}
	return "", fmt.Errorf("agent token not found after %s", maxWait)
}
