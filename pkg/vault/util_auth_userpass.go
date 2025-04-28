// pkg/vault/util_auth_approle.go

package vault

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eosio"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"

	"go.uber.org/zap"
)

func EnableVaultUserpass(ctx *eosio.RuntimeContext, log *zap.Logger) error {
	client, err := NewClient(log)
	if err != nil {
		return fmt.Errorf("failed to create vault client: %w", err)
	}

	// 1. Enable userpass auth if needed
	if err := EnsureAuthMethod(client, "userpass", "userpass/", log); err != nil {
		return fmt.Errorf("failed to enable userpass auth: %w", err)
	}
	log.Info("✅ Userpass auth method enabled")

	// 2. Ensure eos-policy exists
	if err := EnsurePolicy(client, log); err != nil {
		return fmt.Errorf("failed to ensure eos-policy: %w", err)
	}
	log.Info("✅ EOS policy ensured")

	// 3. Prompt for EOS user password
	password, err := crypto.PromptPassword("Enter password for Vault 'eos' user", log)
	if err != nil {
		return fmt.Errorf("failed to prompt eos password: %w", err)
	}
	log.Info("✅ Password entered for EOS Vault user")

	// 4. Create the EOS user in Vault
	userData := map[string]interface{}{
		"password": password,
		"policies": shared.EosVaultPolicy,
	}
	if _, err := client.Logical().Write("auth/userpass/users/eos", userData); err != nil {
		return fmt.Errorf("failed to create eos Vault user: %w", err)
	}
	log.Info("✅ EOS user created in Vault userpass auth")

	return nil
}
