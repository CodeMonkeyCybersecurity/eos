// pkg/vault/auth_userpass.go
package vault

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eosio"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/vault/api/auth/userpass"
	"go.uber.org/zap"
)

func EnableVaultUserpass(ctx *eosio.RuntimeContext) error {
	log := zap.L()
	client, err := NewClient()
	if err != nil {
		return fmt.Errorf("failed to create Vault client: %w", err)
	}

	// 1. Ensure auth methods (userpass + approle) are enabled
	if err := EnsureVaultAuthMethods(client); err != nil {
		return fmt.Errorf("failed to enable auth methods: %w", err)
	}
	log.Info("✅ Userpass and AppRole auth methods ensured")

	// 2. Ensure the eos-policy exists
	if err := EnsurePolicy(); err != nil {
		return fmt.Errorf("failed to ensure eos-policy: %w", err)
	}
	log.Info("✅ EOS policy ensured")

	// 3. Prompt for EOS user password
	passStr, err := crypto.PromptPassword("Enter password for Vault 'eos' user")
	if err != nil {
		return fmt.Errorf("failed to prompt eos password: %w", err)
	}
	log.Info("✅ Password captured for EOS user")

	// 4. Create user using Logical().Write
	writePath := "auth/userpass/users/eos"
	userData := map[string]interface{}{
		"password": passStr,
		"policies": shared.EosDefaultPolicyName,
	}
	if _, err := client.Logical().Write(writePath, userData); err != nil {
		return fmt.Errorf("failed to create eos Vault user: %w", err)
	}
	log.Info("✅ EOS user created", zap.String("path", writePath))

	// 5. (Optional) Attempt login with the new user using the typed API
	auth, err := userpass.NewUserpassAuth("eos", &userpass.Password{FromString: passStr}, userpass.WithMountPath("userpass"))
	if err != nil {
		return fmt.Errorf("failed to create UserpassAuth object: %w", err)
	}

	secret, err := auth.Login(ctx.Ctx, client)
	if err != nil {
		return fmt.Errorf("login failed for eos user: %w", err)
	}
	if secret == nil || secret.Auth == nil {
		return fmt.Errorf("login response missing auth")
	}
	log.Info("🔐 Successfully authenticated with EOS Vault user", zap.String("token", secret.Auth.ClientToken[:8]+"..."))

	return nil
}
