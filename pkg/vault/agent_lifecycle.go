/* pkg/vault/agent_lifecycle.go */

package vault

import (
	"fmt"
	"os"

	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

func CreateAppRole(client *api.Client, roleName string, log *zap.Logger) error {
	fmt.Println("🔐 Creating AppRole:", roleName)

	// Enable AppRole auth method (idempotent)
	_ = client.Sys().EnableAuthWithOptions("approle", &api.EnableAuthOptions{
		Type: "approle",
	})

	// Define AppRole in Vault with the eos-policy
	_, err := client.Logical().Write(rolePath, map[string]interface{}{
		"policies":      []string{EosVaultPolicy},
		"token_ttl":     "60m",
		"token_max_ttl": "120m",
	})
	if err != nil {
		return fmt.Errorf("failed to create AppRole %q: %w", roleName, err)
	}

	// Read role_id from Vault
	roleIDResp, err := client.Logical().Read(rolePath + "/role-id")
	if err != nil {
		return fmt.Errorf("failed to read role_id: %w", err)
	}
	roleID := roleIDResp.Data["role_id"].(string)

	// Generate a new secret_id
	secretIDResp, err := client.Logical().Write(rolePath+"/secret-id", nil)
	if err != nil {
		return fmt.Errorf("failed to generate secret_id: %w", err)
	}
	secretID := secretIDResp.Data["secret_id"].(string)

	// Write both values to disk
	if err := os.WriteFile(AppRoleIDPath, []byte(roleID+"\n"), 0640); err != nil {
		return fmt.Errorf("failed to write role_id: %w", err)
	}
	if err := os.WriteFile(SecretsDir, []byte(secretID+"\n"), 0640); err != nil {
		return fmt.Errorf("failed to write secret_id: %w", err)
	}

	fmt.Println("✅ AppRole credentials written to disk:")
	fmt.Println("   •", AppRoleIDPath)
	fmt.Println("   •", SecretsDir)

	return nil
}

func WriteAppRoleCredentials(client *api.Client, log *zap.Logger) error {
	roleID, err := client.Logical().Read(rolePath + "/role-id")
	if err != nil {
		return fmt.Errorf("failed to read role_id: %w", err)
	}
	secretID, err := client.Logical().Write(rolePath+"/secret-id", nil)
	if err != nil {
		return fmt.Errorf("failed to generate secret_id: %w", err)
	}

	if err := os.WriteFile(AppRoleIDPath, []byte(roleID.Data["role_id"].(string)), 0400); err != nil {
		return err
	}
	if err := os.WriteFile(SecretsDir, []byte(secretID.Data["secret_id"].(string)), 0400); err != nil {
		return err
	}
	return nil
}
