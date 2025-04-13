/* pkg/vault/agent_lifecycle.go */

package vault

import (
	"fmt"
	"os"

	"github.com/hashicorp/vault/api"
)

func CreateAppRole(client *api.Client, roleName string) error {
	const (
		roleIDPath   = "/etc/vault/role_id"
		secretIDPath = "/etc/vault/secret_id"
	)

	rolePath := "auth/approle/role/" + roleName
	fmt.Println("🔐 Creating AppRole:", roleName)

	// Ensure approle auth method is enabled
	client.Sys().EnableAuthWithOptions("approle", &api.EnableAuthOptions{
		Type: "approle",
	})

	// Define the role with full-access policy
	_, err := client.Logical().Write(rolePath, map[string]interface{}{
		"policies":      []string{EosVaultPolicy},
		"token_ttl":     "60m",
		"token_max_ttl": "120m",
	})
	if err != nil {
		return fmt.Errorf("failed to create AppRole %s: %w", roleName, err)
	}

	// Fetch the role_id
	roleIDResp, err := client.Logical().Read(rolePath + "/role-id")
	if err != nil {
		return fmt.Errorf("failed to read role_id: %w", err)
	}
	roleID := roleIDResp.Data["role_id"].(string)

	// Fetch the secret_id
	secretIDResp, err := client.Logical().Write(rolePath+"/secret-id", nil)
	if err != nil {
		return fmt.Errorf("failed to generate secret_id: %w", err)
	}
	secretID := secretIDResp.Data["secret_id"].(string)

	// Write them to disk
	if err := os.WriteFile(roleIDPath, []byte(roleID+"\n"), 0640); err != nil {
		return fmt.Errorf("failed to write role_id: %w", err)
	}
	if err := os.WriteFile(secretIDPath, []byte(secretID+"\n"), 0640); err != nil {
		return fmt.Errorf("failed to write secret_id: %w", err)
	}

	fmt.Println("✅ AppRole credentials written to disk:")
	fmt.Println("   •", roleIDPath)
	fmt.Println("   •", secretIDPath)

	return nil
}
