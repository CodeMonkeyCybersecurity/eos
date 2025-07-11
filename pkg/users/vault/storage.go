package vault

import (
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// StoreUserPassword securely stores the user password in Vault
// Migrated from cmd/create/user.go storeUserPasswordInVault
func StoreUserPassword(rc *eos_io.RuntimeContext, vaultPath, username, password string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS - Validate inputs and check Vault connectivity
	logger.Info("Assessing Vault storage requirements",
		zap.String("username", username),
		zap.String("vault_path", vaultPath))
	
	if username == "" || password == "" {
		return fmt.Errorf("username and password cannot be empty")
	}
	
	client, err := vault.GetVaultClient(rc)
	if err != nil {
		return fmt.Errorf("failed to get Vault client: %w", err)
	}
	
	// INTERVENE - Store password with metadata
	logger.Debug("Storing password in Vault")
	
	secretData := map[string]interface{}{
		"password":    password,
		"username":    username,
		"created_at":  time.Now().Unix(),
		"created_by":  "eos-cli",
		"description": fmt.Sprintf("Password for user %s", username),
	}
	
	secretPath := fmt.Sprintf("%s/users/%s", vaultPath, username)
	if err := vault.WriteKVv2(rc, client, "secret", secretPath, secretData); err != nil {
		return fmt.Errorf("failed to write password to Vault: %w", err)
	}
	
	// EVALUATE - Confirm storage success
	logger.Info("Password stored in Vault successfully",
		zap.String("path", secretPath),
		zap.String("username", username))
	
	return nil
}