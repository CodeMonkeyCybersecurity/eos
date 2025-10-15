// pkg/vault/enablement_state.go

package vault

import (
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// IsUserpassConfigured checks if userpass auth method is mounted and the eos user exists.
// Returns true if both the auth method is enabled AND the eos user is configured.
func IsUserpassConfigured(rc *eos_io.RuntimeContext, client *api.Client) (bool, error) {
	log := otelzap.Ctx(rc.Ctx)

	// Check if userpass auth method is mounted
	auths, err := client.Sys().ListAuth()
	if err != nil {
		log.Warn("Failed to list auth methods", zap.Error(err))
		return false, fmt.Errorf("list auth methods: %w", err)
	}

	// Check for userpass mount (can be "userpass/" or "userpass")
	userpassMounted := false
	for path := range auths {
		if strings.HasPrefix(path, "userpass") {
			userpassMounted = true
			break
		}
	}

	if !userpassMounted {
		log.Debug("Userpass auth method not mounted")
		return false, nil
	}

	// Check if eos user exists under userpass
	secret, err := client.Logical().Read(shared.EosUserpassPath)
	if err != nil {
		log.Warn("Failed to read eos user from userpass",
			zap.Error(err),
			zap.String("path", shared.EosUserpassPath))
		return false, fmt.Errorf("read userpass user: %w", err)
	}

	if secret == nil {
		log.Debug("Eos user not found in userpass auth")
		return false, nil
	}

	log.Debug("Userpass fully configured",
		zap.String("user_path", shared.EosUserpassPath))
	return true, nil
}

// IsAppRoleConfigured checks if AppRole auth method is mounted and the eos-approle exists.
// Also verifies that credentials are written to disk.
func IsAppRoleConfigured(rc *eos_io.RuntimeContext, client *api.Client) (bool, error) {
	log := otelzap.Ctx(rc.Ctx)

	// Check if approle auth method is mounted
	auths, err := client.Sys().ListAuth()
	if err != nil {
		log.Warn("Failed to list auth methods", zap.Error(err))
		return false, fmt.Errorf("list auth methods: %w", err)
	}

	// Check for approle mount
	approleMounted := false
	for path := range auths {
		if strings.HasPrefix(path, "approle") {
			approleMounted = true
			break
		}
	}

	if !approleMounted {
		log.Debug("AppRole auth method not mounted")
		return false, nil
	}

	// Check if eos-approle role exists
	rolePath := shared.AppRolePath
	secret, err := client.Logical().Read(rolePath)
	if err != nil {
		log.Warn("Failed to read AppRole",
			zap.Error(err),
			zap.String("path", rolePath))
		return false, fmt.Errorf("read approle: %w", err)
	}

	if secret == nil {
		log.Debug("Eos AppRole not found")
		return false, nil
	}

	// Check if credentials are written to disk
	roleIDPath := shared.AppRolePaths.RoleID
	secretIDPath := shared.AppRolePaths.SecretID

	roleIDExists := fileExists(roleIDPath)
	secretIDExists := fileExists(secretIDPath)

	if !roleIDExists || !secretIDExists {
		log.Debug("AppRole configured in Vault but credentials missing on disk",
			zap.Bool("role_id_exists", roleIDExists),
			zap.Bool("secret_id_exists", secretIDExists))
		return false, nil
	}

	log.Debug("AppRole fully configured",
		zap.String("role_path", rolePath),
		zap.String("role_id_file", roleIDPath),
		zap.String("secret_id_file", secretIDPath))
	return true, nil
}

// IsEntityConfigured checks if the eos entity exists with userpass and approle aliases.
func IsEntityConfigured(rc *eos_io.RuntimeContext, client *api.Client) (bool, error) {
	log := otelzap.Ctx(rc.Ctx)

	// Try to read the eos entity by name
	entityLookupPath := fmt.Sprintf(shared.EosEntityLookupPath, shared.EosID)
	secret, err := client.Logical().Read(entityLookupPath)
	if err != nil {
		log.Warn("Failed to read eos entity",
			zap.Error(err),
			zap.String("path", entityLookupPath))
		return false, fmt.Errorf("read entity: %w", err)
	}

	if secret == nil || secret.Data == nil {
		log.Debug("Eos entity not found")
		return false, nil
	}

	// Entity exists - check if it has aliases
	entityID, ok := secret.Data["id"].(string)
	if !ok || entityID == "" {
		log.Debug("Entity found but has no ID")
		return false, nil
	}

	log.Debug("Eos entity configured",
		zap.String("entity_id", entityID))
	return true, nil
}

// IsAuditConfigured checks if file-based audit backend is enabled.
func IsAuditConfigured(rc *eos_io.RuntimeContext, client *api.Client) (bool, error) {
	log := otelzap.Ctx(rc.Ctx)

	audits, err := client.Sys().ListAudit()
	if err != nil {
		log.Warn("Failed to list audit devices", zap.Error(err))
		return false, fmt.Errorf("list audit devices: %w", err)
	}

	// Check for file audit backend
	if _, exists := audits[shared.AuditID]; exists {
		log.Debug("File audit backend configured",
			zap.String("audit_id", shared.AuditID))
		return true, nil
	}

	log.Debug("File audit backend not configured")
	return false, nil
}

// IsAgentConfigured checks if Vault Agent is configured.
// Verifies that config file exists and agent service is set up.
func IsAgentConfigured(rc *eos_io.RuntimeContext) (bool, error) {
	log := otelzap.Ctx(rc.Ctx)

	// Check if agent config file exists
	agentConfigPath := shared.VaultAgentConfigPath
	if !fileExists(agentConfigPath) {
		log.Debug("Vault Agent config file not found",
			zap.String("path", agentConfigPath))
		return false, nil
	}

	// Check if agent service exists
	agentServicePath := shared.VaultAgentServicePath
	if !fileExists(agentServicePath) {
		log.Debug("Vault Agent service file not found",
			zap.String("path", agentServicePath))
		return false, nil
	}

	log.Debug("Vault Agent configured",
		zap.String("config", agentConfigPath),
		zap.String("service", agentServicePath))
	return true, nil
}

// UpdateUserpassPassword updates the password for the existing eos userpass user.
func UpdateUserpassPassword(rc *eos_io.RuntimeContext, client *api.Client, newPassword string) error {
	log := otelzap.Ctx(rc.Ctx)

	log.Info("Updating eos userpass password")

	// Get privileged client
	privilegedClient, err := GetRootClient(rc)
	if err != nil {
		return fmt.Errorf("get privileged client: %w", err)
	}

	// Update the password
	userData := shared.UserDataTemplate(newPassword)
	if _, err := privilegedClient.Logical().Write(shared.EosUserpassPath, userData); err != nil {
		log.Error("Failed to update userpass password", zap.Error(err))
		return fmt.Errorf("update userpass password: %w", err)
	}

	// Update fallback file
	if err := WriteUserpassCredentialsFallback(rc, newPassword); err != nil {
		log.Warn("Failed to update fallback credentials", zap.Error(err))
		// Don't fail - password was updated in Vault
	}

	log.Info("Userpass password updated successfully")
	return nil
}

// RegenerateAppRoleCredentials generates new AppRole credentials (new secret_id).
// The role_id remains the same, but a fresh secret_id is generated.
func RegenerateAppRoleCredentials(rc *eos_io.RuntimeContext, client *api.Client) error {
	log := otelzap.Ctx(rc.Ctx)

	log.Info("Regenerating AppRole credentials")

	// Get privileged client
	privilegedClient, err := GetRootClient(rc)
	if err != nil {
		return fmt.Errorf("get privileged client: %w", err)
	}

	// Read the role_id (stays the same)
	roleIDResp, err := privilegedClient.Logical().Read(shared.AppRoleRoleIDPath)
	if err != nil || roleIDResp == nil {
		log.Error("Failed to read role_id", zap.Error(err))
		return fmt.Errorf("read role_id: %w", err)
	}

	roleID, ok := roleIDResp.Data["role_id"].(string)
	if !ok || roleID == "" {
		return fmt.Errorf("invalid role_id response")
	}

	// Generate new secret_id
	secretIDResp, err := privilegedClient.Logical().Write(shared.AppRoleSecretIDPath, nil)
	if err != nil || secretIDResp == nil {
		log.Error("Failed to generate new secret_id", zap.Error(err))
		return fmt.Errorf("generate secret_id: %w", err)
	}

	secretID, ok := secretIDResp.Data["secret_id"].(string)
	if !ok || secretID == "" {
		return fmt.Errorf("invalid secret_id response")
	}

	// Write new credentials to disk
	if err := WriteAppRoleFiles(rc, roleID, secretID); err != nil {
		log.Error("Failed to write new AppRole credentials", zap.Error(err))
		return fmt.Errorf("write approle files: %w", err)
	}

	log.Info("AppRole credentials regenerated successfully",
		zap.String("role_id", roleID))
	return nil
}

// fileExists checks if a file exists and is readable.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
