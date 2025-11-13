// pkg/vault/phase10b2_enable_admin_approle.go
// Phase 10b2: Create Admin AppRole for operational commands
//
// This phase creates an admin-level AppRole that has elevated privileges
// (eos-admin-policy) for operational commands like policy updates, MFA repair,
// and drift correction.
//
// This follows HashiCorp best practice:
// - Use root token ONLY for initial setup
// - Use admin AppRole for operational/maintenance commands
// - Admin AppRole is still policy-bound (not unlimited like root)
// - All operations are audited
//
// Flow:
// 1. ASSESS: Check if admin AppRole already exists
// 2. INTERVENE: Create admin AppRole if needed
// 3. EVALUATE: Verify admin AppRole works

package vault

import (
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	cerr "github.com/cockroachdb/errors"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

// PhaseEnableAdminAppRole provisions admin-level AppRole for operational commands.
// This follows HashiCorp best practice of using AppRole instead of root token
// for maintenance operations.
func PhaseEnableAdminAppRole(
	rc *eos_io.RuntimeContext,
	client *api.Client,
	log *zap.Logger,
) error {

	log.Info(" [Phase10b2] Setting up Admin AppRole for operational commands")

	// ASSESS - Check if admin AppRole is already fully configured
	log.Info(" [ASSESS] Checking if admin AppRole is already configured")

	// Get privileged client for checks
	// NOTE: During initial setup, this is root token. After setup, this could be
	// Vault Agent with admin policy.
	privilegedClient, err := GetPrivilegedClient(rc)
	if err != nil {
		log.Error(" Failed to get privileged Vault client for admin AppRole setup", zap.Error(err))
		return cerr.Wrap(err, "get privileged client")
	}

	if privToken := privilegedClient.Token(); privToken != "" {
		log.Debug(" Using privileged client for admin AppRole operations")
	}

	// Check 1: Does the admin AppRole role exist in Vault?
	roleData, err := privilegedClient.Logical().Read(shared.AdminAppRoleRoleIDPath)
	if err == nil && roleData != nil && roleData.Data != nil {
		if storedRoleID, ok := roleData.Data["role_id"].(string); ok && storedRoleID != "" {
			log.Info(" Admin AppRole exists in Vault backend",
				zap.String("role_name", shared.AdminAppRoleName),
				zap.String("role_id", storedRoleID))

			// Check 2: Do credential files exist on disk?
			roleIDPath := shared.AdminAppRolePaths.RoleID
			secretIDPath := shared.AdminAppRolePaths.SecretID

			if _, roleFileErr := os.Stat(roleIDPath); roleFileErr == nil {
				if _, secretFileErr := os.Stat(secretIDPath); secretFileErr == nil {
					log.Info(" [EVALUATE] Admin AppRole fully configured - skipping creation",
						zap.String("role_id_file", roleIDPath),
						zap.String("secret_id_file", secretIDPath),
						zap.String("role_name", shared.AdminAppRoleName))

					// Verify credentials are valid by reading them
					if roleID, secretID, readErr := readAdminAppRoleCredsFromDisk(rc); readErr == nil {
						log.Info(" [EVALUATE] Existing admin AppRole credentials verified",
							zap.Int("role_id_length", len(roleID)),
							zap.Int("secret_id_length", len(secretID)))
						return nil // IDEMPOTENT: Already configured, skip
					} else {
						log.Warn(" Existing admin credential files unreadable, will regenerate",
							zap.Error(readErr))
					}
				} else {
					log.Debug(" Admin secret ID file missing, will regenerate",
						zap.String("path", secretIDPath))
				}
			} else {
				log.Debug(" Admin role ID file missing, will regenerate",
					zap.String("path", roleIDPath))
			}
		}
	}

	log.Info(" [INTERVENE] Admin AppRole not fully configured, proceeding with setup")

	// Create or update admin AppRole in Vault
	roleID, secretID, err := EnsureAdminAppRole(rc, privilegedClient)
	if err != nil {
		log.Error(" Failed to ensure admin AppRole", zap.Error(err))
		return cerr.Wrap(err, "ensure admin AppRole")
	}

	log.Info(" Admin AppRole created/updated in Vault",
		zap.String("role_name", shared.AdminAppRoleName),
		zap.String("role_id", roleID))

	// Write credentials to disk
	if err := WriteAdminAppRoleFiles(rc, roleID, secretID); err != nil {
		log.Error(" Failed to write admin AppRole credentials to disk", zap.Error(err))
		return cerr.Wrap(err, "write admin AppRole credentials")
	}

	log.Info(" Admin AppRole credentials written to disk")

	// EVALUATE - Verify admin AppRole exists in Vault backend
	log.Info(" [EVALUATE] Verifying admin AppRole in Vault backend",
		zap.String("role_name", shared.AdminAppRoleName),
		zap.String("path", shared.AdminAppRoleRoleIDPath))

	roleIDReadback, err := privilegedClient.Logical().Read(shared.AdminAppRoleRoleIDPath)
	if err != nil {
		log.Error(" Failed to verify admin AppRole role-id in Vault after creation",
			zap.Error(err))
		return cerr.Wrap(err, "verify admin AppRole in Vault")
	}

	if roleIDReadback == nil || roleIDReadback.Data == nil {
		log.Error(" Admin AppRole role-id not found in Vault after creation")
		return cerr.New("admin AppRole verification failed: role-id not found in Vault")
	}

	storedRoleID, ok := roleIDReadback.Data["role_id"].(string)
	if !ok || storedRoleID == "" {
		log.Error(" Admin AppRole role-id is empty or invalid in Vault",
			zap.Any("data", roleIDReadback.Data))
		return cerr.New("admin AppRole verification failed: role-id invalid in Vault")
	}

	if storedRoleID != roleID {
		log.Error(" Admin AppRole role-id mismatch between file and Vault",
			zap.String("expected", roleID),
			zap.String("stored_in_vault", storedRoleID))
		return cerr.New("admin AppRole verification failed: role-id mismatch")
	}

	log.Info(" ✓ Admin AppRole verified in Vault backend",
		zap.String("role_id", roleID),
		zap.String("role_name", shared.AdminAppRoleName))

	log.Info(" ✓ Admin AppRole setup complete and verified",
		zap.String("role_name", shared.AdminAppRoleName),
		zap.String("purpose", "operational commands (policy updates, MFA repair, drift correction)"))

	return nil
}
