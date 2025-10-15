// pkg/vault/phase10_create_approle_auth.go

package vault

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	cerr "github.com/cockroachdb/errors"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

//--------------------------------------------------------------------
// 10. Create AppRole for Eos
//--------------------------------------------------------------------

// EnableAppRoleFlow(client, log, opts)
// ├── EnableAppRoleAuth(client)
// │    └── client.Sys().EnableAuthWithOptions("approle")
// ├── EnsureAppRole(client, log, opts)
// │    ├── os.Stat(RoleIDPath)
// │    ├── vault.refreshAppRoleCreds(client) (optional)
// │    ├── vault.EnableAppRoleAuth(client) (if needed)
// │    ├── client.Logical().Write(shared.RolePath, roleData)
// │    ├── vault.refreshAppRoleCreds(client)
// │    └── vault.WriteAppRoleFiles(roleID, secretID)
// │         ├── eos_unix.EnsureOwnedDir
// │         └── eos_unix.WriteOwnedFile(role_id, secret_id)
// └── Done

// PhaseEnableAppRole provisions (or re-uses) an AppRole and writes its creds to disk.
func PhaseEnableAppRole(
	rc *eos_io.RuntimeContext,
	client *api.Client,
	log *zap.Logger,
	opts shared.AppRoleOptions,
) error {

	log.Info(" [Phase10b] Setting up Vault AppRole", zap.Any("options", opts))

	// Get privileged client with root token for auth method management
	log.Info(" Getting privileged client for AppRole setup")
	privilegedClient, err := GetRootClient(rc)
	if err != nil {
		log.Error(" Failed to get privileged Vault client for AppRole setup", zap.Error(err))
		return cerr.Wrap(err, "get privileged client")
	}

	// Log that we have a privileged client ready
	if privToken := privilegedClient.Token(); privToken != "" {
		log.Info(" Using privileged client for AppRole operations")
	}

	// 2) Ensure the auth method is mounted
	if err := EnableAppRoleAuth(rc, privilegedClient); err != nil {
		log.Error(" Failed to enable AppRole auth method", zap.Error(err))
		return cerr.Wrapf(err, "enable approle auth")
	}
	log.Info(" AppRole auth method is enabled (or already present)")

	// 3) Provision or reuse the role (using privileged client)
	roleID, secretID, err := EnsureAppRole(rc, privilegedClient, opts)
	if err != nil {
		log.Error(" Failed to ensure AppRole credentials", zap.Error(err))
		return cerr.Wrapf(err, "ensure AppRole")
	}
	log.Debug("AppRole credentials obtained successfully")

	// 4) Persist them to disk
	if err := WriteAppRoleFiles(rc, roleID, secretID); err != nil {
		log.Error("Failed to write AppRole credential files", zap.Error(err))
		return cerr.Wrapf(err, "write AppRole files")
	}

	// 5) VERIFY: Confirm Vault actually has this AppRole registered
	log.Info(" Verifying AppRole exists in Vault backend")
	roleIDReadback, err := privilegedClient.Logical().Read("auth/approle/role/eos-agent/role-id")
	if err != nil {
		log.Error(" Failed to verify AppRole role-id in Vault after creation",
			zap.Error(err))
		return cerr.Wrap(err, "verify AppRole in Vault")
	}

	if roleIDReadback == nil || roleIDReadback.Data == nil {
		log.Error(" AppRole role-id not found in Vault after creation")
		return cerr.New("AppRole verification failed: role-id not found in Vault")
	}

	storedRoleID, ok := roleIDReadback.Data["role_id"].(string)
	if !ok || storedRoleID == "" {
		log.Error(" AppRole role-id is empty or invalid in Vault",
			zap.Any("data", roleIDReadback.Data))
		return cerr.New("AppRole verification failed: role-id invalid in Vault")
	}

	if storedRoleID != roleID {
		log.Error(" AppRole role-id mismatch between file and Vault",
			zap.String("expected", roleID),
			zap.String("stored_in_vault", storedRoleID))
		return cerr.New("AppRole verification failed: role-id mismatch")
	}

	log.Info(" AppRole verified in Vault backend",
		zap.String("role_id", roleID),
		zap.String("role_name", "eos-agent"))

	log.Info(" AppRole setup complete and verified", zap.String("role_id", roleID))
	return nil
}

// EnableAppRoleFlow enables AppRole authentication method and provisions Eos-specific AppRole credentials.
func EnableAppRoleFlow(
	rc *eos_io.RuntimeContext,
	client *api.Client,
	log *zap.Logger,
	opts shared.AppRoleOptions,
) error {

	log.Info("🪪 [Phase10b] Starting AppRole setup", zap.Any("options", opts))

	// 2) mount auth
	if err := EnableAppRoleAuth(rc, client); err != nil {
		log.Error("failed to enable AppRole auth", zap.Error(err))
		return cerr.Wrapf(err, "enable approle auth")
	}

	// 3) provision or reuse
	roleID, secretID, err := EnsureAppRole(rc, client, opts)
	if err != nil {
		log.Error("failed to ensure AppRole", zap.Error(err))
		return cerr.Wrapf(err, "ensure AppRole")
	}
	log.Debug("AppRole credentials", zap.String("role_id", roleID))

	// 4) persist to disk
	if err := WriteAppRoleFiles(rc, roleID, secretID); err != nil {
		log.Error("failed to write AppRole files", zap.Error(err))
		return cerr.Wrapf(err, "write AppRole files")
	}

	// 5) VERIFY: Confirm Vault actually has this AppRole registered
	log.Info(" Verifying AppRole exists in Vault backend")
	roleIDReadback, err := client.Logical().Read("auth/approle/role/eos-agent/role-id")
	if err != nil {
		log.Error(" Failed to verify AppRole role-id in Vault after creation",
			zap.Error(err))
		return cerr.Wrap(err, "verify AppRole in Vault")
	}

	if roleIDReadback == nil || roleIDReadback.Data == nil {
		log.Error(" AppRole role-id not found in Vault after creation")
		return cerr.New("AppRole verification failed: role-id not found in Vault")
	}

	storedRoleID, ok := roleIDReadback.Data["role_id"].(string)
	if !ok || storedRoleID == "" {
		log.Error(" AppRole role-id is empty or invalid in Vault",
			zap.Any("data", roleIDReadback.Data))
		return cerr.New("AppRole verification failed: role-id invalid in Vault")
	}

	if storedRoleID != roleID {
		log.Error(" AppRole role-id mismatch between file and Vault",
			zap.String("expected", roleID),
			zap.String("stored_in_vault", storedRoleID))
		return cerr.New("AppRole verification failed: role-id mismatch")
	}

	log.Info(" AppRole verified in Vault backend",
		zap.String("role_id", roleID),
		zap.String("role_name", "eos-agent"))

	log.Info(" AppRole setup complete and verified", zap.String("role_id", roleID))
	return nil
}
