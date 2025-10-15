// pkg/vault/auth_approle.go
package vault

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	cerr "github.com/cockroachdb/errors"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/api/auth/approle"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// LoginAppRole authenticates to Vault using stored RoleID and SecretID.
func LoginAppRole(rc *eos_io.RuntimeContext) (*api.Client, error) {
	log := otelzap.Ctx(rc.Ctx)

	log.Info(" Creating Vault client for AppRole login")
	client, err := GetVaultClient(rc)
	if err != nil {
		log.Error(" Failed to create vault client", zap.Error(err))
		return nil, cerr.Wrap(err, "failed to create vault client")
	}

	log.Info(" Reading AppRole credentials from disk")
	roleID, secretID, err := readAppRoleCredsFromDisk(rc, client)
	if err != nil {
		log.Error(" Failed to read AppRole credentials", zap.Error(err))
		return nil, cerr.Wrap(err, "failed to read AppRole creds")
	}

	log.Info(" Creating AppRole auth method")
	auth, err := approle.NewAppRoleAuth(roleID, &approle.SecretID{
		FromString: secretID,
	}, approle.WithMountPath("auth/approle"))
	if err != nil {
		log.Error(" Failed to create AppRole auth", zap.Error(err))
		return nil, cerr.Wrap(err, "create approle auth")
	}

	log.Info(" Performing AppRole login")
	secret, err := client.Auth().Login(context.Background(), auth)
	if err != nil {
		log.Error(" AppRole login failed", zap.Error(err))
		return nil, cerr.Wrap(err, "approle login failed")
	}
	if secret == nil || secret.Auth == nil {
		log.Error(" No auth info returned from Vault AppRole login")
		return nil, cerr.New("no auth info returned from Vault approle login")
	}

	client.SetToken(secret.Auth.ClientToken)
	log.Info(" Successfully authenticated with Vault using AppRole",
		zap.String("token_accessor", secret.Auth.Accessor))
	return client, nil
}

func readAppRoleCredsFromDisk(rc *eos_io.RuntimeContext, client *api.Client) (string, string, error) {
	log := otelzap.Ctx(rc.Ctx)

	log.Info(" Reading RoleID from disk", zap.String("path", shared.AppRolePaths.RoleID))
	roleIDBytes, err := os.ReadFile(shared.AppRolePaths.RoleID)
	if err != nil {
		log.Error(" Failed to read first credential from disk",
			zap.String("path", shared.AppRolePaths.RoleID),
			zap.Error(err))
		return "", "", cerr.Wrap(err, "read credential from disk")
	}
	roleID := strings.TrimSpace(string(roleIDBytes))

	// VALIDATE: Ensure role_id is not empty and has valid format
	if roleID == "" {
		log.Error(" RoleID file is empty",
			zap.String("path", shared.AppRolePaths.RoleID))
		return "", "", cerr.New("role_id file is empty")
	}

	if len(roleID) < 36 { // UUIDs are at least 36 chars (format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)
		log.Error(" RoleID appears invalid (too short)",
			zap.String("path", shared.AppRolePaths.RoleID),
			zap.Int("length", len(roleID)),
			zap.Int("min_expected", 36))
		return "", "", cerr.Newf("role_id appears invalid: length %d < 36", len(roleID))
	}

	log.Info(" RoleID read and validated successfully",
		zap.Int("length", len(roleID)))

	log.Info(" Reading SecretID from disk", zap.String("path", shared.AppRolePaths.SecretID))
	secretIDBytes, err := os.ReadFile(shared.AppRolePaths.SecretID)
	if err != nil {
		log.Error(" Failed to read second credential from disk",
			zap.String("path", shared.AppRolePaths.SecretID),
			zap.Error(err))
		return "", "", cerr.Wrap(err, "read credential from disk")
	}
	secretIDRaw := strings.TrimSpace(string(secretIDBytes))

	// VALIDATE: Ensure secret_id is not empty
	if secretIDRaw == "" {
		log.Error(" SecretID file is empty",
			zap.String("path", shared.AppRolePaths.SecretID))
		return "", "", cerr.New("secret_id file is empty")
	}

	log.Debug(" SecretID read from disk",
		zap.Int("length", len(secretIDRaw)),
		zap.Bool("is_wrapped", strings.HasPrefix(secretIDRaw, "s.")))

	if strings.HasPrefix(secretIDRaw, "s.") {
		if client == nil {
			log.Error(" Cannot unwrap token: Vault client is nil")
			return "", "", cerr.New("failed to unwrap credential: Vault client is nil")
		}
		log.Info(" Detected wrapped SecretID token — unwrapping")
		secret, err := client.Logical().Unwrap(secretIDRaw)
		if err != nil {
			log.Error(" Failed to unwrap secret_id", zap.Error(err))
			return "", "", cerr.Wrap(err, "failed to unwrap credential")
		}
		if secret == nil || secret.Data == nil {
			log.Error(" Unwrapped SecretID is empty")
			return "", "", cerr.New("unwrapped credential is empty")
		}
		sid, ok := secret.Data["secret_id"].(string)
		if !ok {
			log.Error(" Unwrapped SecretID is malformed", zap.Any("data", secret.Data))
			return "", "", cerr.New("unwrapped credential is malformed")
		}
		log.Info(" SecretID unwrapped successfully")
		return roleID, sid, nil
	}

	log.Warn("SecretID is stored in plaintext. Consider using response wrapping.")
	return roleID, secretIDRaw, nil
}

// PhaseCreateAppRole provisions (or reuses) an AppRole and writes its creds to disk.
func PhaseCreateAppRole(rc *eos_io.RuntimeContext, client *api.Client, log *zap.Logger, opts shared.AppRoleOptions) (string, string, error) {
	if log == nil {
		return "", "", cerr.New("logger cannot be nil")
	}
	if client == nil {
		return "", "", cerr.New("Vault client cannot be nil")
	}

	log.Info(" [Phase 10] Creating AppRole for Eos")

	roleID, secretID, err := EnsureAppRole(rc, client, opts)
	if err != nil {
		log.Error(" Failed to ensure AppRole", zap.Error(err))
		return "", "", cerr.Wrap(err, "ensure AppRole")
	}

	log.Info(" AppRole provisioning complete ")
	return roleID, secretID, nil
}

// WriteAppRoleFiles writes RoleID & SecretID to disk (with correct owner/perm).
func WriteAppRoleFiles(rc *eos_io.RuntimeContext, roleID, secretID string) error {
	log := otelzap.Ctx(rc.Ctx)

	dir := filepath.Dir(shared.AppRolePaths.RoleID)
	rolePath := shared.AppRolePaths.RoleID
	secretPath := shared.AppRolePaths.SecretID

	log.Info("Starting AppRole credential file write operation",
		zap.String("directory", dir),
		zap.String("role_id_path", rolePath),
		zap.String("secret_id_path", secretPath),
		zap.String("target_owner", "vault"),
		zap.String("target_permissions", "0600"))

	// Use vault user instead of deprecated eos user
	uid, gid, err := eos_unix.LookupUser(rc.Ctx, "vault")
	if err != nil {
		log.Error("Failed to lookup vault user",
			zap.String("user", "vault"),
			zap.Error(err))
		return cerr.Wrapf(err, "lookup user %q", "vault")
	}

	log.Debug("Vault user resolved",
		zap.String("user", "vault"),
		zap.Int("uid", uid),
		zap.Int("gid", gid))

	// Recursively chown the directory
	log.Debug("Setting directory ownership recursively",
		zap.String("path", dir),
		zap.Int("uid", uid),
		zap.Int("gid", gid))

	if err := eos_unix.ChownR(rc.Ctx, dir, uid, gid); err != nil {
		log.Error("Failed to set directory ownership",
			zap.String("path", dir),
			zap.Int("uid", uid),
			zap.Int("gid", gid),
			zap.Error(err))
		return cerr.Wrapf(err, "chownR %s", dir)
	}

	log.Debug("Directory ownership set successfully",
		zap.String("path", dir))

	// Write RoleID
	log.Debug("Writing RoleID file",
		zap.String("path", rolePath),
		zap.Int("role_id_length", len(roleID)))

	if err := eos_unix.WriteFile(rc.Ctx, rolePath, []byte(roleID), 0o600, "vault"); err != nil {
		log.Error("Failed to write RoleID file",
			zap.String("path", rolePath),
			zap.Error(err))
		return cerr.Wrapf(err, "write file %s", rolePath)
	}

	// Write SecretID
	log.Debug("Writing SecretID file",
		zap.String("path", secretPath),
		zap.Int("secret_id_length", len(secretID)))

	if err := eos_unix.WriteFile(rc.Ctx, secretPath, []byte(secretID), 0o600, "vault"); err != nil {
		log.Error("Failed to write SecretID file",
			zap.String("path", secretPath),
			zap.Error(err))
		return cerr.Wrapf(err, "write file %s", secretPath)
	}

	// Final verification: check that vault user can actually read the files
	log.Debug("Verifying vault user can read credential files")

	// Verify role_id
	roleIDStat, err := os.Stat(rolePath)
	if err != nil {
		log.Warn("Failed to stat role_id file after writing",
			zap.String("path", rolePath),
			zap.Error(err))
	} else {
		log.Debug("RoleID file verification",
			zap.String("path", rolePath),
			zap.String("mode", roleIDStat.Mode().String()),
			zap.Int64("size", roleIDStat.Size()))
	}

	// Verify secret_id
	secretIDStat, err := os.Stat(secretPath)
	if err != nil {
		log.Warn("Failed to stat secret_id file after writing",
			zap.String("path", secretPath),
			zap.Error(err))
	} else {
		log.Debug("SecretID file verification",
			zap.String("path", secretPath),
			zap.String("mode", secretIDStat.Mode().String()),
			zap.Int64("size", secretIDStat.Size()))
	}

	log.Info("AppRole credentials written successfully",
		zap.String("role_file", rolePath),
		zap.String("secret_file", secretPath),
		zap.String("owner", "vault"),
		zap.String("permissions", "0600"))

	return nil
}

func refreshAppRoleCreds(rc *eos_io.RuntimeContext, client *api.Client) (string, string, error) {
	log := otelzap.Ctx(rc.Ctx)
	log.Info(" Requesting fresh AppRole credentials")

	log.Info(" Reading RoleID from Vault", zap.String("path", shared.AppRoleRoleIDPath))
	roleResp, err := client.Logical().Read(shared.AppRoleRoleIDPath)
	if err != nil {
		log.Error(" Failed to read role_id from Vault",
			zap.String("path", shared.AppRoleRoleIDPath),
			zap.Error(err))
		return "", "", cerr.Wrap(err, "read credential from vault")
	}
	roleID, ok := roleResp.Data["role_id"].(string)
	if !ok || roleID == "" {
		log.Error(" Invalid role_id in Vault response", zap.Any("data", roleResp.Data))
		return "", "", cerr.New("invalid credential in vault response")
	}
	log.Info(" RoleID retrieved")

	log.Info(" Generating new SecretID from Vault", zap.String("path", shared.AppRoleSecretIDPath))
	secretResp, err := client.Logical().Write(shared.AppRoleSecretIDPath, nil)
	if err != nil {
		log.Error(" Failed to generate secret_id",
			zap.String("path", shared.AppRoleSecretIDPath),
			zap.Error(err))
		return "", "", cerr.Wrap(err, "generate credential")
	}
	secretID, ok := secretResp.Data["secret_id"].(string)
	if !ok || secretID == "" {
		log.Error(" Invalid secret_id in Vault response", zap.Any("data", secretResp.Data))
		return "", "", cerr.New("invalid credential in vault response")
	}
	log.Info(" SecretID generated successfully")
	return roleID, secretID, nil
}

// EnsureAppRole sets up (or re-uses) the Vault AppRole and writes creds to disk.
func EnsureAppRole(rc *eos_io.RuntimeContext, client *api.Client, opts shared.AppRoleOptions) (string, string, error) {
	log := otelzap.Ctx(rc.Ctx)

	// If existing and not forced, reuse or refresh
	if !opts.ForceRecreate {
		if _, err := os.Stat(shared.AppRolePaths.RoleID); err == nil {
			log.Info("AppRole creds exist; reusing", zap.String("path", shared.AppRolePaths.RoleID))
			if opts.RefreshCreds {
				return refreshAppRoleCreds(rc, client)
			}
			return readAppRoleCredsFromDisk(rc, client)
		}
	}

	// Enable the mount
	if err := EnableAppRoleAuth(rc, client); err != nil {
		return "", "", cerr.Wrap(err, "enable approle auth")
	}

	// Create or update role
	if _, err := client.Logical().Write(shared.AppRolePath, shared.DefaultAppRoleData); err != nil {
		return "", "", cerr.Wrap(err, "write AppRole")
	}

	// Fetch fresh creds
	roleID, secretID, err := refreshAppRoleCreds(rc, client)
	if err != nil {
		return "", "", cerr.Wrap(err, "fetch AppRole creds")
	}

	// Persist to disk & honor context for tracing
	if err := WriteAppRoleFiles(rc, roleID, secretID); err != nil {
		return "", "", cerr.Wrap(err, "persist AppRole files")
	}

	return roleID, secretID, nil
}

func EnableAppRoleAuth(rc *eos_io.RuntimeContext, client *api.Client) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info(" Enabling AppRole auth method if needed...")

	// Log client details before making API call
	if token := client.Token(); token != "" {
		log.Info(" Making API call to enable AppRole auth",
			zap.String("vault_addr", client.Address()),
			zap.String("api_endpoint", "POST /v1/sys/auth/approle"))
	} else {
		log.Error(" No token set on client for AppRole auth enablement")
		return cerr.New("no token set on Vault client")
	}

	err := client.Sys().EnableAuthWithOptions("approle", &api.EnableAuthOptions{Type: "approle"})
	if err == nil {
		log.Info(" AppRole auth method enabled successfully")
		return nil
	}
	if strings.Contains(err.Error(), "path is already in use") {
		log.Info(" AppRole auth method already enabled", zap.Error(err))
		return nil
	}
	log.Error(" Failed to enable AppRole auth method",
		zap.Error(err),
		zap.String("vault_addr", client.Address()))
	return cerr.Wrap(err, "enable approle auth")
}
