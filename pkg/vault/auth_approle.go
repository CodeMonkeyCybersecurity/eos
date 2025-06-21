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

	log.Info("🔐 Creating Vault client for AppRole login")
	client, err := NewClient(rc)
	if err != nil {
		log.Error("❌ Failed to create vault client", zap.Error(err))
		return nil, cerr.Wrap(err, "failed to create vault client")
	}

	log.Info("📄 Reading AppRole credentials from disk")
	roleID, secretID, err := readAppRoleCredsFromDisk(rc, client)
	if err != nil {
		log.Error("❌ Failed to read AppRole credentials", zap.Error(err))
		return nil, cerr.Wrap(err, "failed to read AppRole creds")
	}

	log.Info("🔑 Creating AppRole auth method")
	auth, err := approle.NewAppRoleAuth(roleID, &approle.SecretID{
		FromString: secretID,
	}, approle.WithMountPath("auth/approle"))
	if err != nil {
		log.Error("❌ Failed to create AppRole auth", zap.Error(err))
		return nil, cerr.Wrap(err, "create approle auth")
	}

	log.Info("🔐 Performing AppRole login")
	secret, err := client.Auth().Login(context.Background(), auth)
	if err != nil {
		log.Error("❌ AppRole login failed", zap.Error(err))
		return nil, cerr.Wrap(err, "approle login failed")
	}
	if secret == nil || secret.Auth == nil {
		log.Error("❌ No auth info returned from Vault AppRole login")
		return nil, cerr.New("no auth info returned from Vault approle login")
	}

	client.SetToken(secret.Auth.ClientToken)
	log.Info("✅ Successfully authenticated with Vault using AppRole",
		zap.String("token_accessor", secret.Auth.Accessor))
	return client, nil
}

func readAppRoleCredsFromDisk(rc *eos_io.RuntimeContext, client *api.Client) (string, string, error) {
	log := otelzap.Ctx(rc.Ctx)

	log.Info("📄 Reading RoleID from disk", zap.String("path", shared.AppRolePaths.RoleID))
	roleIDBytes, err := os.ReadFile(shared.AppRolePaths.RoleID)
	if err != nil {
		log.Error("❌ Failed to read role_id from disk",
			zap.String("path", shared.AppRolePaths.RoleID),
			zap.Error(err))
		return "", "", cerr.Wrap(err, "read role identifier from disk")
	}
	roleID := strings.TrimSpace(string(roleIDBytes))
	log.Info("✅ RoleID read successfully")

	log.Info("📄 Reading SecretID from disk", zap.String("path", shared.AppRolePaths.SecretID))
	secretIDBytes, err := os.ReadFile(shared.AppRolePaths.SecretID)
	if err != nil {
		log.Error("❌ Failed to read secret_id from disk",
			zap.String("path", shared.AppRolePaths.SecretID),
			zap.Error(err))
		return "", "", cerr.Wrap(err, "read secret identifier from disk")
	}
	secretIDRaw := strings.TrimSpace(string(secretIDBytes))

	if strings.HasPrefix(secretIDRaw, "s.") {
		log.Info("🔐 Detected wrapped SecretID token — unwrapping")
		secret, err := client.Logical().Unwrap(secretIDRaw)
		if err != nil {
			log.Error("❌ Failed to unwrap secret_id", zap.Error(err))
			return "", "", cerr.Wrap(err, "failed to unwrap secret_id")
		}
		if secret == nil || secret.Data == nil {
			log.Error("❌ Unwrapped SecretID is empty")
			return "", "", cerr.New("unwrapped SecretID is empty")
		}
		sid, ok := secret.Data["secret_id"].(string)
		if !ok {
			log.Error("❌ Unwrapped SecretID is malformed", zap.Any("data", secret.Data))
			return "", "", cerr.New("unwrapped SecretID is malformed")
		}
		log.Info("✅ SecretID unwrapped successfully")
		return roleID, sid, nil
	}

	log.Warn("⚠️ SecretID is stored in plaintext. Consider using response wrapping.")
	return roleID, secretIDRaw, nil
}

// PhaseCreateAppRole provisions (or reuses) an AppRole and writes its creds to disk.
func PhaseCreateAppRole(rc *eos_io.RuntimeContext, client *api.Client, log *zap.Logger, opts shared.AppRoleOptions) (string, string, error) {

	log.Info("🔑 [Phase 10] Creating AppRole for Eos")

	roleID, secretID, err := EnsureAppRole(rc, client, opts)
	if err != nil {
		log.Error("❌ Failed to ensure AppRole", zap.Error(err))
		return "", "", cerr.Wrap(err, "ensure AppRole")
	}

	log.Info("✅ AppRole provisioning complete 🎉")
	return roleID, secretID, nil
}

// WriteAppRoleFiles writes RoleID & SecretID to disk (with correct owner/perm).
func WriteAppRoleFiles(rc *eos_io.RuntimeContext, roleID, secretID string) error {

	dir := filepath.Dir(shared.AppRolePaths.RoleID)
	otelzap.Ctx(rc.Ctx).Info("📁 Ensuring AppRole directory", zap.String("path", dir))

	// Lookup eos UID/GID
	uid, gid, err := eos_unix.LookupUser(rc.Ctx, shared.EosID)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Error("lookup eos user failed", zap.String("user", shared.EosID), zap.Error(err))
		return cerr.Wrapf(err, "lookup user %q", shared.EosID)
	}

	// Recursively chown the directory
	if err := eos_unix.ChownR(rc.Ctx, dir, uid, gid); err != nil {
		otelzap.Ctx(rc.Ctx).Error("chownR failed", zap.String("path", dir), zap.Error(err))
		return cerr.Wrapf(err, "chownR %s", dir)
	}

	// Write RoleID
	rolePath := shared.AppRolePaths.RoleID
	otelzap.Ctx(rc.Ctx).Debug("✏️ Writing RoleID", zap.String("path", rolePath))
	if err := eos_unix.WriteFile(rc.Ctx, rolePath, []byte(roleID), 0o600, shared.EosID); err != nil {
		return cerr.Wrapf(err, "write file %s", rolePath)
	}

	// Write SecretID
	secretPath := shared.AppRolePaths.SecretID
	otelzap.Ctx(rc.Ctx).Debug("✏️ Writing SecretID", zap.String("path", secretPath))
	if err := eos_unix.WriteFile(rc.Ctx, secretPath, []byte(secretID), 0o600, shared.EosID); err != nil {
		return cerr.Wrapf(err, "write file %s", secretPath)
	}

	otelzap.Ctx(rc.Ctx).Info("✅ AppRole credentials written",
		zap.String("role_file", rolePath),
		zap.String("secret_file", secretPath),
	)
	return nil
}

func refreshAppRoleCreds(rc *eos_io.RuntimeContext, client *api.Client) (string, string, error) {
	log := otelzap.Ctx(rc.Ctx)
	log.Info("🔑 Requesting fresh AppRole credentials")

	log.Info("📞 Reading RoleID from Vault", zap.String("path", shared.AppRoleRoleIDPath))
	roleResp, err := client.Logical().Read(shared.AppRoleRoleIDPath)
	if err != nil {
		log.Error("❌ Failed to read role_id from Vault",
			zap.String("path", shared.AppRoleRoleIDPath),
			zap.Error(err))
		return "", "", cerr.Wrap(err, "read role_id")
	}
	roleID, ok := roleResp.Data["role_id"].(string)
	if !ok || roleID == "" {
		log.Error("❌ Invalid role_id in Vault response", zap.Any("data", roleResp.Data))
		return "", "", cerr.New("invalid role_id in Vault response")
	}
	log.Info("✅ RoleID retrieved")

	log.Info("📞 Generating new SecretID from Vault", zap.String("path", shared.AppRoleSecretIDPath))
	secretResp, err := client.Logical().Write(shared.AppRoleSecretIDPath, nil)
	if err != nil {
		log.Error("❌ Failed to generate secret_id",
			zap.String("path", shared.AppRoleSecretIDPath),
			zap.Error(err))
		return "", "", cerr.Wrap(err, "generate secret_id")
	}
	secretID, ok := secretResp.Data["secret_id"].(string)
	if !ok || secretID == "" {
		log.Error("❌ Invalid secret_id in Vault response", zap.Any("data", secretResp.Data))
		return "", "", cerr.New("invalid secret_id in Vault response")
	}
	log.Info("✅ SecretID generated successfully")
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
	log.Info("📡 Enabling AppRole auth method if needed...")

	// Log client details before making API call
	if token := client.Token(); token != "" {
		log.Info("🔍 Making API call to enable AppRole auth",
			zap.String("vault_addr", client.Address()),
			zap.String("api_endpoint", "POST /v1/sys/auth/approle"))
	} else {
		log.Error("❌ No token set on client for AppRole auth enablement")
		return cerr.New("no token set on Vault client")
	}

	err := client.Sys().EnableAuthWithOptions("approle", &api.EnableAuthOptions{Type: "approle"})
	if err == nil {
		log.Info("✅ AppRole auth method enabled successfully")
		return nil
	}
	if strings.Contains(err.Error(), "path is already in use") {
		log.Info("✅ AppRole auth method already enabled", zap.Error(err))
		return nil
	}
	log.Error("❌ Failed to enable AppRole auth method",
		zap.Error(err),
		zap.String("vault_addr", client.Address()))
	return cerr.Wrap(err, "enable approle auth")
}
