// pkg/vault/auth_approle.go
package vault

import (
	"context"
	"fmt"
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
	client, err := NewClient(rc)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}

	roleID, secretID, err := readAppRoleCredsFromDisk(rc, client)
	if err != nil {
		return nil, fmt.Errorf("failed to read AppRole creds: %w", err)
	}

	auth, err := approle.NewAppRoleAuth(roleID, &approle.SecretID{
		FromString: secretID,
	}, approle.WithMountPath("auth/approle"))
	if err != nil {
		return nil, fmt.Errorf("create approle auth: %w", err)
	}

	secret, err := client.Auth().Login(context.Background(), auth)
	if err != nil {
		return nil, fmt.Errorf("approle login failed: %w", err)
	}
	if secret == nil || secret.Auth == nil {
		return nil, fmt.Errorf("no auth info returned from Vault approle login")
	}

	client.SetToken(secret.Auth.ClientToken)
	otelzap.Ctx(rc.Ctx).Info("✅ Successfully authenticated with Vault using AppRole")
	return client, nil
}

func readAppRoleCredsFromDisk(rc *eos_io.RuntimeContext, client *api.Client) (string, string, error) {
	roleIDBytes, err := os.ReadFile(shared.AppRolePaths.RoleID)
	if err != nil {
		return "", "", fmt.Errorf("read role_id from disk: %w", err)
	}
	roleID := strings.TrimSpace(string(roleIDBytes))

	secretIDBytes, err := os.ReadFile(shared.AppRolePaths.SecretID)
	if err != nil {
		return "", "", fmt.Errorf("read secret_id from disk: %w", err)
	}
	secretIDRaw := strings.TrimSpace(string(secretIDBytes))

	if strings.HasPrefix(secretIDRaw, "s.") {
		otelzap.Ctx(rc.Ctx).Info("🔐 Detected wrapped SecretID token — unwrapping")
		secret, err := client.Logical().Unwrap(secretIDRaw)
		if err != nil {
			return "", "", fmt.Errorf("failed to unwrap secret_id: %w", err)
		}
		if secret == nil || secret.Data == nil {
			return "", "", fmt.Errorf("unwrapped SecretID is empty")
		}
		sid, ok := secret.Data["secret_id"].(string)
		if !ok {
			return "", "", fmt.Errorf("unwrapped SecretID is malformed")
		}
		return roleID, sid, nil
	}

	otelzap.Ctx(rc.Ctx).Warn("⚠️ SecretID is stored in plaintext. Consider using response wrapping.")
	return roleID, secretIDRaw, nil
}

// PhaseCreateAppRole provisions (or reuses) an AppRole and writes its creds to disk.
func PhaseCreateAppRole(rc *eos_io.RuntimeContext, client *api.Client, log *zap.Logger, opts shared.AppRoleOptions) (string, string, error) {

	log.Info("🔑 [Phase 10] Creating AppRole for EOS")

	roleID, secretID, err := EnsureAppRole(rc, client, opts)
	if err != nil {
		log.Error("❌ Failed to ensure AppRole", zap.Error(err))
		return "", "", cerr.Wrap(err, "ensure AppRole")
	}

	log.Info("✅ AppRole provisioning complete 🎉",
		zap.String("role_id", roleID),
		zap.String("secret_id", secretID),
	)
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
	if err := eos_unix.WriteFile(rc.Ctx, rolePath, []byte(roleID+"\n"), 0o600, shared.EosID); err != nil {
		return cerr.Wrapf(err, "write file %s", rolePath)
	}

	// Write SecretID
	secretPath := shared.AppRolePaths.SecretID
	otelzap.Ctx(rc.Ctx).Debug("✏️ Writing SecretID", zap.String("path", secretPath))
	if err := eos_unix.WriteFile(rc.Ctx, secretPath, []byte(secretID+"\n"), 0o600, shared.EosID); err != nil {
		return cerr.Wrapf(err, "write file %s", secretPath)
	}

	otelzap.Ctx(rc.Ctx).Info("✅ AppRole credentials written",
		zap.String("role_file", rolePath),
		zap.String("secret_file", secretPath),
	)
	return nil
}

func refreshAppRoleCreds(rc *eos_io.RuntimeContext, client *api.Client) (string, string, error) {
	otelzap.Ctx(rc.Ctx).Debug("🔑 Requesting fresh AppRole credentials")
	roleResp, err := client.Logical().Read(shared.AppRoleRoleIDPath)
	if err != nil {
		return "", "", fmt.Errorf("read role_id: %w", err)
	}
	roleID, ok := roleResp.Data["role_id"].(string)
	if !ok || roleID == "" {
		return "", "", fmt.Errorf("invalid role_id in Vault response")
	}

	secretResp, err := client.Logical().Write(shared.AppRoleSecretIDPath, nil)
	if err != nil {
		return "", "", fmt.Errorf("generate secret_id: %w", err)
	}
	secretID, ok := secretResp.Data["secret_id"].(string)
	if !ok || secretID == "" {
		return "", "", fmt.Errorf("invalid secret_id in Vault response")
	}
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
	otelzap.Ctx(rc.Ctx).Info("📡 Enabling AppRole auth method if needed...")
	err := client.Sys().EnableAuthWithOptions("approle", &api.EnableAuthOptions{Type: "approle"})
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "path is already in use") {
		otelzap.Ctx(rc.Ctx).Warn("⚠️ AppRole auth method may already be enabled", zap.Error(err))
		return nil
	}
	otelzap.Ctx(rc.Ctx).Error("❌ Failed to enable AppRole auth method", zap.Error(err))
	return fmt.Errorf("enable approle auth: %w", err)
}
