// pkg/vault/phase10_enable_userpass.go

package vault

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/telemetry"
	cerr "github.com/cockroachdb/errors"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

//--------------------------------------------------------------------
// 10. Create Userpass Auth for EOS User
//--------------------------------------------------------------------

// PhaseEnableUserpass sets up the userpass auth method and creates the eos user.
func PhaseEnableUserpass(_ *api.Client, log *zap.Logger, password string) error {
	ctx, span := telemetry.Start(context.Background(), "vault.phase10_enable_userpass")
	defer span.End()

	client, err := GetRootClient()
	if err != nil {
		log.Error("get privileged Vault client failed", zap.Error(err))
		return cerr.Wrap(err, "get-root-client")
	}

	if password == "" {
		log.Warn("no password provided; prompting interactively")
		password, err = crypto.PromptPassword("Enter password for EOS Vault user:")
		if err != nil {
			return cerr.Wrap(err, "prompt password")
		}
	} else if err := crypto.ValidateStrongPassword(password); err != nil {
		return cerr.Wrap(err, "validate provided password")
	}

	if err := EnableUserpassAuth(client); err != nil {
		return cerr.Wrap(err, "enable-userpass-auth")
	}
	if err := EnsureUserpassUser(client, ctx, password); err != nil {
		return cerr.Wrap(err, "ensure-userpass-user")
	}

	log.Info("userpass auth and EOS user configured")
	return nil
}

// EnableUserpassAuth enables the userpass auth method if it is not already mounted.
func EnableUserpassAuth(client *api.Client) error {
	zap.L().Info("📡 Enabling userpass auth method if needed...")

	err := client.Sys().EnableAuthWithOptions("userpass", &api.EnableAuthOptions{Type: "userpass"})
	if err == nil {
		zap.L().Info("✅ Userpass auth method enabled")
		return nil
	}

	if strings.Contains(err.Error(), "path is already in use") {
		zap.L().Warn("⚠️ Userpass auth method already enabled", zap.Error(err))
		return nil
	}

	zap.L().Error("❌ Failed to enable userpass auth method", zap.Error(err))
	return fmt.Errorf("enable userpass auth: %w", err)
}

// EnsureUserpassUser ensures the eos user exists under userpass auth.
func EnsureUserpassUser(client *api.Client, ctx context.Context, password string) error {
	zap.S().Infow("ensuring EOS user exists", "path", shared.EosUserpassPath)
	if sec, _ := client.Logical().Read(shared.EosUserpassPath); sec != nil {
		zap.S().Warn("EOS user already exists; skipping")
		return nil
	}
	if _, err := client.Logical().Write(shared.EosUserpassPath, shared.UserDataTemplate(password)); err != nil {
		return cerr.Wrap(err, "create-userpass-user")
	}
	zap.S().Infow("EOS user created under userpass auth")

	// fallback save
	if err := WriteUserpassCredentialsFallback(ctx, password); err != nil {
		return cerr.Wrap(err, "write-credentials-fallback")
	}
	return nil
}

// WriteUserpassCredentialsFallback writes the EOS user’s password to disk and Vault KV,
// with telemetry, structured logging, and cockroachdb‐style error wrapping.
func WriteUserpassCredentialsFallback(ctx context.Context, password string) error {
	ctx, span := telemetry.Start(ctx, "vault.write_userpass_credentials_fallback")
	defer span.End()
	zap.S().Infow("saving fallback copy")

	dir := filepath.Dir(shared.EosUserPassPasswordFile)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return cerr.Wrapf(err, "mkdir %s", dir)
	}
	if err := eos_unix.WriteFile(
		shared.EosUserPassPasswordFile,
		[]byte(password+"\n"),
		0o600,
		shared.EosID,
	); err != nil {
		return cerr.Wrapf(err, "write file %s", shared.EosUserPassPasswordFile)
	}
	zap.S().Infow("fallback file written", "path", shared.EosUserPassPasswordFile)

	uid, gid, err := eos_unix.LookupUser(shared.EosID)
	if err != nil {
		return cerr.Wrapf(err, "lookup user %s", shared.EosID)
	}
	if err := eos_unix.ChownR(ctx, shared.SecretsDir, uid, gid); err != nil {
		zap.S().Warnw("chownR failed; continuing", "dir", shared.SecretsDir, "err", err)
	}

	client, err := GetRootClient()
	if err != nil {
		return cerr.Wrap(err, "get-root-client")
	}
	if err := WriteKVv2(client, "secret", "eos/userpass-password", shared.FallbackSecretsTemplate(password)); err != nil {
		return cerr.Wrap(err, "write-kv-v2")
	}
	zap.S().Infow("secret written to Vault KV", "path", "secret/eos/userpass-password")
	return nil
}
