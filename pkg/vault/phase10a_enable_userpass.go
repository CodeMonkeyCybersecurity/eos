// pkg/vault/phase10_enable_userpass.go

package vault

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	cerr "github.com/cockroachdb/errors"
	"github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

//--------------------------------------------------------------------
// 10. Create Userpass Auth for Eos User
//--------------------------------------------------------------------

// PhaseEnableUserpass sets up the userpass auth method and creates the eos user.
func PhaseEnableUserpass(rc *eos_io.RuntimeContext, _ *api.Client, log *zap.Logger, password string) error {

	client, err := GetRootClient(rc)
	if err != nil {
		log.Error("get privileged Vault client failed", zap.Error(err))
		return cerr.Wrap(err, "get-root-client")
	}

	if password == "" {
		log.Warn("no password provided; prompting interactively")
		password, err = crypto.PromptPassword(rc, "Enter password for Eos Vault user:")
		if err != nil {
			return cerr.Wrap(err, "prompt password")
		}
	} else if err := crypto.ValidateStrongPassword(rc.Ctx, password); err != nil {
		return cerr.Wrap(err, "validate provided password")
	}

	if err := EnableUserpassAuth(rc, client); err != nil {
		return cerr.Wrap(err, "enable-userpass-auth")
	}
	if err := EnsureUserpassUser(client, rc, password); err != nil {
		return cerr.Wrap(err, "ensure-userpass-user")
	}

	log.Info("userpass auth and Eos user configured")
	return nil
}

// EnableUserpassAuth enables the userpass auth method if it is not already mounted.
func EnableUserpassAuth(rc *eos_io.RuntimeContext, client *api.Client) error {
	otelzap.Ctx(rc.Ctx).Info(" Enabling userpass auth method if needed...")

	err := client.Sys().EnableAuthWithOptions("userpass", &api.EnableAuthOptions{Type: "userpass"})
	if err == nil {
		otelzap.Ctx(rc.Ctx).Info(" Userpass auth method enabled")
		return nil
	}

	if strings.Contains(err.Error(), "path is already in use") {
		otelzap.Ctx(rc.Ctx).Warn("Userpass auth method already enabled", zap.Error(err))
		return nil
	}

	otelzap.Ctx(rc.Ctx).Error(" Failed to enable userpass auth method", zap.Error(err))
	return fmt.Errorf("enable userpass auth: %w", err)
}

// EnsureUserpassUser ensures the eos user exists under userpass auth.
func EnsureUserpassUser(client *api.Client, rc *eos_io.RuntimeContext, password string) error {
	zap.S().Infow("ensuring Eos user exists", "path", shared.EosUserpassPath)
	if sec, _ := client.Logical().Read(shared.EosUserpassPath); sec != nil {
		zap.S().Warn("Eos user already exists; skipping")
		return nil
	}
	if _, err := client.Logical().Write(shared.EosUserpassPath, shared.UserDataTemplate(password)); err != nil {
		return cerr.Wrap(err, "create-userpass-user")
	}
	zap.S().Infow("Eos user created under userpass auth")

	// fallback save
	if err := WriteUserpassCredentialsFallback(rc, password); err != nil {
		return cerr.Wrap(err, "write-credentials-fallback")
	}
	return nil
}

// WriteUserpassCredentialsFallback writes the Eos user’s password to disk and Vault KV,
// with telemetry, structured logging, and cockroachdb‐style error wrapping.
func WriteUserpassCredentialsFallback(rc *eos_io.RuntimeContext, password string) error {
	zap.S().Infow("saving fallback copy")

	dir := filepath.Dir(shared.EosUserPassPasswordFile)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return cerr.Wrapf(err, "mkdir %s", dir)
	}
	if err := eos_unix.WriteFile(
		rc.Ctx,
		shared.EosUserPassPasswordFile,
		[]byte(password+"\n"),
		0o600,
		"vault",
	); err != nil {
		return cerr.Wrapf(err, "write file %s", shared.EosUserPassPasswordFile)
	}
	zap.S().Infow("fallback file written", "path", shared.EosUserPassPasswordFile)

	// Use vault user instead of deprecated eos user
	uid, gid, err := eos_unix.LookupUser(rc.Ctx, "vault")
	if err != nil {
		return cerr.Wrapf(err, "lookup user %s", "vault")
	}
	if err := eos_unix.ChownR(rc.Ctx, shared.SecretsDir, uid, gid); err != nil {
		zap.S().Warnw("chownR failed; continuing", "dir", shared.SecretsDir, "err", err)
	}

	client, err := GetRootClient(rc)
	if err != nil {
		return cerr.Wrap(err, "get-root-client")
	}
	if err := WriteKVv2(rc, client, "secret", "eos/userpass-password", shared.FallbackSecretsTemplate(password)); err != nil {
		return cerr.Wrap(err, "write-kv-v2")
	}
	zap.S().Infow("secret written to Vault KV", "path", "secret/eos/userpass-password")
	return nil
}
