// pkg/vault/phase10_enable_userpass.go

package vault

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

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
//
// Idempotency: Safe to re-run. If user exists, skips creation and ensures bootstrap secret exists.
// This allows recovery from partial failures where user was created but secret wasn't persisted.
// Note: Does not update existing user's password - that requires explicit password change operation.
func PhaseEnableUserpass(rc *eos_io.RuntimeContext, _ *api.Client, log *zap.Logger, password string) error {

	client, err := GetPrivilegedClient(rc)
	if err != nil {
		log.Error("get privileged Vault client failed", zap.Error(err))
		return cerr.Wrap(err, "get-privileged-client")
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
	log := otelzap.Ctx(rc.Ctx)

	// ASSESS: Check current auth methods
	log.Info(" [ASSESS] Checking if userpass auth method is already enabled")
	auths, err := client.Sys().ListAuth()
	if err != nil {
		log.Warn("Failed to list existing auth methods", zap.Error(err))
		// Continue anyway - we'll find out if it exists when we try to enable it
	} else {
		log.Debug("Current auth methods",
			zap.Int("count", len(auths)),
			zap.Any("methods", getAuthMethodNames(auths)))

		// Check if userpass is already mounted
		for path, method := range auths {
			if method.Type == "userpass" || strings.HasPrefix(path, "userpass") {
				log.Info(" [EVALUATE] Userpass auth method already enabled",
					zap.String("path", path),
					zap.String("type", method.Type))
				return nil
			}
		}
		log.Info(" Userpass auth method not found, will enable it")
	}

	// INTERVENE: Enable userpass auth method
	log.Info(" [INTERVENE] Enabling userpass auth method at path 'userpass/'")
	err = client.Sys().EnableAuthWithOptions("userpass", &api.EnableAuthOptions{Type: "userpass"})
	if err == nil {
		log.Info(" [EVALUATE] Userpass auth method enabled successfully")

		// Verify it was actually enabled
		auths, verifyErr := client.Sys().ListAuth()
		if verifyErr == nil {
			for path, method := range auths {
				if method.Type == "userpass" {
					log.Info(" Verification: Userpass auth method confirmed in auth list",
						zap.String("path", path),
						zap.String("accessor", method.Accessor))
					break
				}
			}
		}
		return nil
	}

	// Handle "already enabled" error gracefully
	if strings.Contains(err.Error(), "path is already in use") {
		log.Info(" [EVALUATE] Userpass auth method already enabled (detected via error)",
			zap.String("error_message", err.Error()))
		return nil
	}

	log.Error(" [EVALUATE] Failed to enable userpass auth method",
		zap.Error(err),
		zap.String("error_detail", err.Error()))
	return fmt.Errorf("enable userpass auth: %w", err)
}

// getAuthMethodNames extracts auth method names for logging
func getAuthMethodNames(auths map[string]*api.AuthMount) []string {
	names := make([]string, 0, len(auths))
	for path := range auths {
		names = append(names, path)
	}
	return names
}

// EnsureUserpassUser ensures the eos user exists under userpass auth.
func EnsureUserpassUser(client *api.Client, rc *eos_io.RuntimeContext, password string) error {
	log := otelzap.Ctx(rc.Ctx)

	// ASSESS: Check if eos user already exists
	log.Info(" [ASSESS] Checking if eos user exists in userpass auth",
		zap.String("path", shared.EosUserpassPath))

	existingUser, readErr := client.Logical().Read(shared.EosUserpassPath)
	if readErr != nil {
		log.Warn("Failed to read existing user (may not exist yet)",
			zap.Error(readErr),
			zap.String("path", shared.EosUserpassPath))
	}

	if existingUser != nil {
		log.Info(" [EVALUATE] Eos user already exists in userpass auth",
			zap.String("path", shared.EosUserpassPath),
			zap.Any("data_keys", getSecretDataKeys(existingUser)))
		log.Info("terminal prompt: ✓ Eos userpass user already configured (skipping creation)")

		// Still write fallback credentials in case they were lost
		log.Info(" Ensuring fallback credentials are saved")
		if err := WriteUserpassCredentialsFallback(rc, password); err != nil {
			return cerr.Wrap(err, "write-credentials-fallback")
		}
		return nil
	}

	// INTERVENE: Create eos user
	log.Info(" [INTERVENE] Creating eos user in userpass auth",
		zap.String("path", shared.EosUserpassPath),
		zap.String("username", shared.EosID))

	userData := shared.UserDataTemplate(password)
	log.Debug("User data template prepared",
		zap.Any("template_keys", getMapKeys(userData)))

	writeResp, err := client.Logical().Write(shared.EosUserpassPath, userData)
	if err != nil {
		log.Error(" [EVALUATE] Failed to create userpass user",
			zap.Error(err),
			zap.String("path", shared.EosUserpassPath))
		return cerr.Wrap(err, "create-userpass-user")
	}

	log.Info(" [EVALUATE] Eos user created successfully in userpass auth",
		zap.String("path", shared.EosUserpassPath))

	// CRITICAL UX FIX: Communicate login credentials to user
	log.Info("terminal prompt: ✓ Vault userpass user created successfully")
	log.Info(fmt.Sprintf("terminal prompt:   Username: %s", shared.EosID))
	log.Info(fmt.Sprintf("terminal prompt:   Password: [saved to %s]", shared.EosUserPassPasswordFile))
	log.Info(fmt.Sprintf("terminal prompt:   Login: vault login -method=userpass username=%s", shared.EosID))

	// Verify user was created by reading it back
	log.Info(" Verifying user creation by reading back from Vault")
	verifyUser, verifyErr := client.Logical().Read(shared.EosUserpassPath)
	if verifyErr != nil {
		log.Warn("Failed to verify user creation", zap.Error(verifyErr))
	} else if verifyUser == nil {
		log.Warn("User verification returned nil - user may not have been created properly")
	} else {
		log.Info(" User verification successful",
			zap.String("path", shared.EosUserpassPath),
			zap.Any("response_keys", getSecretDataKeys(verifyUser)))
	}

	if writeResp != nil && writeResp.Warnings != nil && len(writeResp.Warnings) > 0 {
		log.Warn("Vault returned warnings during user creation",
			zap.Strings("warnings", writeResp.Warnings))
	}

	// Write fallback credentials
	log.Info(" Writing fallback credentials to disk and KV store")
	if err := WriteUserpassCredentialsFallback(rc, password); err != nil {
		return cerr.Wrap(err, "write-credentials-fallback")
	}

	return nil
}

// getSecretDataKeys extracts keys from a Vault secret for logging (avoids logging sensitive data)
func getSecretDataKeys(secret *api.Secret) []string {
	if secret == nil || secret.Data == nil {
		return []string{}
	}
	keys := make([]string, 0, len(secret.Data))
	for k := range secret.Data {
		keys = append(keys, k)
	}
	return keys
}

// WriteUserpassCredentialsFallback writes the Eos user's password to disk and Vault KV,
// with telemetry, structured logging, and cockroachdb‐style error wrapping.
func WriteUserpassCredentialsFallback(rc *eos_io.RuntimeContext, password string) error {
	log := otelzap.Ctx(rc.Ctx)

	// ASSESS: Check if secrets directory exists
	log.Info(" [ASSESS] Preparing to save fallback credentials")
	dir := filepath.Dir(shared.EosUserPassPasswordFile)

	if stat, err := os.Stat(dir); err == nil {
		log.Debug("Secrets directory already exists",
			zap.String("path", dir),
			zap.String("mode", stat.Mode().String()))
	} else if os.IsNotExist(err) {
		log.Info(" Secrets directory does not exist, will create it",
			zap.String("path", dir))
	}

	// INTERVENE: Create secrets directory
	log.Info(" [INTERVENE] Creating secrets directory",
		zap.String("path", dir),
		zap.String("permissions", "0700"))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		log.Error(" Failed to create secrets directory",
			zap.String("path", dir),
			zap.Error(err))
		return cerr.Wrapf(err, "mkdir %s", dir)
	}

	// Verify directory was created
	if stat, err := os.Stat(dir); err == nil {
		log.Debug("Secrets directory ready",
			zap.String("path", dir),
			zap.String("mode", stat.Mode().String()))
	}

	// Write password file
	log.Info(" Writing fallback password file",
		zap.String("path", shared.EosUserPassPasswordFile),
		zap.String("permissions", "0600"),
		zap.String("owner", "vault"))

	if err := eos_unix.WriteFile(
		rc.Ctx,
		shared.EosUserPassPasswordFile,
		[]byte(password+"\n"),
		0o600,
		"vault",
	); err != nil {
		log.Error(" Failed to write fallback password file",
			zap.String("path", shared.EosUserPassPasswordFile),
			zap.Error(err))
		return cerr.Wrapf(err, "write file %s", shared.EosUserPassPasswordFile)
	}

	log.Info(" [EVALUATE] Fallback password file written successfully",
		zap.String("path", shared.EosUserPassPasswordFile))

	// Verify file was written with correct permissions
	if stat, err := os.Stat(shared.EosUserPassPasswordFile); err == nil {
		log.Debug("Password file verification",
			zap.String("path", shared.EosUserPassPasswordFile),
			zap.String("mode", stat.Mode().String()),
			zap.Int64("size", stat.Size()))
	}

	// Set ownership on secrets directory
	log.Info(" Setting ownership on secrets directory",
		zap.String("path", shared.SecretsDir),
		zap.String("owner", "vault:vault"))

	uid, gid, err := eos_unix.LookupUser(rc.Ctx, "vault")
	if err != nil {
		log.Error(" Failed to lookup vault user for ownership",
			zap.String("user", "vault"),
			zap.Error(err))
		return cerr.Wrapf(err, "lookup user %s", "vault")
	}

	log.Debug("Vault user IDs resolved",
		zap.Int("uid", uid),
		zap.Int("gid", gid))

	if err := eos_unix.ChownR(rc.Ctx, shared.SecretsDir, uid, gid); err != nil {
		log.Warn("Failed to set recursive ownership on secrets directory (non-fatal)",
			zap.String("dir", shared.SecretsDir),
			zap.Error(err))
		// Continue anyway - file operations may still work
	} else {
		log.Info(" Ownership set successfully on secrets directory")
	}

	// Write bootstrap password to Vault KV using unified abstraction
	// with built-in write-then-verify (replaces 120 lines of inline verification)
	// NOTE: This is a temporary bootstrap password for initial setup only.
	// It will be deleted after successful TOTP verification in Phase 13.
	client, err := GetPrivilegedClient(rc)
	if err != nil {
		log.Error(" Failed to get privileged client for KV write",
			zap.Error(err))
		return cerr.Wrap(err, "get-privileged-client")
	}

	// Get underlying *zap.Logger from otelzap.LoggerWithCtx
	zapLogger := log.Logger().Logger
	kv := NewEosKVv2Store(client, "secret", zapLogger)
	if err := WriteBootstrapPassword(rc.Ctx, kv, password, zapLogger); err != nil {
		return cerr.Wrap(err, "write-bootstrap-password")
	}

	// State transition logging for forensic analysis
	log.Info("Phase 10a State Transition",
		zap.String("phase", "10a"),
		zap.String("from_state", "userpass_user_created"),
		zap.String("to_state", "bootstrap_password_persisted"),
		zap.String("secret_path", "secret/eos/bootstrap"),
		zap.String("completion_status", "success"),
		zap.Time("completed_at", time.Now()))

	return nil
}
