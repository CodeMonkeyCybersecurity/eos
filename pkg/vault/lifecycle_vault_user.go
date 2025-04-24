// pkg/vault/lifecycle_vault_user.go

package vault

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)


// ## 11. Render Vault Agent Config

// - `RenderVaultAgentConfig(roleID, secretID string) ([]byte, error)`
// - `WriteVaultAgentConfig(config []byte) error`

// ---



// StoreUserSecret reads an SSH key and stores full user credentials in Vault.
func StoreUserSecret(username, password, keyPath string, log *zap.Logger) error {
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("failed to read SSH key from %s: %w", keyPath, err)
	}
	secret := UserSecret{
		Username: username,
		Password: password,
		SSHKey:   string(keyData),
	}
	return WriteToVaultAt("secret", UserSecretPath(username), &secret, log)
}

// LoadUserSecret retrieves and validates a user's secret from Vault.
func LoadUserSecret(client *api.Client, username string, log *zap.Logger) (*UserSecret, error) {
	var secret UserSecret
	if err := ReadFromVaultAt(context.Background(), "secret", userVaultPath(username, log), &secret, log); err != nil {
		return nil, err
	}
	if !secret.IsValid() {
		return nil, fmt.Errorf("incomplete secret for user %s", username)
	}
	return &secret, nil
}

// IsValid ensures required fields are populated.
func (s *UserSecret) IsValid() bool {
	return s.Username != "" && s.Password != ""
}

// userVaultPath returns the Vault path for eos .
func userVaultPath(username string, log *zap.Logger) string {
	path := EosVaultUserPath
	log.Debug("Resolved Vault path for user", zap.String("username", username), zap.String("path", path))
	return path
}

func EnsureEosUserpassAccount(client *api.Client, username, password string, log *zap.Logger) error {
	log.Info("🔍 Checking for existing Vault userpass account", zap.String("username", username))

	// Pre-check if the user already exists
	if _, err := client.Logical().Read(UserpassPathPrefix + username); err == nil {
		log.Info("✅ Vault userpass account already exists — skipping creation", zap.String("username", username))
		return nil
	}

	log.Info("👤 Creating Vault userpass account", zap.String("username", username))
	_, err := client.Logical().Write(
		UserpassPathPrefix+username,
		map[string]interface{}{
			"password": password,
			"policies": EosVaultPolicy,
		},
	)
	if err != nil {
		log.Error("❌ Failed to create userpass account", zap.String("username", username), zap.Error(err))
		return err
	}

	log.Info("✅ Created Vault userpass account", zap.String("username", username))
	return nil
}

// EnsureEosPassword retrieves the eos Vault password from Vault, fallback file, or generates a new one.
func EnsureEosPassword(log *zap.Logger) (string, error) {
	// 1. Try Vault
	var data map[string]interface{} // 👈 this was missing
	if err := ReadFromVaultAt(context.Background(), "secret", EosVaultUserPath, &data, log); err == nil {
		if pw, ok := data["password"].(string); ok && pw != "" {
			log.Info("🔐 Loaded eos Vault password from Vault")
			return pw, nil
		}
	}

	// 2. Try fallback file
	var creds UserpassCreds
	if err := ReadFallbackIntoJSON(EosUserVaultFallback, &creds, log); err == nil && creds.Password != "" {
		log.Info("🔐 Loaded eos Vault password from fallback file")
		return creds.Password, nil
	}

	// 3. Prompt the user interactively
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("🔐 Please enter a secure password for the eos Vault user.")
	for {
		fmt.Print("Enter password: ")
		pw1, _ := reader.ReadString('\n')
		pw1 = strings.TrimSpace(pw1)

		if !crypto.IsPasswordStrong(pw1) {
			fmt.Println("❌ Password too weak. Use at least 12 characters, mix of upper/lowercase, numbers, and symbols.")
			continue
		}

		fmt.Print("Confirm password: ")
		pw2, _ := reader.ReadString('\n')
		pw2 = strings.TrimSpace(pw2)

		if pw1 != pw2 {
			fmt.Println("❌ Passwords do not match. Try again.")
			continue
		}

		log.Info("🔐 Password entered interactively")

		// Save fallback
		creds := UserpassCreds{Username: "eos", Password: pw1}
		if err := WriteFallbackJSON(EosUserVaultFallback, creds); err != nil {
			log.Warn("⚠️ Failed to write eos fallback password", zap.Error(err))
		} else {
			log.Info("📦 eos Vault user password saved to fallback file")
		}

		// Save plaintext password to agent-accessible file (if needed)
		if err := os.WriteFile(VaultAgentPassPath, []byte(pw1), 0600); err != nil {
			log.Warn("⚠️ Failed to write eos Vault user password file", zap.Error(err))
		} else {
			log.Info("📄 eos Vault user password written to agent-accessible file")
		}

		// Save to Vault KV
		if err := WriteToVaultAt("secret", EosVaultUserPath, map[string]interface{}{
			"username": "eos",
			"password": pw1,
		}, log); err != nil {
			log.Warn("Failed to write eos-user secret to Vault", zap.Error(err))
		} else {
			log.Info("✅ eos-user secret written to Vault KV")
		}

		return pw1, nil
	}
}

// EnsureVaultUser enables auth methods, applies policies, and provisions the eos Vault user.
func EnsureEosVaultUser(client *api.Client, log *zap.Logger) error {
	log.Info("🔐 Ensuring Vault user 'eos' is configured")

	// Retrieve password
	password, err := EnsureEosPassword(log)
	if err != nil {
		log.Error("Failed to ensure eos Vault password", zap.Error(err))
		return err
	}

	// Enable auth methods (idempotent)
	if err := EnsureVaultAuthMethods(client, log); err != nil {
		log.Error("Failed to enable auth methods", zap.Error(err))
		return err
	}

	// Ensure eos policy exists
	if err := client.Sys().PutPolicy(EosVaultPolicy, Policies[EosVaultPolicy]); err != nil {
		log.Warn("Failed to apply eos policy", zap.Error(err))
	}

	// Ensure userpass user exists
	if err := EnsureEosUserpassAccount(client, "eos", password, log); err != nil {
		log.Error("Failed to ensure eos userpass account", zap.Error(err))
		return err
	}

	// Ensure AppRole and write credentials
	_, _, err = EnsureAppRole(client, log, DefaultAppRoleOptions())
	if err != nil {
		log.Error("Failed to ensure eos AppRole", zap.Error(err))
		return err
	}

	// Persist fallback file locally
	creds := UserpassCreds{Username: "eos", Password: password}
	if err := WriteFallbackJSON(EosUserVaultFallback, creds); err != nil {
		log.Warn("Failed to write fallback userpass secret", zap.Error(err))
	} else {
		log.Info("📦 eos Vault user fallback password saved", zap.String("path", EosUserVaultFallback))
	}

	// Persist in Vault KV (e.g. for web UI consumption or bootstrap reuse)
	if err := WriteToVaultAt("secret", EosVaultUserPath, map[string]interface{}{
		"username": "eos",
		"password": password,
	}, log); err != nil {
		log.Warn("Failed to write eos-user secret to Vault", zap.Error(err))
	} else {
		log.Info("✅ eos-user secret written to Vault KV")
	}

	// Start Vault Agent (if needed)
	if err := EnsureAgent(client, password, log, DefaultAppRoleOptions()); err != nil {
		log.Warn("Vault Agent startup failed", zap.Error(err))
	}

	log.Info("✅ Vault user 'eos' fully ensured")
	return nil
}

// WriteAppRoleFiles writes the role_id & secret_id into /etc/vault and
// ensures the directory is 0700, owned by eos:eos.
func WriteAppRoleFiles(roleID, secretID string, log *zap.Logger) error {
	dir := filepath.Dir(RoleIDPath)
	log.Info("📁 Ensuring AppRole directory", zap.String("path", dir))
	if err := ensureOwnedDir(dir, 0o700, EosUser); err != nil {
		return err
	}

	pairs := map[string]string{
		RoleIDPath:   roleID + "\n",
		SecretIDPath: secretID + "\n",
	}
	for path, data := range pairs {
		log.Debug("✏️  Writing AppRole file", zap.String("path", path))
		if err := writeOwnedFile(path, []byte(data), 0o600, EosUser); err != nil {
			return err
		}
	}

	log.Info("✅ AppRole credentials written",
		zap.String("role_file", RoleIDPath),
		zap.String("secret_file", SecretIDPath))
	return nil
}

// ------------------------ APP ROLE ------------------------

func EnsureAppRole(client *api.Client, log *zap.Logger, opts AppRoleOptions) (roleID string, secretID string, err error) {
	// Skip if credentials already exist and ForceRecreate is false
	if !opts.ForceRecreate {
		if _, err := os.Stat(RoleIDPath); err == nil {
			log.Info("🔐 AppRole credentials already present — skipping creation",
				zap.String("role_id_path", RoleIDPath),
				zap.Bool("refresh", opts.RefreshCreds),
			)
			if opts.RefreshCreds {
				log.Info("🔄 Refreshing AppRole credentials...")
				roleID, secretID, err := refreshAppRoleCreds(client, log)
				return roleID, secretID, err
			}
			return readAppRoleCredsFromDisk(log)
		}
	}

	log.Info("🛠️ Creating or updating Vault AppRole",
		zap.String("role_path", rolePath),
		zap.Strings("policies", []string{EosVaultPolicy}),
	)

	// Enable auth method
	log.Debug("📡 Enabling AppRole auth method if needed...")
	if err := client.Sys().EnableAuthWithOptions("approle", &api.EnableAuthOptions{Type: "approle"}); err != nil {
		log.Warn("⚠️ AppRole auth method may already be enabled", zap.Error(err))
	}

	// Write role config
	log.Debug("📦 Writing AppRole definition to Vault...")
	if _, err := client.Logical().Write(rolePath, map[string]interface{}{
		"policies":      []string{EosVaultPolicy},
		"token_ttl":     "60m",
		"token_max_ttl": "120m",
	}); err != nil {
		log.Error("❌ Failed to write AppRole definition", zap.String("path", rolePath), zap.Error(err))
		return "", "", fmt.Errorf("failed to create AppRole %q: %w", rolePath, err)
	}
	log.Info("✅ AppRole written to Vault", zap.String("role_path", rolePath))

	// Read credentials from Vault
	log.Debug("🔑 Fetching AppRole credentials from Vault...")
	roleResp, err := client.Logical().Read(rolePath + "/role-id")
	if err != nil {
		log.Error("❌ Failed to read AppRole role_id", zap.String("path", rolePath+"/role-id"), zap.Error(err))
		return "", "", fmt.Errorf("failed to read role_id: %w", err)
	}

	secretResp, err := client.Logical().Write(rolePath+"/secret-id", nil)
	if err != nil {
		log.Error("❌ Failed to generate AppRole secret_id", zap.String("path", rolePath+"/secret-id"), zap.Error(err))
		return "", "", fmt.Errorf("failed to generate secret_id: %w", err)
	}

	rawRoleID, ok := roleResp.Data["role_id"].(string)
	if !ok || rawRoleID == "" {
		log.Error("❌ Invalid or missing role_id in Vault response", zap.Any("data", roleResp.Data))
		return "", "", fmt.Errorf("invalid role_id in Vault response")
	}

	rawSecretID, ok := secretResp.Data["secret_id"].(string)
	if !ok || rawSecretID == "" {
		log.Error("❌ Invalid or missing secret_id in Vault response", zap.Any("data", secretResp.Data))
		return "", "", fmt.Errorf("invalid secret_id in Vault response")
	}

	// Persist them to disk for the agent
	if err := WriteAppRoleFiles(rawRoleID, rawSecretID, log); err != nil {
		log.Error("❌ Failed to write AppRole credentials to disk", zap.Error(err))
		return "", "", err
	}

	log.Info("✅ AppRole provisioning complete",
		zap.String("role_id", rawRoleID),
		zap.String("secret_id", "[redacted]"),
	)

	return rawRoleID, rawSecretID, nil
}

func readAppRoleCredsFromDisk(log *zap.Logger) (string, string, error) {
	roleIDBytes, err := os.ReadFile(RoleIDPath)
	if err != nil {
		return "", "", fmt.Errorf("read role_id from disk: %w", err)
	}
	secretIDBytes, err := os.ReadFile(SecretIDPath)
	if err != nil {
		return "", "", fmt.Errorf("read secret_id from disk: %w", err)
	}
	roleID := strings.TrimSpace(string(roleIDBytes))
	secretID := strings.TrimSpace(string(secretIDBytes))

	log.Info("📄 Loaded AppRole credentials from disk",
		zap.String("role_id_path", RoleIDPath),
		zap.String("secret_id_path", SecretIDPath),
	)
	return roleID, secretID, nil
}

func refreshAppRoleCreds(client *api.Client, log *zap.Logger) (string, string, error) {
	log.Debug("🔑 Requesting AppRole credentials from Vault...")

	// Read role_id from Vault
	roleID, err := client.Logical().Read(rolePath + "/role-id")
	if err != nil {
		log.Error("❌ Failed to read AppRole role_id",
			zap.String("path", rolePath+"/role-id"),
			zap.Error(err),
		)
		return "", "", err
	}

	// Generate secret_id
	secretID, err := client.Logical().Write(rolePath+"/secret-id", nil)
	if err != nil {
		log.Error("❌ Failed to generate AppRole secret_id",
			zap.String("path", rolePath+"/secret-id"),
			zap.Error(err),
		)
		return "", "", err
	}

	// Safely extract role_id
	rawRoleID, ok := roleID.Data["role_id"].(string)
	if !ok || rawRoleID == "" {
		log.Error("❌ Invalid or missing role_id in Vault response",
			zap.Any("data", roleID.Data),
		)
		return "", "", fmt.Errorf("invalid role_id in Vault response")
	}

	// Safely extract secret_id
	rawSecretID, ok := secretID.Data["secret_id"].(string)
	if !ok || rawSecretID == "" {
		log.Error("❌ Invalid or missing secret_id in Vault response",
			zap.Any("data", secretID.Data),
		)
		return "", "", fmt.Errorf("invalid secret_id in Vault response")
	}

	// Ensure directory exists (logged elsewhere if needed)
	log.Debug("💾 Writing AppRole credentials to disk")

	// Write role_id
	if err := writeOwnedFile(RoleIDPath, []byte(rawRoleID+"\n"), 0o640, EosUser); err != nil {
		log.Error("❌ Failed to write role_id",
			zap.String("path", RoleIDPath),
			zap.Error(err),
		)
		return "", "", err
	}

	// Write secret_id
	if err := writeOwnedFile(SecretIDPath, []byte(rawSecretID+"\n"), 0o640, EosUser); err != nil {
		log.Error("❌ Failed to write secret_id",
			zap.String("path", SecretIDPath),
			zap.Error(err),
		)
		return "", "", err
	}

	log.Info("✅ AppRole credentials written to disk",
		zap.String("role_id_path", RoleIDPath),
		zap.String("secret_id_path", SecretIDPath),
	)
	return rawRoleID, rawSecretID, nil
}

// --- helper: ensure a dir exists with the right owner & perms ---
func ensureOwnedDir(path string, perm os.FileMode, owner string) error {
	if err := os.MkdirAll(path, perm); err != nil {
		return fmt.Errorf("mkdir %s: %w", path, err)
	}
	uid, gid, err := system.LookupUser(owner)
	if err != nil {
		return fmt.Errorf("lookup %s: %w", owner, err)
	}
	if err := os.Chown(path, uid, gid); err != nil {
		return fmt.Errorf("chown %s: %w", path, err)
	}
	return nil
}

// --- helper: write a file and chown to owner ---
func writeOwnedFile(path string, data []byte, perm os.FileMode, owner string) error {
	if err := os.WriteFile(path, data, perm); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	uid, gid, err := system.LookupUser(owner)
	if err != nil {
		return fmt.Errorf("lookup %s: %w", owner, err)
	}
	if err := os.Chown(path, uid, gid); err != nil {
		return fmt.Errorf("chown %s: %w", path, err)
	}
	return nil
}
