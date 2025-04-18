// pkg/vault/lifecycle_vault_user.go

package vault

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

//
// ========================== ENSURE ==========================
//

//
// ========================== LIST ==========================
//

//
// ========================== READ ==========================
//

//
// ========================== UPDATE ==========================
//

//
// ========================== DELETE ==========================
//

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
	if err := EnsureAppRole(client, log, DefaultAppRoleOptions()); err != nil {
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
