package auth

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"golang.org/x/term"
)

// ConfigureTokenAuth configures token-based authentication for Vault
// Migrated from cmd/self/secrets.go configureTokenAuth
func ConfigureTokenAuth(rc *eos_io.RuntimeContext, reader *bufio.Reader) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Prepare for token authentication setup
	logger.Info("Assessing token authentication configuration")

	// INTERVENE - Get token from user
	logger.Info("terminal prompt: Enter Vault token")
	token, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		logger.Error("Failed to read token", zap.Error(err))
		return fmt.Errorf("failed to read token: %w", err)
	}

	// Set token environment variable
	_ = os.Setenv("VAULT_TOKEN", string(token))

	// EVALUATE - Log success
	logger.Info("Token authentication configured successfully")

	return nil
}

// ConfigureUserPassAuth configures username/password authentication for Vault
// Migrated from cmd/self/secrets.go configureUserPassAuth
func ConfigureUserPassAuth(rc *eos_io.RuntimeContext, reader *bufio.Reader) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Prepare for userpass authentication setup
	logger.Info("Assessing userpass authentication configuration")

	// INTERVENE - Get credentials from user
	logger.Info("terminal prompt: Enter username")
	username, err := reader.ReadString('\n')
	if err != nil {
		logger.Error("Failed to read username", zap.Error(err))
		return fmt.Errorf("failed to read username: %w", err)
	}
	username = strings.TrimSpace(username)

	logger.Info("terminal prompt: Enter password")
	password, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		logger.Error("Failed to read password", zap.Error(err))
		return fmt.Errorf("failed to read password: %w", err)
	}

	// Store credentials
	_ = os.Setenv("VAULT_AUTH_USERNAME", username)
	_ = os.Setenv("VAULT_AUTH_PASSWORD", string(password))

	// EVALUATE - Log success
	logger.Info("Userpass authentication configured successfully",
		zap.String("username", username))

	return nil
}

// ConfigureAppRoleAuth configures AppRole authentication for Vault
// Migrated from cmd/self/secrets.go configureAppRoleAuth
func ConfigureAppRoleAuth(rc *eos_io.RuntimeContext, reader *bufio.Reader) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Prepare for AppRole authentication setup
	logger.Info("Assessing AppRole authentication configuration")

	// INTERVENE - Get AppRole credentials from user
	logger.Info("terminal prompt: Enter Role ID")
	roleID, err := reader.ReadString('\n')
	if err != nil {
		logger.Error("Failed to read role ID", zap.Error(err))
		return fmt.Errorf("failed to read role ID: %w", err)
	}
	roleID = strings.TrimSpace(roleID)

	logger.Info("terminal prompt: Enter Secret ID")
	secretID, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		logger.Error("Failed to read secret ID", zap.Error(err))
		return fmt.Errorf("failed to read secret ID: %w", err)
	}

	// Store credentials
	_ = os.Setenv("VAULT_ROLE_ID", roleID)
	_ = os.Setenv("VAULT_SECRET_ID", string(secretID))

	// EVALUATE - Log success
	logger.Info("AppRole authentication configured successfully",
		zap.String("role_id", roleID))

	return nil
}

// SaveVaultConfig saves Vault configuration to disk
// Migrated from cmd/self/secrets.go saveVaultConfig
func SaveVaultConfig(rc *eos_io.RuntimeContext, vaultAddr, authMethod string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Prepare configuration save
	logger.Info("Assessing Vault configuration save requirements",
		zap.String("vault_addr", vaultAddr),
		zap.String("auth_method", authMethod))

	// INTERVENE - Create directory and save configuration
	configDir := "/etc/eos"
	if err := os.MkdirAll(configDir, 0755); err != nil {
		logger.Error("Failed to create config directory",
			zap.String("dir", configDir),
			zap.Error(err))
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	configFile := fmt.Sprintf("%s/vault.env", configDir)
	file, err := os.Create(configFile)
	if err != nil {
		logger.Error("Failed to create config file",
			zap.String("file", configFile),
			zap.Error(err))
		return fmt.Errorf("failed to create config file: %w", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			logger.Warn("Failed to close config file", zap.Error(err))
		}
	}()

	if _, err := fmt.Fprintf(file, "VAULT_ADDR=%s\n", vaultAddr); err != nil {
		return fmt.Errorf("failed to write VAULT_ADDR: %w", err)
	}
	if _, err := fmt.Fprintf(file, "VAULT_AUTH_METHOD=%s\n", authMethod); err != nil {
		return fmt.Errorf("failed to write VAULT_AUTH_METHOD: %w", err)
	}

	// EVALUATE - Log success
	logger.Info("Vault configuration saved successfully",
		zap.String("config_file", configFile))

	return nil
}
