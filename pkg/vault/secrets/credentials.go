package secrets

// TODO: MIGRATION IN PROGRESS
// This file has 28 fmt.Printf/Println violations that need to be replaced with structured logging.
// See credentials_refactored.go for the migrated version that follows Eos standards:
// - All user output uses fmt.Fprint(os.Stderr, ...) to preserve stdout
// - All debug/info logging uses otelzap.Ctx(rc.Ctx)
// - User prompts use interaction package patterns
// - Follows Assess → Intervene → Evaluate pattern
// - Enhanced error handling and proper return values

import (
	"bufio"
	"fmt"
	"strings"
	"syscall"
	"time"

	vaultDomain "github.com/CodeMonkeyCybersecurity/eos/pkg/domain/vault"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"golang.org/x/term"
)

// SetDatabaseCredentials configures database credentials in Vault
// Migrated from cmd/self/secrets.go setDatabaseCredentials
func SetDatabaseCredentials(rc *eos_io.RuntimeContext, secretStore vaultDomain.SecretStore, reader *bufio.Reader) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Prepare for database credential configuration
	logger.Info("Assessing database credentials setup")
	fmt.Printf("\n🗄️  Database Credentials Setup\n")
	fmt.Printf("===============================\n")

	// INTERVENE - Collect database connection parameters
	fmt.Printf("Database host [localhost]: ")
	host, _ := reader.ReadString('\n')
	host = strings.TrimSpace(host)
	if host == "" {
		host = "localhost"
	}

	fmt.Printf("Database port [5432]: ")
	port, _ := reader.ReadString('\n')
	port = strings.TrimSpace(port)
	if port == "" {
		port = "5432"
	}

	fmt.Printf("Database name [delphi]: ")
	dbname, _ := reader.ReadString('\n')
	dbname = strings.TrimSpace(dbname)
	if dbname == "" {
		dbname = "delphi"
	}

	fmt.Printf("Database username [delphi]: ")
	username, _ := reader.ReadString('\n')
	username = strings.TrimSpace(username)
	if username == "" {
		username = "delphi"
	}

	fmt.Printf("Database password: ")
	password, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		logger.Error("Failed to read password", zap.Error(err))
		return fmt.Errorf("failed to read password: %w", err)
	}
	fmt.Printf("\n")

	// Store secrets in Vault
	secrets := map[string]string{
		"delphi/database/host":     host,
		"delphi/database/port":     port,
		"delphi/database/name":     dbname,
		"delphi/database/username": username,
		"delphi/database/password": string(password),
	}

	for key, value := range secrets {
		secret := &vaultDomain.Secret{
			Key:       key,
			Value:     value,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		if err := secretStore.Set(rc.Ctx, key, secret); err != nil {
			logger.Error("Failed to store secret",
				zap.String("key", key),
				zap.Error(err))
			return fmt.Errorf("failed to store %s: %w", key, err)
		}
	}

	// EVALUATE - Log success
	logger.Info("Database credentials stored successfully")
	fmt.Printf("✅ Database credentials stored successfully\n")
	return nil
}

// SetSMTPCredentials configures SMTP credentials in Vault
// Migrated from cmd/self/secrets.go setSMTPCredentials
func SetSMTPCredentials(rc *eos_io.RuntimeContext, secretStore vaultDomain.SecretStore, reader *bufio.Reader) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Prepare for SMTP credential configuration
	logger.Info("Assessing SMTP credentials setup")
	fmt.Printf("\n📧 SMTP Credentials Setup\n")
	fmt.Printf("=========================\n")

	// INTERVENE - Collect SMTP configuration
	fmt.Printf("SMTP host: ")
	host, _ := reader.ReadString('\n')
	host = strings.TrimSpace(host)

	fmt.Printf("SMTP port [587]: ")
	port, _ := reader.ReadString('\n')
	port = strings.TrimSpace(port)
	if port == "" {
		port = "587"
	}

	fmt.Printf("SMTP username: ")
	username, _ := reader.ReadString('\n')
	username = strings.TrimSpace(username)

	fmt.Printf("SMTP password: ")
	password, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		logger.Error("Failed to read password", zap.Error(err))
		return fmt.Errorf("failed to read password: %w", err)
	}
	fmt.Printf("\n")

	secrets := map[string]string{
		"smtp/host":     host,
		"smtp/port":     port,
		"smtp/username": username,
		"smtp/password": string(password),
	}

	for key, value := range secrets {
		secret := &vaultDomain.Secret{
			Key:       key,
			Value:     value,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		if err := secretStore.Set(rc.Ctx, key, secret); err != nil {
			logger.Error("Failed to store secret",
				zap.String("key", key),
				zap.Error(err))
			return fmt.Errorf("failed to store %s: %w", key, err)
		}
	}

	// EVALUATE - Log success
	logger.Info("SMTP credentials stored successfully")
	fmt.Printf("✅ SMTP credentials stored successfully\n")
	return nil
}

// SetOpenAICredentials configures OpenAI API credentials in Vault
// Migrated from cmd/self/secrets.go setOpenAICredentials
func SetOpenAICredentials(rc *eos_io.RuntimeContext, secretStore vaultDomain.SecretStore, reader *bufio.Reader) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Prepare for OpenAI credential configuration
	logger.Info("Assessing OpenAI credentials setup")
	fmt.Printf("\n🤖 OpenAI API Key Setup\n")
	fmt.Printf("=======================\n")

	// INTERVENE - Collect API key
	fmt.Printf("OpenAI API Key: ")
	apiKey, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		logger.Error("Failed to read API key", zap.Error(err))
		return fmt.Errorf("failed to read API key: %w", err)
	}
	fmt.Printf("\n")

	secret := &vaultDomain.Secret{
		Key:       "openai/api_key",
		Value:     string(apiKey),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := secretStore.Set(rc.Ctx, "openai/api_key", secret); err != nil {
		logger.Error("Failed to store OpenAI API key", zap.Error(err))
		return fmt.Errorf("failed to store OpenAI API key: %w", err)
	}

	// EVALUATE - Log success
	logger.Info("OpenAI API key stored successfully")
	fmt.Printf("✅ OpenAI API key stored successfully\n")
	return nil
}

// SetCustomSecret configures custom key-value secrets in Vault
// Migrated from cmd/self/secrets.go setCustomSecret
func SetCustomSecret(rc *eos_io.RuntimeContext, secretStore vaultDomain.SecretStore, reader *bufio.Reader) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Prepare for custom secret configuration
	logger.Info("Assessing custom secret setup")
	fmt.Printf("\n🔐 Custom Secret Setup\n")
	fmt.Printf("======================\n")

	// INTERVENE - Collect custom secret details
	fmt.Printf("Secret path (e.g., myapp/config/key): ")
	path, _ := reader.ReadString('\n')
	path = strings.TrimSpace(path)

	fmt.Printf("Secret value: ")
	value, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		logger.Error("Failed to read value", zap.Error(err))
		return fmt.Errorf("failed to read value: %w", err)
	}
	fmt.Printf("\n")

	secret := &vaultDomain.Secret{
		Key:       path,
		Value:     string(value),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := secretStore.Set(rc.Ctx, path, secret); err != nil {
		logger.Error("Failed to store custom secret",
			zap.String("path", path),
			zap.Error(err))
		return fmt.Errorf("failed to store secret: %w", err)
	}

	// EVALUATE - Log success
	logger.Info("Custom secret stored successfully",
		zap.String("path", path))
	fmt.Printf("✅ Custom secret stored successfully\n")
	return nil
}