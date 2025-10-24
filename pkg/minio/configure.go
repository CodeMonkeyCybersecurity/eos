package minio

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ConfigureVaultSecrets sets up MinIO credentials in Vault
func ConfigureVaultSecrets(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Check Vault status
	logger.Info("Assessing Vault configuration for MinIO secrets")

	if err := checkVaultStatus(rc); err != nil {
		return fmt.Errorf("vault not ready: %w", err)
	}

	// INTERVENE - Store credentials
	logger.Info("Storing MinIO credentials in Vault")

	// Generate secure credentials if not provided
	if config.RootUser == "" {
		config.RootUser = "minioadmin"
	}

	if config.RootPassword == "" {
		password, err := generateSecurePassword(32)
		if err != nil {
			return fmt.Errorf("failed to generate password: %w", err)
		}
		config.RootPassword = password
	}

	// Store in Vault KV v2
	logger.Info("Writing MinIO root credentials to Vault",
		zap.String("path", VaultMinIOPath))

	// Write to Vault using vault CLI (more reliable than API in various environments)
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "vault",
		Args: []string{"kv", "put", "-format=json", VaultMinIOPath,
			fmt.Sprintf("root_user=%s", config.RootUser),
			fmt.Sprintf("root_password=%s", config.RootPassword),
			fmt.Sprintf("region=%s", config.Region),
			fmt.Sprintf("api_port=%d", DefaultAPIPort),
			fmt.Sprintf("console_port=%d", DefaultConsolePort),
		},
		Timeout: HealthCheckTimeout,
	})
	if err != nil {
		logger.Error("Failed to write to Vault",
			zap.Error(err),
			zap.String("output", output))
		return eos_err.NewUserError(
			"failed to store credentials in Vault: %v\n"+
				"Please ensure:\n"+
				"1. Vault is unsealed and accessible\n"+
				"2. You have write permissions to path: %s\n"+
				"3. KV v2 secrets engine is enabled at 'kv/'\n"+
				"Run: vault secrets enable -version=2 -path=kv kv",
			err, VaultMinIOPath)
	}

	// EVALUATE - Verify the secret was stored
	logger.Info("Verifying credentials were stored successfully")

	_, err = execute.Run(rc.Ctx, execute.Options{
		Command: "vault",
		Args:    []string{"kv", "get", "-format=json", VaultMinIOPath},
		Timeout: HealthCheckTimeout,
	})
	if err != nil {
		return fmt.Errorf("failed to verify stored credentials: %w", err)
	}

	logger.Info("MinIO credentials successfully stored in Vault")
	return nil
}

// ConfigureVaultPolicies sets up Vault policies for MinIO access
func ConfigureVaultPolicies(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Configuring Vault policies for MinIO")

	// Create MinIO access policy
	policyContent := `
# MinIO root credentials access
path "kv/data/minio/root" {
  capabilities = ["read"]
}

# MinIO policies management
path "kv/data/minio/policies/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# MinIO user credentials
path "kv/data/minio/users/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
`

	// Write policy to temporary file
	tmpFile := "/tmp/minio-vault-policy.hcl"
	if err := os.WriteFile(tmpFile, []byte(policyContent), 0600); err != nil {
		return fmt.Errorf("failed to write policy file: %w", err)
	}
	defer func() { _ = os.Remove(tmpFile) }()

	// Apply the policy
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "vault",
		Args:    []string{"policy", "write", "minio-access", tmpFile},
		Timeout: HealthCheckTimeout,
	})
	if err != nil {
		logger.Warn("Failed to create Vault policy (may already exist)",
			zap.Error(err),
			zap.String("output", output))
	} else {
		logger.Info("Vault policy 'minio-access' created successfully")
	}

	return nil
}

// GenerateDeploymentConfig creates configuration files for deployment
func GenerateDeploymentConfig(rc *eos_io.RuntimeContext, opts *DeploymentOptions) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Generating MinIO deployment configuration")

	// Create deployment directory
	deployDir := filepath.Join("/tmp", "eos-minio-deploy")
	if err := os.MkdirAll(deployDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create deployment directory: %w", err)
	}

	// Create directory structure
	dirs := []string{
		filepath.Join(deployDir, "terraform", "minio"),
		filepath.Join(deployDir, "", "states"),
		filepath.Join(deployDir, "nomad"),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return "", fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	logger.Info("Deployment configuration generated",
		zap.String("directory", deployDir))

	return deployDir, nil
}

// checkVaultStatus verifies Vault is accessible and unsealed
func checkVaultStatus(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "vault",
		Args:    []string{"status", "-format=json"},
		Timeout: HealthCheckTimeout,
	})

	if err != nil {
		// Exit code 2 means sealed
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 2 {
			return eos_err.NewUserError("Vault is sealed. Please unseal Vault before proceeding")
		}
		return fmt.Errorf("cannot connect to Vault: %w", err)
	}

	// Parse status to check if initialized
	var status map[string]interface{}
	if err := json.Unmarshal([]byte(output), &status); err != nil {
		logger.Warn("Failed to parse Vault status", zap.Error(err))
		return nil // Continue anyway
	}

	if initialized, ok := status["initialized"].(bool); ok && !initialized {
		return eos_err.NewUserError("Vault is not initialized. Please initialize Vault before proceeding")
	}

	return nil
}

// generateSecurePassword generates a cryptographically secure password
func generateSecurePassword(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes)[:length], nil
}
