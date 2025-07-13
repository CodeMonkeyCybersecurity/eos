package clusterfuzz

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// StoreSecretsInVault stores ClusterFuzz secrets in HashiCorp Vault
// following the Assess → Intervene → Evaluate pattern
func StoreSecretsInVault(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS
	logger.Info("Assessing Vault connectivity for secret storage")
	
	if config.VaultPath == "" {
		return fmt.Errorf("vault path not configured")
	}
	
	// TODO: Add vault connectivity check here
	
	// INTERVENE
	logger.Info("Storing ClusterFuzz secrets in Vault", 
		zap.String("base_path", config.VaultPath))
	
	// Store database credentials
	if err := storeDatabaseSecrets(rc, config); err != nil {
		return fmt.Errorf("failed to store database secrets: %w", err)
	}
	
	// Store queue credentials
	if err := storeQueueSecrets(rc, config); err != nil {
		return fmt.Errorf("failed to store queue secrets: %w", err)
	}
	
	// Store S3/MinIO credentials if configured
	if config.StorageConfig.Type == "s3" || config.StorageConfig.Type == "minio" {
		if err := storeS3Secrets(rc, config); err != nil {
			return fmt.Errorf("failed to store S3 secrets: %w", err)
		}
	}
	
	// EVALUATE
	logger.Info("Successfully stored all ClusterFuzz secrets in Vault")
	
	return nil
}

func storeDatabaseSecrets(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	dbSecrets := map[string]interface{}{
		"username": config.DatabaseConfig.Username,
		"password": config.DatabaseConfig.Password,
		"host":     config.DatabaseConfig.Host,
		"port":     config.DatabaseConfig.Port,
		"database": config.DatabaseConfig.Database,
	}
	
	dbPath := fmt.Sprintf("%s/database", config.VaultPath)
	if err := vault.WriteToVault(rc, dbPath, dbSecrets); err != nil {
		return fmt.Errorf("failed to write database secrets: %w", err)
	}
	
	logger.Info("Stored database credentials in Vault", zap.String("path", dbPath))
	return nil
}

func storeQueueSecrets(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	queueSecrets := map[string]interface{}{
		"type":     config.QueueConfig.Type,
		"host":     config.QueueConfig.Host,
		"port":     config.QueueConfig.Port,
		"password": config.QueueConfig.Password,
	}
	
	if config.QueueConfig.Username != "" {
		queueSecrets["username"] = config.QueueConfig.Username
	}
	
	queuePath := fmt.Sprintf("%s/queue", config.VaultPath)
	if err := vault.WriteToVault(rc, queuePath, queueSecrets); err != nil {
		return fmt.Errorf("failed to write queue secrets: %w", err)
	}
	
	logger.Info("Stored queue credentials in Vault", zap.String("path", queuePath))
	return nil
}

func storeS3Secrets(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Store S3/MinIO credentials
	s3Secrets := map[string]interface{}{
		"endpoint":   config.StorageConfig.S3Config.Endpoint,
		"access_key": config.StorageConfig.S3Config.AccessKey,
		"secret_key": config.StorageConfig.S3Config.SecretKey,
		"bucket":     config.StorageConfig.S3Config.Bucket,
		"region":     config.StorageConfig.S3Config.Region,
	}
	
	s3Path := fmt.Sprintf("%s/storage", config.VaultPath)
	if err := vault.WriteToVault(rc, s3Path, s3Secrets); err != nil {
		return fmt.Errorf("failed to write S3 secrets: %w", err)
	}
	
	logger.Info("Stored S3/MinIO credentials in Vault", zap.String("path", s3Path))
	return nil
}