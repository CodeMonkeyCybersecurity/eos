package clusterfuzz

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// InitializeServices initializes databases and storage for ClusterFuzz
// following the Assess → Intervene → Evaluate pattern
func InitializeServices(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS
	logger.Info("Assessing service initialization requirements")
	
	// Check if initialization scripts exist
	dbScriptPath := filepath.Join(config.ConfigDir, "init", "db-setup.sql")
	if _, err := os.Stat(dbScriptPath); os.IsNotExist(err) {
		return fmt.Errorf("database initialization script not found: %s", dbScriptPath)
	}
	
	// INTERVENE
	logger.Info("Initializing ClusterFuzz services")
	
	// Initialize database
	if err := initializeDatabase(rc, config, dbScriptPath); err != nil {
		return fmt.Errorf("database initialization failed: %w", err)
	}
	
	// Initialize storage
	if err := initializeStorage(rc, config); err != nil {
		return fmt.Errorf("storage initialization failed: %w", err)
	}
	
	// EVALUATE
	logger.Info("Service initialization completed successfully")
	return nil
}

func initializeDatabase(rc *eos_io.RuntimeContext, config *Config, scriptPath string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Initializing database schema...")
	
	switch config.DatabaseBackend {
	case "postgresql":
		// Set password environment variable
		if err := os.Setenv("PGPASSWORD", config.DatabaseConfig.Password); err != nil {
			return fmt.Errorf("failed to set PGPASSWORD: %w", err)
		}
		defer func() { _ = os.Unsetenv("PGPASSWORD") }()

		// Execute initialization script
		_, err := execute.Run(rc.Ctx, execute.Options{
			Command: "psql",
			Args: []string{
				"-h", config.DatabaseConfig.Host,
				"-p", fmt.Sprintf("%d", config.DatabaseConfig.Port),
				"-U", config.DatabaseConfig.Username,
				"-d", config.DatabaseConfig.Database,
				"-f", scriptPath,
			},
		})
		if err != nil {
			return fmt.Errorf("failed to execute database initialization script: %w", err)
		}
		
	case "mongodb":
		// MongoDB initialization would go here
		return fmt.Errorf("MongoDB initialization not implemented yet")
		
	default:
		return fmt.Errorf("unsupported database backend: %s", config.DatabaseBackend)
	}
	
	logger.Info("Database initialized successfully")
	return nil
}

func initializeStorage(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	switch config.StorageBackend {
	case "minio":
		logger.Info("Initializing MinIO buckets...")
		
		// Use mc (MinIO client) to create buckets
		mcConfigHost := fmt.Sprintf("http://%s:%s@localhost:9000", 
			config.StorageConfig.S3Config.AccessKey,
			config.StorageConfig.S3Config.SecretKey)
		
		// Add MinIO host
		_, err := execute.Run(rc.Ctx, execute.Options{
			Command: "mc",
			Args:    []string{"alias", "set", "clusterfuzz", mcConfigHost},
		})
		if err != nil {
			logger.Warn("Failed to configure MinIO client, continuing...", zap.Error(err))
		}
		
		// Create bucket
		_, err = execute.Run(rc.Ctx, execute.Options{
			Command: "mc",
			Args:    []string{"mb", "--ignore-existing", fmt.Sprintf("clusterfuzz/%s", config.StorageConfig.S3Config.Bucket)},
		})
		if err != nil {
			logger.Warn("Failed to create MinIO bucket, it may already exist", zap.Error(err))
		}
		
	case "s3":
		logger.Info("Using existing S3 bucket", zap.String("bucket", config.StorageConfig.S3Config.Bucket))
		// Assume S3 bucket already exists
		
	case "local":
		logger.Info("Initializing local storage...")
		localPath := filepath.Join(config.ConfigDir, "storage")
		if err := os.MkdirAll(localPath, 0755); err != nil {
			return fmt.Errorf("failed to create local storage directory: %w", err)
		}
		
	default:
		return fmt.Errorf("unsupported storage backend: %s", config.StorageBackend)
	}
	
	logger.Info("Storage initialized successfully")
	return nil
}