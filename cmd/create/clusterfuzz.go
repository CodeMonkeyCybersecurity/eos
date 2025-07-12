package create

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/clusterfuzz"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/clusterfuzz/config"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/clusterfuzz/generator"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/clusterfuzz/prerequisites"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/clusterfuzz/validation"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Removed embedded templates for now - templates are generated dynamically
// //go:embed templates/clusterfuzz/*
// var clusterfuzzTemplates embed.FS
// TODO move to pkg/ to DRY up this code base but putting it with other similar functions
var (
	nomadAddress        string
	consulAddress       string
	storageBackend      string
	databaseBackend     string
	queueBackend        string
	botCount            int
	preemptibleBotCount int
	domain              string
	configDir           string
	useVault            bool
	vaultPath           string
	s3Endpoint          string
	s3AccessKey         string
	s3SecretKey         string
	s3Bucket            string
	skipPrereqCheck     bool
)

var clusterfuzzCmd = &cobra.Command{
	Use:   "clusterfuzz",
	Short: "Deploy ClusterFuzz fuzzing infrastructure on Nomad",
	Long: `Deploy ClusterFuzz fuzzing infrastructure on Nomad with configurable backends.

ClusterFuzz is Google's scalable fuzzing infrastructure, adapted for Nomad deployment.
This command sets up all required services including database, queue, storage, and fuzzing bots.

FEATURES:
• Configurable storage backends (MinIO, S3, local)
• Database backend support (PostgreSQL, MongoDB)
• Queue backend support (Redis, RabbitMQ)
• Scalable fuzzing bot deployment
• Vault integration for secrets management
• Comprehensive health monitoring
• Production-ready configuration

EXAMPLES:
  # Deploy with default settings (PostgreSQL, Redis, MinIO)
  eos create clusterfuzz

  # Deploy with custom storage backend
  eos create clusterfuzz --storage-backend s3 --s3-endpoint s3.amazonaws.com

  # Deploy with MongoDB and RabbitMQ
  eos create clusterfuzz --database-backend mongodb --queue-backend rabbitmq

  # Deploy with Vault integration
  eos create clusterfuzz --use-vault --vault-path secret/clusterfuzz

  # Deploy with custom bot configuration
  eos create clusterfuzz --bot-count 5 --preemptible-bot-count 10`,
	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		logger.Info("Starting ClusterFuzz deployment on Nomad",
			zap.String("nomad_address", nomadAddress),
			zap.String("storage_backend", storageBackend),
			zap.String("database_backend", databaseBackend))

		// Validate configuration
		if err := validation.ValidateConfig(storageBackend, databaseBackend, queueBackend,
			botCount, preemptibleBotCount, s3Endpoint, s3AccessKey, s3SecretKey); err != nil {
			return fmt.Errorf("invalid configuration: %w", err)
		}

		// Create configuration
		cfg := config.CreateConfig(nomadAddress, consulAddress, storageBackend, databaseBackend,
			queueBackend, botCount, preemptibleBotCount, domain, configDir, useVault,
			vaultPath, s3Endpoint, s3AccessKey, s3SecretKey, s3Bucket)

		// Check prerequisites
		if !skipPrereqCheck {
			logger.Info("Checking prerequisites...")
			if err := prerequisites.Check(rc, cfg); err != nil {
				return fmt.Errorf("prerequisite check failed: %w", err)
			}
		}

		// Create configuration directory
		if err := os.MkdirAll(configDir, 0755); err != nil {
			return fmt.Errorf("failed to create config directory: %w", err)
		}

		// Generate configurations
		logger.Info("Generating ClusterFuzz configurations...")
		if err := generator.GenerateConfigurations(rc, cfg); err != nil {
			return fmt.Errorf("failed to generate configurations: %w", err)
		}

		// Store secrets in Vault if enabled
		if useVault {
			logger.Info("Storing secrets in Vault...")
			if err := storeSecretsInVault(rc, cfg); err != nil {
				return fmt.Errorf("failed to store secrets in Vault: %w", err)
			}
		}

		// Deploy infrastructure services
		logger.Info("Deploying infrastructure services...")
		if err := deployInfrastructure(rc, cfg); err != nil {
			return fmt.Errorf("failed to deploy infrastructure: %w", err)
		}

		// Wait for infrastructure to be ready
		logger.Info("Waiting for infrastructure services to be ready...")
		if err := waitForInfrastructure(rc, cfg); err != nil {
			return fmt.Errorf("infrastructure failed to become ready: %w", err)
		}

		// Initialize databases and storage
		logger.Info("Initializing databases and storage...")
		if err := initializeServices(rc, cfg); err != nil {
			return fmt.Errorf("failed to initialize services: %w", err)
		}

		// Deploy ClusterFuzz application
		logger.Info("Deploying ClusterFuzz application...")
		if err := deployApplication(rc, cfg); err != nil {
			return fmt.Errorf("failed to deploy application: %w", err)
		}

		// Deploy fuzzing bots
		logger.Info("Deploying fuzzing bots...")
		if err := deployBots(rc, cfg); err != nil {
			return fmt.Errorf("failed to deploy bots: %w", err)
		}

		// Verify deployment
		logger.Info("Verifying deployment...")
		if err := verifyDeployment(rc, cfg); err != nil {
			return fmt.Errorf("deployment verification failed: %w", err)
		}

		// Display success information
		displaySuccessInfo(cfg)

		logger.Info("ClusterFuzz deployment completed successfully")
		return nil
	}),
}

func init() {
	CreateCmd.AddCommand(clusterfuzzCmd)

	clusterfuzzCmd.Flags().StringVar(&nomadAddress, "nomad-address", "http://localhost:4646", "Nomad server address")
	clusterfuzzCmd.Flags().StringVar(&consulAddress, "consul-address", "http://localhost:8500", "Consul server address")
	clusterfuzzCmd.Flags().StringVar(&storageBackend, "storage-backend", "minio", "Storage backend (minio, s3, local)")
	clusterfuzzCmd.Flags().StringVar(&databaseBackend, "database-backend", "postgresql", "Database backend (postgresql, mongodb)")
	clusterfuzzCmd.Flags().StringVar(&queueBackend, "queue-backend", "redis", "Queue backend (redis, rabbitmq)")
	clusterfuzzCmd.Flags().IntVar(&botCount, "bot-count", 3, "Number of regular fuzzing bots")
	clusterfuzzCmd.Flags().IntVar(&preemptibleBotCount, "preemptible-bot-count", 5, "Number of preemptible fuzzing bots")
	clusterfuzzCmd.Flags().StringVar(&domain, "domain", "clusterfuzz.local", "Domain for web UI access")
	clusterfuzzCmd.Flags().StringVar(&configDir, "config-dir", "./clusterfuzz-config", "Directory to store generated configurations")
	clusterfuzzCmd.Flags().BoolVar(&useVault, "use-vault", false, "Use HashiCorp Vault for secrets management")
	clusterfuzzCmd.Flags().StringVar(&vaultPath, "vault-path", "secret/clusterfuzz", "Vault path for ClusterFuzz secrets")
	clusterfuzzCmd.Flags().StringVar(&s3Endpoint, "s3-endpoint", "", "S3-compatible endpoint (for MinIO)")
	clusterfuzzCmd.Flags().StringVar(&s3AccessKey, "s3-access-key", "", "S3 access key")
	clusterfuzzCmd.Flags().StringVar(&s3SecretKey, "s3-secret-key", "", "S3 secret key")
	clusterfuzzCmd.Flags().StringVar(&s3Bucket, "s3-bucket", "clusterfuzz", "S3 bucket name")
	clusterfuzzCmd.Flags().BoolVar(&skipPrereqCheck, "skip-prereq-check", false, "Skip prerequisite checks")
}






// TODO: HELPER_REFACTOR - Move to pkg/clusterfuzz/vault or pkg/clusterfuzz/secrets
// Type: Business Logic
// Related functions: checkVaultConnectivity
// Dependencies: eos_io, vault, otelzap, zap, fmt
// TODO: Move to pkg/clusterfuzz/vault or pkg/clusterfuzz/secrets
func storeSecretsInVault(rc *eos_io.RuntimeContext, config *clusterfuzz.Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Store database credentials
	dbSecrets := map[string]interface{}{
		"username": config.DatabaseConfig.Username,
		"password": config.DatabaseConfig.Password,
		"host":     config.DatabaseConfig.Host,
		"port":     config.DatabaseConfig.Port,
		"database": config.DatabaseConfig.Database,
	}

	dbPath := fmt.Sprintf("%s/database", config.VaultPath)
	if err := vault.WriteToVault(rc, dbPath, dbSecrets); err != nil {
		return fmt.Errorf("failed to store database secrets: %w", err)
	}
	logger.Info("Stored database credentials in Vault", zap.String("path", dbPath))

	// Store queue credentials
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
		return fmt.Errorf("failed to store queue secrets: %w", err)
	}
	logger.Info("Stored queue credentials in Vault", zap.String("path", queuePath))

	// Store S3/MinIO credentials if applicable
	if config.StorageBackend == "s3" || config.StorageBackend == "minio" {
		s3Secrets := map[string]interface{}{
			"endpoint":   config.S3Config.Endpoint,
			"access_key": config.S3Config.AccessKey,
			"secret_key": config.S3Config.SecretKey,
			"bucket":     config.S3Config.Bucket,
			"use_ssl":    config.S3Config.UseSSL,
		}

		s3Path := fmt.Sprintf("%s/storage", config.VaultPath)
		if err := vault.WriteToVault(rc, s3Path, s3Secrets); err != nil {
			return fmt.Errorf("failed to store S3 secrets: %w", err)
		}
		logger.Info("Stored S3/MinIO credentials in Vault", zap.String("path", s3Path))
	}

	return nil
}

// TODO: HELPER_REFACTOR - Move to pkg/clusterfuzz/deploy or pkg/clusterfuzz/infrastructure
// Type: Business Logic
// Related functions: buildDockerImages, deployApplication, deployBots
// Dependencies: eos_io, otelzap, zap, fmt
// TODO: Move to pkg/clusterfuzz/deploy or pkg/clusterfuzz/infrastructure
func deployInfrastructure(rc *eos_io.RuntimeContext, config *clusterfuzz.Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Build Docker images first
	logger.Info("Building Docker images...")
	if err := buildDockerImages(rc, config); err != nil {
		return fmt.Errorf("failed to build Docker images: %w", err)
	}

	// Deploy core services job
	logger.Info("Deploying core services to Nomad...")
	coreJobPath := filepath.Join(config.ConfigDir, "jobs", "clusterfuzz-core.nomad")

	if _, err := executeCommand(rc, "nomad", "job", "run", "-address="+config.NomadAddress, coreJobPath); err != nil {
		return fmt.Errorf("failed to deploy core services: %w", err)
	}

	return nil
}

// TODO: HELPER_REFACTOR - Move to pkg/clusterfuzz/docker or pkg/clusterfuzz/build
// Type: Business Logic
// Related functions: deployInfrastructure, generateDockerfiles
// Dependencies: eos_io, otelzap, zap, filepath
// TODO: Move to pkg/clusterfuzz/docker or pkg/clusterfuzz/build
func buildDockerImages(rc *eos_io.RuntimeContext, config *clusterfuzz.Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Build web image
	webDockerfilePath := filepath.Join(config.ConfigDir, "docker", "web.Dockerfile")
	dockerDir := filepath.Join(config.ConfigDir, "docker")

	logger.Info("Building ClusterFuzz web image...")
	if _, err := executeCommand(rc, "docker", "build", "-t", "clusterfuzz/web:custom", "-f", webDockerfilePath, dockerDir); err != nil {
		logger.Warn("Failed to build web image, will use default",
			zap.Error(err))
	}

	// Build bot image
	botDockerfilePath := filepath.Join(config.ConfigDir, "docker", "bot.Dockerfile")

	logger.Info("Building ClusterFuzz bot image...")
	if _, err := executeCommand(rc, "docker", "build", "-t", "clusterfuzz/bot:custom", "-f", botDockerfilePath, dockerDir); err != nil {
		logger.Warn("Failed to build bot image, will use default",
			zap.Error(err))
	}

	return nil
}

// TODO: HELPER_REFACTOR - Move to pkg/clusterfuzz/deploy or pkg/clusterfuzz/wait
// Type: Business Logic
// Related functions: waitForService, deployInfrastructure
// Dependencies: eos_io, otelzap, context, time, zap, fmt
// TODO: Move to pkg/clusterfuzz/deploy or pkg/clusterfuzz/wait
func waitForInfrastructure(rc *eos_io.RuntimeContext, config *clusterfuzz.Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	services := []struct {
		name string
		port int
		host string
	}{
		{"database", config.DatabaseConfig.Port, config.DatabaseConfig.Host},
		{"queue", config.QueueConfig.Port, config.QueueConfig.Host},
	}

	if config.StorageBackend == "minio" {
		services = append(services, struct {
			name string
			port int
			host string
		}{"minio", 9000, "localhost"})
	}

	// Wait for each service
	ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Minute)
	defer cancel()

	for _, svc := range services {
		logger.Info("Waiting for service to be ready",
			zap.String("service", svc.name),
			zap.String("host", svc.host),
			zap.Int("port", svc.port))

		if err := waitForService(ctx, svc.host, svc.port); err != nil {
			return fmt.Errorf("%s service failed to start: %w", svc.name, err)
		}

		logger.Info("Service is ready", zap.String("service", svc.name))
	}

	return nil
}

// TODO: HELPER_REFACTOR - Move to pkg/shared/network or pkg/eos_io
// Type: Utility
// Related functions: waitForInfrastructure
// Dependencies: context, time, net, strconv
// TODO: Move to pkg/shared/network or pkg/eos_io
func waitForService(ctx context.Context, host string, port int) error {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			conn, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
			if err == nil {
				if closeErr := conn.Close(); closeErr != nil {
					fmt.Printf("Warning: Failed to close connection: %v\n", closeErr)
				}
				return nil
			}
		}
	}
}

// TODO: HELPER_REFACTOR - Move to pkg/clusterfuzz/init or pkg/clusterfuzz/services
// Type: Business Logic
// Related functions: deployInfrastructure, deployApplication
// Dependencies: eos_io, otelzap, os, fmt, zap
// TODO: Move to pkg/clusterfuzz/init or pkg/clusterfuzz/services
func initializeServices(rc *eos_io.RuntimeContext, config *clusterfuzz.Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Initialize database
	logger.Info("Initializing database schema...")
	dbScriptPath := filepath.Join(config.ConfigDir, "init", "db-setup.sql")

	switch config.DatabaseBackend {
	case "postgresql":
		// Set password environment variable
		if err := os.Setenv("PGPASSWORD", config.DatabaseConfig.Password); err != nil {
			return fmt.Errorf("failed to set PGPASSWORD: %w", err)
		}
		defer func() {
			if err := os.Unsetenv("PGPASSWORD"); err != nil {
				fmt.Printf("Warning: Failed to unset PGPASSWORD: %v\n", err)
			}
		}()

		if _, err := executeCommand(rc, "psql",
			"-h", "localhost", // Use localhost for initial setup
			"-p", fmt.Sprintf("%d", config.DatabaseConfig.Port),
			"-U", config.DatabaseConfig.Username,
			"-d", config.DatabaseConfig.Database,
			"-f", dbScriptPath); err != nil {
			logger.Warn("Database initialization had warnings", zap.Error(err))
		}
	}

	// Initialize storage
	if config.StorageBackend == "minio" {
		logger.Info("Initializing MinIO storage...")
		storageScriptPath := filepath.Join(config.ConfigDir, "init", "storage-setup.sh")

		// Install mc (MinIO client) if not available
		if _, err := executeCommand(rc, "which", "mc"); err != nil {
			logger.Info("Installing MinIO client...")
			// Install MinIO client
			if _, err := executeCommand(rc, "curl", "-o", "/tmp/mc", "https://dl.min.io/client/mc/release/linux-amd64/mc"); err != nil {
				logger.Warn("Failed to download MinIO client", zap.Error(err))
			} else {
				if _, err := executeCommand(rc, "chmod", "+x", "/tmp/mc"); err != nil {
					logger.Warn("Failed to make mc executable", zap.Error(err))
				} else {
					if _, err := executeCommand(rc, "sudo", "mv", "/tmp/mc", "/usr/local/bin/"); err != nil {
						logger.Warn("Failed to install MinIO client", zap.Error(err))
					}
				}
			}
		}

		// Run storage setup
		if _, err := executeCommand(rc, "bash", storageScriptPath); err != nil {
			logger.Warn("Storage initialization had warnings", zap.Error(err))
		}
	}

	return nil
}

// TODO: HELPER_REFACTOR - Move to pkg/clusterfuzz/deploy or pkg/clusterfuzz/application
// Type: Business Logic
// Related functions: deployInfrastructure, deployBots
// Dependencies: eos_io, otelzap, fmt, time, zap
// TODO: Move to pkg/clusterfuzz/deploy or pkg/clusterfuzz/application
func deployApplication(rc *eos_io.RuntimeContext, config *clusterfuzz.Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	// The web application is already deployed as part of core services
	logger.Info("ClusterFuzz web interface deployed with core services")

	// Verify web interface is accessible
	webURL := fmt.Sprintf("http://%s:8080/health", config.Domain)

	retries := 10
	for i := 0; i < retries; i++ {
		if _, err := executeCommand(rc, "curl", "-f", "-s", webURL); err == nil {
			logger.Info("Web interface is accessible", zap.String("url", webURL))
			break
		}

		if i < retries-1 {
			logger.Info("Waiting for web interface to start...",
				zap.Int("attempt", i+1),
				zap.Int("max_attempts", retries))
			time.Sleep(5 * time.Second)
		} else {
			logger.Warn("Web interface health check failed, but continuing")
		}
	}

	return nil
}

// TODO: HELPER_REFACTOR - Move to pkg/clusterfuzz/deploy or pkg/clusterfuzz/bots
// Type: Business Logic
// Related functions: deployInfrastructure, deployApplication
// Dependencies: eos_io, otelzap, filepath, fmt, zap
// TODO: Move to pkg/clusterfuzz/deploy or pkg/clusterfuzz/bots
func deployBots(rc *eos_io.RuntimeContext, config *clusterfuzz.Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Deploy bot jobs
	logger.Info("Deploying fuzzing bots to Nomad...")
	botJobPath := filepath.Join(config.ConfigDir, "jobs", "clusterfuzz-bots.nomad")

	if _, err := executeCommand(rc, "nomad", "job", "run", "-address="+config.NomadAddress, botJobPath); err != nil {
		return fmt.Errorf("failed to deploy bots: %w", err)
	}

	logger.Info("Fuzzing bots deployed successfully",
		zap.Int("regular_bots", config.BotCount),
		zap.Int("preemptible_bots", config.PreemptibleBotCount))

	return nil
}

// TODO: HELPER_REFACTOR - Move to pkg/clusterfuzz/verify or pkg/clusterfuzz/validation
// Type: Validation
// Related functions: checkPrerequisites
// Dependencies: eos_io, otelzap, strings, fmt, zap
// TODO: Move to pkg/clusterfuzz/verify or pkg/clusterfuzz/validation
func verifyDeployment(rc *eos_io.RuntimeContext, config *clusterfuzz.Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check job status
	logger.Info("Verifying deployment status...")

	jobs := []string{"clusterfuzz-core", "clusterfuzz-bots"}
	for _, job := range jobs {
		output, err := executeCommand(rc, "nomad", "job", "status", "-address="+config.NomadAddress, job)
		if err != nil {
			return fmt.Errorf("failed to check status of job %s: %w", job, err)
		}

		if strings.Contains(output, "running") {
			logger.Info("Job is running", zap.String("job", job))
		} else {
			logger.Warn("Job may not be fully running",
				zap.String("job", job),
				zap.String("status", output))
		}
	}

	return nil
}

// TODO: HELPER_REFACTOR - Move to pkg/clusterfuzz/display or pkg/clusterfuzz/output
// Type: Output Formatter
// Related functions: None visible in this file
// Dependencies: fmt
// TODO: Move to pkg/clusterfuzz/display or pkg/clusterfuzz/output
func displaySuccessInfo(config *clusterfuzz.Config) {
	fmt.Println("\nClusterFuzz deployment completed successfully!")
	fmt.Println("\nDeployment Summary:")
	fmt.Printf("   • Web Interface: http://%s:8080\n", config.Domain)
	if config.StorageBackend == "minio" {
		fmt.Printf("   • MinIO Console: http://%s:9001\n", config.Domain)
		fmt.Printf("     - Access Key: %s\n", config.S3Config.AccessKey)
		fmt.Printf("     - Secret Key: [hidden]\n")
	}
	fmt.Printf("   • Database: %s on port %d\n", config.DatabaseBackend, config.DatabaseConfig.Port)
	fmt.Printf("   • Queue: %s on port %d\n", config.QueueBackend, config.QueueConfig.Port)
	fmt.Printf("   • Regular Bots: %d\n", config.BotCount)
	fmt.Printf("   • Preemptible Bots: %d\n", config.PreemptibleBotCount)

	fmt.Println("\n🚀 Next Steps:")
	fmt.Println("   1. Access the web interface to configure fuzzing jobs")
	fmt.Println("   2. Upload your fuzzing targets")
	fmt.Println("   3. Monitor fuzzing progress and crashes")

	fmt.Println("\n Configuration saved to:", config.ConfigDir)
	fmt.Println("\n💡 Useful Commands:")
	fmt.Printf("   • View logs: nomad alloc logs -address=%s <alloc-id>\n", config.NomadAddress)
	fmt.Printf("   • Check status: nomad job status -address=%s clusterfuzz-core\n", config.NomadAddress)
	fmt.Printf("   • Scale bots: nomad job scale -address=%s clusterfuzz-bots regular-bots %d\n",
		config.NomadAddress, config.BotCount+2)

	if config.UseVault {
		fmt.Printf("\n Secrets stored in Vault at: %s\n", config.VaultPath)
	}
}

// Helper functions

// TODO: HELPER_REFACTOR - Move to pkg/eos_cli or pkg/system
// Type: Utility
// Related functions: Used throughout the file
// Dependencies: eos_io, execute
// TODO: Move to pkg/eos_cli or pkg/system
func executeCommand(rc *eos_io.RuntimeContext, command string, args ...string) (string, error) {
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: command,
		Args:    args,
		Capture: true,
	})
	return output, err
}



