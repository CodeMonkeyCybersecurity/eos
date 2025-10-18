package create

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/clusterfuzz"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/clusterfuzz/config"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/clusterfuzz/generator"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/clusterfuzz/prerequisites"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/clusterfuzz/validation"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)
//TODO: refactor
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
		
		// ASSESS - Check prerequisites and validate configuration
		logger.Info("Assessing ClusterFuzz deployment requirements",
			zap.String("nomad_address", nomadAddress),
			zap.String("storage_backend", storageBackend),
			zap.String("database_backend", databaseBackend))

		// Prompt for S3 credentials if needed and not provided
		if (storageBackend == "s3" || storageBackend == "minio") && (s3AccessKey == "" || s3SecretKey == "") {
			logger.Info("S3 credentials required for storage backend",
				zap.String("backend", storageBackend))
			
			if s3AccessKey == "" {
				logger.Info("terminal prompt: Please enter S3 access key")
				accessKey, err := eos_io.PromptInput(rc, "S3 Access Key: ", "s3_access_key")
				if err != nil {
					return eos_err.NewUserError("failed to read S3 access key: %v", err)
				}
				s3AccessKey = accessKey
			}
			
			if s3SecretKey == "" {
				logger.Info("terminal prompt: Please enter S3 secret key")
				secretKey, err := eos_io.PromptSecurePassword(rc, "S3 Secret Key: ")
				if err != nil {
					return eos_err.NewUserError("failed to read S3 secret key: %v", err)
				}
				s3SecretKey = secretKey
			}
		}

		// Validate configuration after prompting
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

		// INTERVENE - Perform the deployment operations
		logger.Info("Starting ClusterFuzz deployment intervention")

		// Create configuration directory
		logger.Info("Creating configuration directory",
			zap.String("path", configDir))
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
			if err := clusterfuzz.StoreSecretsInVault(rc, cfg); err != nil {
				return fmt.Errorf("failed to store secrets in Vault: %w", err)
			}
		}

		// Deploy infrastructure services
		logger.Info("Deploying infrastructure services...")
		if err := clusterfuzz.DeployInfrastructure(rc, cfg); err != nil {
			return fmt.Errorf("failed to deploy infrastructure: %w", err)
		}

		// Wait for infrastructure to be ready
		logger.Info("Waiting for infrastructure services to be ready...")
		if err := clusterfuzz.WaitForInfrastructure(rc, cfg); err != nil {
			return fmt.Errorf("infrastructure failed to become ready: %w", err)
		}

		// Initialize databases and storage
		logger.Info("Initializing databases and storage...")
		if err := clusterfuzz.InitializeServices(rc, cfg); err != nil {
			return fmt.Errorf("failed to initialize services: %w", err)
		}

		// Deploy ClusterFuzz application
		logger.Info("Deploying ClusterFuzz application...")
		if err := clusterfuzz.DeployApplication(rc, cfg); err != nil {
			return fmt.Errorf("failed to deploy application: %w", err)
		}

		// Deploy fuzzing bots
		logger.Info("Deploying fuzzing bots...")
		if err := clusterfuzz.DeployBots(rc, cfg); err != nil {
			return fmt.Errorf("failed to deploy bots: %w", err)
		}

		// EVALUATE - Verify the deployment was successful
		logger.Info("Evaluating ClusterFuzz deployment success")
		
		if err := clusterfuzz.VerifyDeployment(rc, cfg); err != nil {
			return fmt.Errorf("deployment verification failed: %w", err)
		}

		// Display success information
		clusterfuzz.DisplaySuccessInfo(cfg)

		logger.Info("ClusterFuzz deployment completed successfully")
		return nil
	}),
}

func init() {
	CreateCmd.AddCommand(clusterfuzzCmd)

	// Use the same hostname resolution pattern as Vault
	hostname := shared.GetInternalHostname()
	clusterfuzzCmd.Flags().StringVar(&nomadAddress, "nomad-address", fmt.Sprintf("http://%s:%d", hostname, shared.PortNomad), "Nomad server address")
	clusterfuzzCmd.Flags().StringVar(&consulAddress, "consul-address", fmt.Sprintf("http://%s:%d", hostname, shared.PortConsul), "Consul server address")
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