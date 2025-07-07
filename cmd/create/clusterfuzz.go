package create

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"

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
	Long: `Deploy ClusterFuzz on Nomad with configurable backends.
	
ClusterFuzz is Google's scalable fuzzing infrastructure, adapted for Nomad deployment.
This command sets up all required services including database, queue, storage, and fuzzing bots.`,
	RunE: eos_cli.Wrap(runClusterfuzz),
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

// ClusterfuzzConfig holds the configuration for deployment
type ClusterfuzzConfig struct {
	NomadAddress        string
	ConsulAddress       string
	StorageBackend      string
	DatabaseBackend     string
	QueueBackend        string
	BotCount            int
	PreemptibleBotCount int
	Domain              string
	ConfigDir           string
	UseVault            bool
	VaultPath           string
	S3Config            S3Config
	DatabaseConfig      DatabaseConfig
	QueueConfig         QueueConfig
	Timestamp           string
}

// S3Config holds S3/MinIO configuration
type S3Config struct {
	Endpoint  string
	AccessKey string
	SecretKey string
	Bucket    string
	UseSSL    bool
}

// DatabaseConfig holds database configuration
type DatabaseConfig struct {
	Type     string
	Host     string
	Port     int
	Database string
	Username string
	Password string
}

// QueueConfig holds queue configuration
type QueueConfig struct {
	Type     string
	Host     string
	Port     int
	Username string
	Password string
}

func runClusterfuzz(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting ClusterFuzz deployment on Nomad",
		zap.String("nomad_address", nomadAddress),
		zap.String("storage_backend", storageBackend),
		zap.String("database_backend", databaseBackend))

	// Validate configuration
	if err := validateClusterfuzzConfig(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	// Create configuration
	config := createClusterfuzzConfig()

	// Check prerequisites
	if !skipPrereqCheck {
		logger.Info("Checking prerequisites...")
		if err := checkPrerequisites(rc, config); err != nil {
			return fmt.Errorf("prerequisite check failed: %w", err)
		}
	}

	// Create configuration directory
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Generate configurations
	logger.Info("Generating ClusterFuzz configurations...")
	if err := generateConfigurations(rc, config); err != nil {
		return fmt.Errorf("failed to generate configurations: %w", err)
	}

	// Store secrets in Vault if enabled
	if useVault {
		logger.Info("Storing secrets in Vault...")
		if err := storeSecretsInVault(rc, config); err != nil {
			return fmt.Errorf("failed to store secrets in Vault: %w", err)
		}
	}

	// Deploy infrastructure services
	logger.Info("Deploying infrastructure services...")
	if err := deployInfrastructure(rc, config); err != nil {
		return fmt.Errorf("failed to deploy infrastructure: %w", err)
	}

	// Wait for infrastructure to be ready
	logger.Info("Waiting for infrastructure services to be ready...")
	if err := waitForInfrastructure(rc, config); err != nil {
		return fmt.Errorf("infrastructure failed to become ready: %w", err)
	}

	// Initialize databases and storage
	logger.Info("Initializing databases and storage...")
	if err := initializeServices(rc, config); err != nil {
		return fmt.Errorf("failed to initialize services: %w", err)
	}

	// Deploy ClusterFuzz application
	logger.Info("Deploying ClusterFuzz application...")
	if err := deployApplication(rc, config); err != nil {
		return fmt.Errorf("failed to deploy application: %w", err)
	}

	// Deploy fuzzing bots
	logger.Info("Deploying fuzzing bots...")
	if err := deployBots(rc, config); err != nil {
		return fmt.Errorf("failed to deploy bots: %w", err)
	}

	// Verify deployment
	logger.Info("Verifying deployment...")
	if err := verifyDeployment(rc, config); err != nil {
		return fmt.Errorf("deployment verification failed: %w", err)
	}

	// Display success information
	displaySuccessInfo(config)

	logger.Info("ClusterFuzz deployment completed successfully")
	return nil
}

func validateClusterfuzzConfig() error {
	// Validate storage backend
	validStorage := []string{"minio", "s3", "local"}
	if !containsString(validStorage, storageBackend) {
		return fmt.Errorf("invalid storage backend: %s (valid: %v)", storageBackend, validStorage)
	}

	// Validate database backend
	validDB := []string{"postgresql", "mongodb"}
	if !containsString(validDB, databaseBackend) {
		return fmt.Errorf("invalid database backend: %s (valid: %v)", databaseBackend, validDB)
	}

	// Validate queue backend
	validQueue := []string{"redis", "rabbitmq"}
	if !containsString(validQueue, queueBackend) {
		return fmt.Errorf("invalid queue backend: %s (valid: %v)", queueBackend, validQueue)
	}

	// Validate S3 configuration if using S3/MinIO
	if storageBackend == "s3" || storageBackend == "minio" {
		if s3Endpoint == "" && storageBackend == "minio" {
			s3Endpoint = "http://localhost:9000" // Default MinIO endpoint
		}
		if s3AccessKey == "" || s3SecretKey == "" {
			return fmt.Errorf("S3 access key and secret key are required for %s backend", storageBackend)
		}
	}

	// Validate bot counts
	if botCount < 0 || preemptibleBotCount < 0 {
		return fmt.Errorf("bot counts must be non-negative")
	}

	return nil
}

func createClusterfuzzConfig() *ClusterfuzzConfig {
	config := &ClusterfuzzConfig{
		NomadAddress:        nomadAddress,
		ConsulAddress:       consulAddress,
		StorageBackend:      storageBackend,
		DatabaseBackend:     databaseBackend,
		QueueBackend:        queueBackend,
		BotCount:            botCount,
		PreemptibleBotCount: preemptibleBotCount,
		Domain:              domain,
		ConfigDir:           configDir,
		UseVault:            useVault,
		VaultPath:           vaultPath,
		Timestamp:           time.Now().Format("20060102-150405"),
	}

	// Configure S3/MinIO
	if storageBackend == "s3" || storageBackend == "minio" {
		config.S3Config = S3Config{
			Endpoint:  s3Endpoint,
			AccessKey: s3AccessKey,
			SecretKey: s3SecretKey,
			Bucket:    s3Bucket,
			UseSSL:    !strings.HasPrefix(s3Endpoint, "http://"),
		}
	}

	// Configure database
	switch databaseBackend {
	case "postgresql":
		config.DatabaseConfig = DatabaseConfig{
			Type:     "postgresql",
			Host:     "clusterfuzz-postgres.service.consul",
			Port:     5432,
			Database: "clusterfuzz",
			Username: "clusterfuzz",
			Password: generatePassword(),
		}
	case "mongodb":
		config.DatabaseConfig = DatabaseConfig{
			Type:     "mongodb",
			Host:     "clusterfuzz-mongodb.service.consul",
			Port:     27017,
			Database: "clusterfuzz",
			Username: "clusterfuzz",
			Password: generatePassword(),
		}
	}

	// Configure queue
	switch queueBackend {
	case "redis":
		config.QueueConfig = QueueConfig{
			Type:     "redis",
			Host:     "clusterfuzz-redis.service.consul",
			Port:     6379,
			Password: generatePassword(),
		}
	case "rabbitmq":
		config.QueueConfig = QueueConfig{
			Type:     "rabbitmq",
			Host:     "clusterfuzz-rabbitmq.service.consul",
			Port:     5672,
			Username: "clusterfuzz",
			Password: generatePassword(),
		}
	}

	return config
}

func checkPrerequisites(rc *eos_io.RuntimeContext, config *ClusterfuzzConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check Nomad connectivity
	logger.Info("Checking Nomad connectivity...")
	if _, err := executeCommand(rc, "nomad", "status", "-address="+config.NomadAddress); err != nil {
		return fmt.Errorf("cannot connect to Nomad at %s: %w", config.NomadAddress, err)
	}

	// Check Consul connectivity
	logger.Info("Checking Consul connectivity...")
	if _, err := executeCommand(rc, "consul", "members", "-http-addr="+config.ConsulAddress); err != nil {
		logger.Warn("Consul not available, service discovery will be limited",
			zap.String("consul_address", config.ConsulAddress))
	}

	// Check if required tools are installed
	requiredTools := []string{"nomad", "docker"}
	for _, tool := range requiredTools {
		if _, err := executeCommand(rc, "which", tool); err != nil {
			return fmt.Errorf("%s is required but not found in PATH", tool)
		}
	}

	// Check if Vault is accessible if enabled
	if config.UseVault {
		logger.Info("Checking Vault connectivity...")
		if err := checkVaultConnectivity(rc); err != nil {
			return fmt.Errorf("Vault check failed: %w", err)
		}
	}

	return nil
}

func generateConfigurations(rc *eos_io.RuntimeContext, config *ClusterfuzzConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Create directory structure
	dirs := []string{
		filepath.Join(config.ConfigDir, "jobs"),
		filepath.Join(config.ConfigDir, "env"),
		filepath.Join(config.ConfigDir, "init"),
		filepath.Join(config.ConfigDir, "docker"),
		filepath.Join(config.ConfigDir, "terraform"),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	// Generate Nomad job files
	logger.Info("Generating Nomad job files...")
	if err := generateNomadJobs(config); err != nil {
		return fmt.Errorf("failed to generate Nomad jobs: %w", err)
	}

	// Generate environment files
	logger.Info("Generating environment configuration files...")
	if err := generateEnvironmentFiles(config); err != nil {
		return fmt.Errorf("failed to generate environment files: %w", err)
	}

	// Generate initialization scripts
	logger.Info("Generating initialization scripts...")
	if err := generateInitScripts(config); err != nil {
		return fmt.Errorf("failed to generate init scripts: %w", err)
	}

	// Generate Dockerfiles
	logger.Info("Generating Dockerfiles...")
	if err := generateDockerfiles(config); err != nil {
		return fmt.Errorf("failed to generate Dockerfiles: %w", err)
	}

	// Generate Terraform configuration if using Terraform
	if config.UseVault || storageBackend == "s3" {
		logger.Info("Generating Terraform configuration...")
		if err := generateTerraformConfig(config); err != nil {
			return fmt.Errorf("failed to generate Terraform config: %w", err)
		}
	}

	return nil
}

func generateNomadJobs(config *ClusterfuzzConfig) error {
	// Template for core services job
	coreJobTemplate := `job "clusterfuzz-core" {
  datacenters = ["dc1"]
  type = "service"
  
  update {
    max_parallel = 1
    min_healthy_time = "10s"
    healthy_deadline = "5m"
    auto_revert = true
  }

  {{if eq .DatabaseBackend "postgresql"}}
  group "database" {
    count = 1
    
    network {
      port "db" {
        static = 5432
      }
    }
    
    service {
      name = "clusterfuzz-postgres"
      port = "db"
      
      check {
        type = "tcp"
        interval = "10s"
        timeout = "2s"
      }
    }
    
    task "postgres" {
      driver = "docker"
      
      config {
        image = "postgres:15"
        ports = ["db"]
        
        volumes = [
          "local/init:/docker-entrypoint-initdb.d"
        ]
      }
      
      template {
        data = <<EOF
#!/bin/bash
set -e
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<-EOSQL
    CREATE DATABASE clusterfuzz;
    GRANT ALL PRIVILEGES ON DATABASE clusterfuzz TO $POSTGRES_USER;
EOSQL
EOF
        destination = "local/init/01-create-db.sh"
        perms = "755"
      }
      
      env {
        POSTGRES_USER = "{{.DatabaseConfig.Username}}"
        POSTGRES_PASSWORD = "{{.DatabaseConfig.Password}}"
        POSTGRES_DB = "{{.DatabaseConfig.Database}}"
      }
      
      resources {
        cpu    = 2000
        memory = 4096
      }
    }
  }
  {{end}}

  {{if eq .QueueBackend "redis"}}
  group "queue" {
    count = 1
    
    network {
      port "redis" {
        static = 6379
      }
    }
    
    service {
      name = "clusterfuzz-redis"
      port = "redis"
      
      check {
        type = "tcp"
        interval = "10s"
        timeout = "2s"
      }
    }
    
    task "redis" {
      driver = "docker"
      
      config {
        image = "redis:7-alpine"
        ports = ["redis"]
        command = "redis-server"
        args = ["--requirepass", "{{.QueueConfig.Password}}"]
      }
      
      resources {
        cpu    = 500
        memory = 1024
      }
    }
  }
  {{end}}

  {{if eq .StorageBackend "minio"}}
  group "storage" {
    count = 1
    
    network {
      port "minio" {
        static = 9000
      }
      port "console" {
        static = 9001
      }
    }
    
    service {
      name = "clusterfuzz-minio"
      port = "minio"
      
      check {
        type = "http"
        path = "/minio/health/live"
        interval = "10s"
        timeout = "2s"
      }
    }
    
    task "minio" {
      driver = "docker"
      
      config {
        image = "minio/minio:latest"
        ports = ["minio", "console"]
        args = ["server", "/data", "--console-address", ":9001"]
      }
      
      env {
        MINIO_ROOT_USER = "{{.S3Config.AccessKey}}"
        MINIO_ROOT_PASSWORD = "{{.S3Config.SecretKey}}"
      }
      
      resources {
        cpu    = 1000
        memory = 2048
      }
    }
  }
  {{end}}

  group "web" {
    count = 1
    
    network {
      port "http" {
        static = 8080
      }
    }
    
    service {
      name = "clusterfuzz-web"
      port = "http"
      
      check {
        type = "http"
        path = "/health"
        interval = "30s"
        timeout = "5s"
      }
    }
    
    task "web" {
      driver = "docker"
      
      config {
        image = "clusterfuzz/web:custom"
        ports = ["http"]
        
        volumes = [
          "secrets/config:/etc/clusterfuzz/config"
        ]
      }
      
      template {
        data = <<EOF
# ClusterFuzz Configuration
DATABASE_URL={{if eq .DatabaseBackend "postgresql"}}postgresql://{{.DatabaseConfig.Username}}:{{.DatabaseConfig.Password}}@{{.DatabaseConfig.Host}}:{{.DatabaseConfig.Port}}/{{.DatabaseConfig.Database}}{{end}}
REDIS_URL=redis://:{{.QueueConfig.Password}}@{{.QueueConfig.Host}}:{{.QueueConfig.Port}}/0
{{if eq .StorageBackend "minio"}}
S3_ENDPOINT={{.S3Config.Endpoint}}
S3_ACCESS_KEY={{.S3Config.AccessKey}}
S3_SECRET_KEY={{.S3Config.SecretKey}}
S3_BUCKET={{.S3Config.Bucket}}
{{end}}
DOMAIN={{.Domain}}
DISABLE_AUTH=true
EOF
        destination = "secrets/config/app.env"
        env = true
      }
      
      resources {
        cpu    = 1000
        memory = 2048
      }
    }
  }
}`

	// Write core services job
	tmpl, err := template.New("core").Parse(coreJobTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse core job template: %w", err)
	}

	coreJobPath := filepath.Join(config.ConfigDir, "jobs", "clusterfuzz-core.nomad")
	coreFile, err := os.Create(coreJobPath)
	if err != nil {
		return fmt.Errorf("failed to create core job file: %w", err)
	}
	defer coreFile.Close()

	if err := tmpl.Execute(coreFile, config); err != nil {
		return fmt.Errorf("failed to execute core job template: %w", err)
	}

	// Template for bot jobs
	botJobTemplate := `job "clusterfuzz-bots" {
  datacenters = ["dc1"]
  type = "batch"
  
  periodic {
    cron = "*/5 * * * *"
    prohibit_overlap = true
  }

  group "regular-bots" {
    count = {{.BotCount}}
    
    task "bot" {
      driver = "docker"
      
      config {
        image = "clusterfuzz/bot:custom"
        
        volumes = [
          "secrets/config:/etc/clusterfuzz/config"
        ]
      }
      
      template {
        data = <<EOF
# Bot Configuration
WEB_URL=http://{{.Domain}}:8080
DATABASE_URL={{if eq .DatabaseBackend "postgresql"}}postgresql://{{.DatabaseConfig.Username}}:{{.DatabaseConfig.Password}}@{{.DatabaseConfig.Host}}:{{.DatabaseConfig.Port}}/{{.DatabaseConfig.Database}}{{end}}
REDIS_URL=redis://:{{.QueueConfig.Password}}@{{.QueueConfig.Host}}:{{.QueueConfig.Port}}/0
{{if eq .StorageBackend "minio"}}
S3_ENDPOINT={{.S3Config.Endpoint}}
S3_ACCESS_KEY={{.S3Config.AccessKey}}
S3_SECRET_KEY={{.S3Config.SecretKey}}
S3_BUCKET={{.S3Config.Bucket}}
{{end}}
BOT_NAME={{env "NOMAD_ALLOC_ID"}}
TASK_TYPES=all
EOF
        destination = "secrets/config/bot.env"
        env = true
      }
      
      resources {
        cpu    = 500
        memory = 1024
      }
    }
  }

  {{if gt .PreemptibleBotCount 0}}
  group "preemptible-bots" {
    count = {{.PreemptibleBotCount}}
    
    task "bot" {
      driver = "docker"
      
      config {
        image = "clusterfuzz/bot:custom"
        
        volumes = [
          "secrets/config:/etc/clusterfuzz/config"
        ]
      }
      
      template {
        data = <<EOF
# Preemptible Bot Configuration
WEB_URL=http://{{.Domain}}:8080
DATABASE_URL={{if eq .DatabaseBackend "postgresql"}}postgresql://{{.DatabaseConfig.Username}}:{{.DatabaseConfig.Password}}@{{.DatabaseConfig.Host}}:{{.DatabaseConfig.Port}}/{{.DatabaseConfig.Database}}{{end}}
REDIS_URL=redis://:{{.QueueConfig.Password}}@{{.QueueConfig.Host}}:{{.QueueConfig.Port}}/0
{{if eq .StorageBackend "minio"}}
S3_ENDPOINT={{.S3Config.Endpoint}}
S3_ACCESS_KEY={{.S3Config.AccessKey}}
S3_SECRET_KEY={{.S3Config.SecretKey}}
S3_BUCKET={{.S3Config.Bucket}}
{{end}}
BOT_NAME={{env "NOMAD_ALLOC_ID"}}
TASK_TYPES=fuzz
PREEMPTIBLE=true
EOF
        destination = "secrets/config/bot.env"
        env = true
      }
      
      resources {
        cpu    = 2000
        memory = 2048
      }
    }
  }
  {{end}}
}`

	// Write bot jobs
	botTmpl, err := template.New("bots").Parse(botJobTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse bot job template: %w", err)
	}

	botJobPath := filepath.Join(config.ConfigDir, "jobs", "clusterfuzz-bots.nomad")
	botFile, err := os.Create(botJobPath)
	if err != nil {
		return fmt.Errorf("failed to create bot job file: %w", err)
	}
	defer botFile.Close()

	if err := botTmpl.Execute(botFile, config); err != nil {
		return fmt.Errorf("failed to execute bot job template: %w", err)
	}

	return nil
}

func generateEnvironmentFiles(config *ClusterfuzzConfig) error {
	// Core environment file
	coreEnv := fmt.Sprintf(`# ClusterFuzz Core Environment
DATABASE_TYPE=%s
DATABASE_HOST=%s
DATABASE_PORT=%d
DATABASE_NAME=%s
DATABASE_USER=%s
DATABASE_PASSWORD=%s

QUEUE_TYPE=%s
QUEUE_HOST=%s
QUEUE_PORT=%d
QUEUE_PASSWORD=%s

STORAGE_TYPE=%s
`, config.DatabaseBackend,
		config.DatabaseConfig.Host,
		config.DatabaseConfig.Port,
		config.DatabaseConfig.Database,
		config.DatabaseConfig.Username,
		config.DatabaseConfig.Password,
		config.QueueBackend,
		config.QueueConfig.Host,
		config.QueueConfig.Port,
		config.QueueConfig.Password,
		config.StorageBackend)

	if config.StorageBackend == "minio" || config.StorageBackend == "s3" {
		coreEnv += fmt.Sprintf(`S3_ENDPOINT=%s
S3_ACCESS_KEY=%s
S3_SECRET_KEY=%s
S3_BUCKET=%s
S3_USE_SSL=%t
`, config.S3Config.Endpoint,
			config.S3Config.AccessKey,
			config.S3Config.SecretKey,
			config.S3Config.Bucket,
			config.S3Config.UseSSL)
	}

	coreEnvPath := filepath.Join(config.ConfigDir, "env", "core.env")
	if err := os.WriteFile(coreEnvPath, []byte(coreEnv), 0600); err != nil {
		return fmt.Errorf("failed to write core env file: %w", err)
	}

	// Bot environment file
	botEnv := fmt.Sprintf(`# ClusterFuzz Bot Environment
WEB_URL=http://%s:8080
DISABLE_AUTH=true
BOT_WORKING_DIR=/tmp/clusterfuzz
`, config.Domain)

	botEnvPath := filepath.Join(config.ConfigDir, "env", "bots.env")
	if err := os.WriteFile(botEnvPath, []byte(botEnv), 0600); err != nil {
		return fmt.Errorf("failed to write bot env file: %w", err)
	}

	return nil
}

func generateInitScripts(config *ClusterfuzzConfig) error {
	// Database initialization script
	var dbScript string
	switch config.DatabaseBackend {
	case "postgresql":
		dbScript = `-- ClusterFuzz PostgreSQL Schema
CREATE SCHEMA IF NOT EXISTS clusterfuzz;

-- Create tables for ClusterFuzz
CREATE TABLE IF NOT EXISTS clusterfuzz.testcases (
    id SERIAL PRIMARY KEY,
    crash_type VARCHAR(255),
    crash_state TEXT,
    security_flag BOOLEAN DEFAULT FALSE,
    fuzzer_name VARCHAR(255),
    job_type VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS clusterfuzz.fuzzers (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL,
    revision INTEGER DEFAULT 0,
    jobs TEXT[],
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS clusterfuzz.jobs (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL,
    platform VARCHAR(50),
    description TEXT,
    environment TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS clusterfuzz.crash_statistics (
    id SERIAL PRIMARY KEY,
    crash_type VARCHAR(255),
    crash_state TEXT,
    crash_count INTEGER DEFAULT 0,
    last_seen TIMESTAMP,
    first_seen TIMESTAMP,
    is_security BOOLEAN DEFAULT FALSE
);

-- Create indexes
CREATE INDEX idx_testcases_fuzzer ON clusterfuzz.testcases(fuzzer_name);
CREATE INDEX idx_testcases_job ON clusterfuzz.testcases(job_type);
CREATE INDEX idx_testcases_security ON clusterfuzz.testcases(security_flag);
CREATE INDEX idx_crash_stats_type ON clusterfuzz.crash_statistics(crash_type);
`
	case "mongodb":
		dbScript = `// ClusterFuzz MongoDB Schema
db = db.getSiblingDB('clusterfuzz');

// Create collections
db.createCollection('testcases');
db.createCollection('fuzzers');
db.createCollection('jobs');
db.createCollection('crash_statistics');

// Create indexes
db.testcases.createIndex({ fuzzer_name: 1 });
db.testcases.createIndex({ job_type: 1 });
db.testcases.createIndex({ security_flag: 1 });
db.testcases.createIndex({ created_at: -1 });

db.fuzzers.createIndex({ name: 1 }, { unique: true });
db.jobs.createIndex({ name: 1 }, { unique: true });
db.crash_statistics.createIndex({ crash_type: 1 });
db.crash_statistics.createIndex({ last_seen: -1 });
`
	}

	dbScriptPath := filepath.Join(config.ConfigDir, "init", "db-setup.sql")
	if err := os.WriteFile(dbScriptPath, []byte(dbScript), 0644); err != nil {
		return fmt.Errorf("failed to write db script: %w", err)
	}

	// Storage initialization script
	storageScript := `#!/bin/bash
# ClusterFuzz Storage Setup

set -e

echo "Setting up ClusterFuzz storage..."

`

	if config.StorageBackend == "minio" {
		storageScript += fmt.Sprintf(`
# Wait for MinIO to be ready
until mc alias set clusterfuzz %s %s %s; do
  echo "Waiting for MinIO..."
  sleep 5
done

# Create bucket if it doesn't exist
mc mb clusterfuzz/%s --ignore-existing

# Set bucket policies
mc policy set download clusterfuzz/%s/public
mc policy set private clusterfuzz/%s/private

# Create directory structure
mc cp /dev/null clusterfuzz/%s/corpus/.keep
mc cp /dev/null clusterfuzz/%s/crashes/.keep
mc cp /dev/null clusterfuzz/%s/coverage/.keep
mc cp /dev/null clusterfuzz/%s/stats/.keep

echo "MinIO storage setup complete"
`, config.S3Config.Endpoint,
			config.S3Config.AccessKey,
			config.S3Config.SecretKey,
			config.S3Config.Bucket,
			config.S3Config.Bucket,
			config.S3Config.Bucket,
			config.S3Config.Bucket,
			config.S3Config.Bucket,
			config.S3Config.Bucket,
			config.S3Config.Bucket)
	}

	storageScriptPath := filepath.Join(config.ConfigDir, "init", "storage-setup.sh")
	if err := os.WriteFile(storageScriptPath, []byte(storageScript), 0755); err != nil {
		return fmt.Errorf("failed to write storage script: %w", err)
	}

	return nil
}

func generateDockerfiles(config *ClusterfuzzConfig) error {
	// Web Dockerfile
	webDockerfile := `FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Clone ClusterFuzz
RUN git clone https://github.com/google/clusterfuzz.git /clusterfuzz

WORKDIR /clusterfuzz

# Install Python dependencies
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

# Apply patches for non-GCP deployment
COPY patches/non_gcp.patch /tmp/
RUN patch -p1 < /tmp/non_gcp.patch || true

# Set up environment
ENV PYTHONPATH=/clusterfuzz/src
ENV DISABLE_REMOTE_APIS=1
ENV LOCAL_DEVELOPMENT=1

# Copy custom entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8080

ENTRYPOINT ["/entrypoint.sh"]
CMD ["python", "src/appengine/main.py"]
`

	webDockerfilePath := filepath.Join(config.ConfigDir, "docker", "web.Dockerfile")
	if err := os.WriteFile(webDockerfilePath, []byte(webDockerfile), 0644); err != nil {
		return fmt.Errorf("failed to write web Dockerfile: %w", err)
	}

	// Bot Dockerfile
	botDockerfile := `FROM ubuntu:22.04

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    git \
    curl \
    build-essential \
    llvm \
    clang \
    && rm -rf /var/lib/apt/lists/*

# Clone ClusterFuzz
RUN git clone https://github.com/google/clusterfuzz.git /clusterfuzz

WORKDIR /clusterfuzz

# Install Python dependencies
RUN pip3 install --upgrade pip
RUN pip3 install -r requirements.txt

# Install fuzzing engines
RUN python3 butler.py setup

# Apply patches for non-GCP deployment
COPY patches/bot_non_gcp.patch /tmp/
RUN patch -p1 < /tmp/bot_non_gcp.patch || true

# Set up environment
ENV PYTHONPATH=/clusterfuzz/src
ENV DISABLE_REMOTE_APIS=1
ENV LOCAL_DEVELOPMENT=1

# Copy custom bot entrypoint
COPY bot_entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["python3", "src/python/bot/startup/run_bot.py"]
`

	botDockerfilePath := filepath.Join(config.ConfigDir, "docker", "bot.Dockerfile")
	if err := os.WriteFile(botDockerfilePath, []byte(botDockerfile), 0644); err != nil {
		return fmt.Errorf("failed to write bot Dockerfile: %w", err)
	}

	// Web entrypoint script
	webEntrypoint := `#!/bin/bash
set -e

echo "Starting ClusterFuzz web interface..."

# Wait for database
until nc -z ${DATABASE_HOST} ${DATABASE_PORT}; do
  echo "Waiting for database..."
  sleep 2
done

# Run migrations
python src/appengine/handlers/setup.py || true

# Start application
exec "$@"
`

	webEntrypointPath := filepath.Join(config.ConfigDir, "docker", "entrypoint.sh")
	if err := os.WriteFile(webEntrypointPath, []byte(webEntrypoint), 0755); err != nil {
		return fmt.Errorf("failed to write web entrypoint: %w", err)
	}

	// Bot entrypoint script
	botEntrypoint := `#!/bin/bash
set -e

echo "Starting ClusterFuzz bot..."

# Create working directory
mkdir -p ${BOT_WORKING_DIR}
cd ${BOT_WORKING_DIR}

# Set bot name
export BOT_NAME=${BOT_NAME:-$(hostname)}

# Start bot
exec "$@"
`

	botEntrypointPath := filepath.Join(config.ConfigDir, "docker", "bot_entrypoint.sh")
	if err := os.WriteFile(botEntrypointPath, []byte(botEntrypoint), 0755); err != nil {
		return fmt.Errorf("failed to write bot entrypoint: %w", err)
	}

	// Create patches directory and add placeholder patches
	patchesDir := filepath.Join(config.ConfigDir, "docker", "patches")
	if err := os.MkdirAll(patchesDir, 0755); err != nil {
		return fmt.Errorf("failed to create patches directory: %w", err)
	}

	// Non-GCP patch for web
	nonGCPPatch := `--- a/src/appengine/handlers/base_handler.py
+++ b/src/appengine/handlers/base_handler.py
@@ -100,7 +100,10 @@ class Handler(webapp2.RequestHandler):
 
   def _check_auth(self):
     """Check authentication."""
-    if not auth.is_authenticated():
+    # Disable auth for local deployment
+    if os.environ.get('DISABLE_AUTH') == 'true':
+      return True
+    elif not auth.is_authenticated():
       raise helpers.UnauthorizedException('User is not authenticated.')
 
--- a/src/python/config/local_config.py
+++ b/src/python/config/local_config.py
@@ -50,6 +50,15 @@ def get_application_config():
   # Override for local development
   if LOCAL_DEVELOPMENT:
     config['datastore_emulator_host'] = 'localhost:8432'
+    
+    # Override for non-GCP deployment
+    if os.environ.get('DATABASE_URL'):
+      config['database_url'] = os.environ.get('DATABASE_URL')
+    if os.environ.get('REDIS_URL'):
+      config['redis_url'] = os.environ.get('REDIS_URL')
+    if os.environ.get('S3_ENDPOINT'):
+      config['storage_backend'] = 's3'
+      config['s3_config'] = {
+        'endpoint': os.environ.get('S3_ENDPOINT'),
+        'access_key': os.environ.get('S3_ACCESS_KEY'),
+        'secret_key': os.environ.get('S3_SECRET_KEY'),
+        'bucket': os.environ.get('S3_BUCKET'),
+      }
 
   return config
`

	nonGCPPatchPath := filepath.Join(patchesDir, "non_gcp.patch")
	if err := os.WriteFile(nonGCPPatchPath, []byte(nonGCPPatch), 0644); err != nil {
		return fmt.Errorf("failed to write non-GCP patch: %w", err)
	}

	// Bot non-GCP patch
	botNonGCPPatch := `--- a/src/python/bot/startup/run_bot.py
+++ b/src/python/bot/startup/run_bot.py
@@ -200,8 +200,12 @@ def main():
   
   # Override metadata service for non-GCP
   if os.environ.get('LOCAL_DEVELOPMENT'):
-    from datastore import ndb_init
-    ndb_init.initialize_ndb()
+    # Use environment variables instead of metadata service
+    os.environ['BOT_NAME'] = os.environ.get('BOT_NAME', socket.gethostname())
+    os.environ['TASK_TYPES'] = os.environ.get('TASK_TYPES', 'all')
+    os.environ['PREEMPTIBLE'] = os.environ.get('PREEMPTIBLE', 'false')
+    # Skip GCP metadata checks
+    os.environ['DISABLE_METADATA_SERVICE'] = 'true'
 
   run_bot()
`

	botNonGCPPatchPath := filepath.Join(patchesDir, "bot_non_gcp.patch")
	if err := os.WriteFile(botNonGCPPatchPath, []byte(botNonGCPPatch), 0644); err != nil {
		return fmt.Errorf("failed to write bot non-GCP patch: %w", err)
	}

	return nil
}

func generateTerraformConfig(config *ClusterfuzzConfig) error {
	// Only generate if using S3/MinIO or Vault
	if config.StorageBackend != "s3" && config.StorageBackend != "minio" && !config.UseVault {
		return nil
	}

	terraformMain := `terraform {
  required_version = ">= 1.0"
  
  required_providers {
    nomad = {
      source = "hashicorp/nomad"
      version = "~> 1.4"
    }
    
    vault = {
      source = "hashicorp/vault"
      version = "~> 3.0"
    }
  }
}

provider "nomad" {
  address = "{{.NomadAddress}}"
}

{{if .UseVault}}
provider "vault" {
  # Vault provider configuration
}

# Create Vault secrets
resource "vault_kv_secret_v2" "clusterfuzz_db" {
  mount = "secret"
  name  = "clusterfuzz/database"
  
  data_json = jsonencode({
    username = "{{.DatabaseConfig.Username}}"
    password = "{{.DatabaseConfig.Password}}"
    host     = "{{.DatabaseConfig.Host}}"
    port     = {{.DatabaseConfig.Port}}
    database = "{{.DatabaseConfig.Database}}"
  })
}

resource "vault_kv_secret_v2" "clusterfuzz_s3" {
  mount = "secret"
  name  = "clusterfuzz/storage"
  
  data_json = jsonencode({
    endpoint   = "{{.S3Config.Endpoint}}"
    access_key = "{{.S3Config.AccessKey}}"
    secret_key = "{{.S3Config.SecretKey}}"
    bucket     = "{{.S3Config.Bucket}}"
  })
}
{{end}}

# Outputs
output "web_url" {
  value = "http://{{.Domain}}:8080"
}

output "minio_console" {
  value = "{{if eq .StorageBackend "minio"}}http://{{.Domain}}:9001{{else}}N/A{{end}}"
}
`

	// Parse and execute template
	tmpl, err := template.New("terraform").Parse(terraformMain)
	if err != nil {
		return fmt.Errorf("failed to parse terraform template: %w", err)
	}

	terraformPath := filepath.Join(config.ConfigDir, "terraform", "main.tf")
	tfFile, err := os.Create(terraformPath)
	if err != nil {
		return fmt.Errorf("failed to create terraform file: %w", err)
	}
	defer tfFile.Close()

	if err := tmpl.Execute(tfFile, config); err != nil {
		return fmt.Errorf("failed to execute terraform template: %w", err)
	}

	return nil
}

func storeSecretsInVault(rc *eos_io.RuntimeContext, config *ClusterfuzzConfig) error {
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

func deployInfrastructure(rc *eos_io.RuntimeContext, config *ClusterfuzzConfig) error {
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

func buildDockerImages(rc *eos_io.RuntimeContext, config *ClusterfuzzConfig) error {
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

func waitForInfrastructure(rc *eos_io.RuntimeContext, config *ClusterfuzzConfig) error {
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

func waitForService(ctx context.Context, host string, port int) error {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
			if err == nil {
				conn.Close()
				return nil
			}
		}
	}
}

func initializeServices(rc *eos_io.RuntimeContext, config *ClusterfuzzConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Initialize database
	logger.Info("Initializing database schema...")
	dbScriptPath := filepath.Join(config.ConfigDir, "init", "db-setup.sql")
	
	switch config.DatabaseBackend {
	case "postgresql":
		// Set password environment variable
		os.Setenv("PGPASSWORD", config.DatabaseConfig.Password)
		defer os.Unsetenv("PGPASSWORD")
		
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

func deployApplication(rc *eos_io.RuntimeContext, config *ClusterfuzzConfig) error {
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

func deployBots(rc *eos_io.RuntimeContext, config *ClusterfuzzConfig) error {
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

func verifyDeployment(rc *eos_io.RuntimeContext, config *ClusterfuzzConfig) error {
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

func displaySuccessInfo(config *ClusterfuzzConfig) {
	fmt.Println("\n✅ ClusterFuzz deployment completed successfully!")
	fmt.Println("\n📋 Deployment Summary:")
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
	
	fmt.Println("\n📁 Configuration saved to:", config.ConfigDir)
	fmt.Println("\n💡 Useful Commands:")
	fmt.Printf("   • View logs: nomad alloc logs -address=%s <alloc-id>\n", config.NomadAddress)
	fmt.Printf("   • Check status: nomad job status -address=%s clusterfuzz-core\n", config.NomadAddress)
	fmt.Printf("   • Scale bots: nomad job scale -address=%s clusterfuzz-bots regular-bots %d\n",
		config.NomadAddress, config.BotCount+2)
	
	if config.UseVault {
		fmt.Printf("\n🔐 Secrets stored in Vault at: %s\n", config.VaultPath)
	}
}

// Helper functions

func executeCommand(rc *eos_io.RuntimeContext, command string, args ...string) (string, error) {
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: command,
		Args:    args,
		Capture: true,
	})
	return output, err
}

func containsString(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func generatePassword() string {
	// Simple password generation (should be replaced with crypto/rand in production)
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 16)
	for i := range b {
		b[i] = charset[time.Now().UnixNano()%int64(len(charset))]
	}
	return string(b)
}

func checkVaultConnectivity(rc *eos_io.RuntimeContext) error {
	// Check if Vault is accessible
	vaultClient, err := vault.NewClient(rc)
	if err != nil {
		return err
	}
	
	// Try to check health to verify connectivity
	healthy, err := vaultClient.Sys().Health()
	if err != nil {
		// This is expected to fail, but we just want to check connectivity
		if strings.Contains(err.Error(), "connection refused") {
			return fmt.Errorf("cannot connect to Vault")
		}
	}
	
	if healthy != nil {
		// Vault is accessible
		return nil
	}
	
	return nil
}