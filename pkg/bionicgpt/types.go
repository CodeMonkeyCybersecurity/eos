// Package bionicgpt provides functionality to install and configure
// BionicGPT multi-tenant LLM platform using Docker Compose.
//
// The package follows the Eos Assess → Intervene → Evaluate pattern:
//   - Assess: Check prerequisites, Docker availability, and current installation state
//   - Intervene: Install BionicGPT with Docker Compose, configure databases, set up RAG engine
//   - Evaluate: Verify the installation is healthy, containers running, and web interface responds
//
// Security Features:
//   - PostgreSQL with pgVector for RAG capabilities
//   - Row-Level Security (RLS) for multi-tenant data isolation
//   - Document chunking and embedding pipeline
//   - Secure .env file permissions (0600)
//   - Authentication via JWT (configurable)
//
// BionicGPT Integration:
//   - Multi-container architecture (app, database, LLM, embeddings, RAG engine)
//   - Document parsing with unstructured.io
//   - Local LLM support (Llama-3-8b by default)
//   - Comprehensive audit logging
//   - Team-based access control
//
// Example usage:
//
//	config := &bionicgpt.InstallConfig{
//	    Port: 3000,
//	    PostgresPassword: "secure-password",
//	}
//	installer := bionicgpt.NewBionicGPTInstaller(rc, config)
//	if err := installer.Install(); err != nil {
//	    log.Fatal(err)
//	}
//
// Production Considerations:
//   - Docker Compose for single-node deployment
//   - Minimum 16GB RAM recommended for local LLM
//   - 100GB+ storage for database and documents
//   - Resource limits configured (prevent runaway containers)
//   - Health checks for all services
//
// Code Monkey Cybersecurity - "Cybersecurity. With humans."
package bionicgpt

import (
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

// InstallConfig contains configuration for BionicGPT installation
type InstallConfig struct {
	// Installation paths
	InstallDir  string // Base installation directory (default: /opt/bionicgpt)
	ComposeFile string // Path to docker-compose.yml
	EnvFile     string // Path to .env file

	// PostgreSQL Configuration
	PostgresUser     string // PostgreSQL user (default: postgres)
	PostgresPassword string // PostgreSQL password (retrieved from Vault)
	PostgresDB       string // PostgreSQL database name (default: bionic-gpt)

	// Application Settings
	AppName   string // Display name for the application
	JWTSecret string // JWT secret for authentication (retrieved from Vault)
	LogLevel  string // Log level (default: INFO)
	Timezone  string // Timezone (default: Australia/Perth)

	// Network configuration
	Port int // External port to expose (default: shared.PortBionicGPT = 8513)

	// Azure OpenAI Configuration (via LiteLLM proxy)
	AzureEndpoint             string // Azure OpenAI endpoint URL
	AzureChatDeployment       string // Azure OpenAI chat deployment name (e.g., gpt-4-deployment)
	AzureEmbeddingsDeployment string // Azure OpenAI embeddings deployment name (e.g., embeddings-deployment)
	AzureAPIKey               string // Azure OpenAI API key (retrieved from Vault)
	AzureAPIVersion           string // Azure OpenAI API version (default: 2024-02-15-preview)

	// Local Embeddings Configuration (Ollama)
	UseLocalEmbeddings   bool   // Use local embeddings via Ollama instead of Azure
	LocalEmbeddingsModel string // Local embeddings model name (default: nomic-embed-text)
	OllamaEndpoint       string // Ollama endpoint URL (default: http://localhost:11434)

	// LiteLLM Proxy Configuration
	LiteLLMMasterKey string // LiteLLM proxy master key (retrieved from Vault or generated)
	LiteLLMPort      int    // LiteLLM proxy port (default: 4000)

	// Feature flags
	EnableRAG         bool // Enable Retrieval-Augmented Generation (default: true)
	EnableAuditLog    bool // Enable audit logging (default: true)
	EnableMultiTenant bool // Enable multi-tenant features (default: true)

	// Installation behavior
	ForceReinstall  bool // Force reinstall even if already installed
	SkipHealthCheck bool // Skip health check after installation
}

// BionicGPTInstaller handles BionicGPT installation
type BionicGPTInstaller struct {
	rc     *eos_io.RuntimeContext
	config *InstallConfig
}

// InstallState tracks the state of BionicGPT installation
type InstallState struct {
	Installed         bool
	Running           bool
	ComposeFileExists bool
	EnvFileExists     bool
	VolumesExist      []string // Docker volumes that exist
	ContainerIDs      map[string]string
	HealthStatus      map[string]string
	Version           string
	ExistingPaths     []string
}

// Constants for default values
const (
	// Default installation paths
	DefaultInstallDir = "/opt/bionicgpt"

	// Default PostgreSQL configuration
	DefaultPostgresUser = "postgres"
	DefaultPostgresDB   = "bionic-gpt"

	// Default application settings
	DefaultAppName  = "BionicGPT"
	DefaultLogLevel = "INFO"
	DefaultTimezone = "Australia/Perth"

	// Default port from shared package
	DefaultPort = 8513 // shared.PortBionicGPT

	// Default Azure OpenAI configuration
	DefaultAzureAPIVersion = "2024-02-15-preview"

	// Default LiteLLM configuration
	DefaultLiteLLMPort = 4000

	// Default Ollama configuration
	DefaultOllamaEndpoint       = "http://localhost:11434"
	DefaultOllamaDockerEndpoint = "http://host.docker.internal:11434"
	DefaultLocalEmbeddingsModel = "nomic-embed-text"

	// Default BionicGPT version
	DefaultBionicGPTVersion = "1.11.7"

	// Docker image references
	ImageBionicGPT  = "ghcr.io/bionic-gpt/bionicgpt"
	ImageMigrations = "ghcr.io/bionic-gpt/bionicgpt-db-migrations"
	ImageRAGEngine  = "ghcr.io/bionic-gpt/bionicgpt-rag-engine"
	ImageEmbeddings = "ghcr.io/bionic-gpt/bionicgpt-embeddings-api"
	ImageChunking   = "downloads.unstructured.io/unstructured-io/unstructured-api"
	ImagePostgreSQL = "ankane/pgvector"
	ImageLiteLLM    = "ghcr.io/berriai/litellm"

	// Docker image versions
	VersionEmbeddings = "cpu-0.6"
	VersionChunking   = "4ffd8bc"
	VersionLiteLLM    = "main-latest"

	// Container names
	ContainerApp        = "bionicgpt-app"
	ContainerPostgres   = "bionicgpt-postgres"
	ContainerEmbeddings = "bionicgpt-embeddings"
	ContainerChunking   = "bionicgpt-chunking"
	ContainerMigrations = "bionicgpt-migrations"
	ContainerRAGEngine  = "bionicgpt-rag-engine"
	ContainerLiteLLM    = "bionicgpt-litellm"

	// Docker volume names
	VolumePostgresData = "bionicgpt-postgres-data"
	VolumeDocuments    = "bionicgpt-documents"

	// Vault paths for secrets
	// NOTE: Actual path is secret/data/services/{environment}/bionicgpt (managed by secrets.SecretManager)
	// This constant documents the service name used in GetOrGenerateServiceSecrets()
	VaultServiceName = "bionicgpt" // Service name for Vault secrets (stored at secret/data/services/{env}/bionicgpt)

	// Container names (additional for refresh operations)
	ContainerNameApp        = "bionicgpt-app"
	ContainerNamePostgres   = "bionicgpt-postgres"
	ContainerNameLiteLLMDB  = "bionicgpt-litellm-db"
	ContainerNameLiteLLM    = "bionicgpt-litellm-proxy"
	ContainerNameEmbeddings = "bionicgpt-embeddings"
	ContainerNameChunking   = "bionicgpt-chunking"
	ContainerNameRAGEngine  = "bionicgpt-rag-engine"

	// Database configuration
	PostgresDefaultPort = "5432"
	LiteLLMDefaultUser  = "litellm"
	LiteLLMDefaultDB    = "litellm"
	LiteLLMDefaultPort  = "5433"

	// LiteLLM configuration
	LiteLLMProxyPort        = 4000
	LiteLLMDefaultMasterKey = "sk-" // Must start with sk-

	// Backup configuration
	BackupDirName          = "backups"
	BackupTimestampFormat  = "20060102_150405"
	BackupPrefixRefresh    = "refresh-"
	RollbackScriptName     = "rollback.sh"
	RollbackScriptPerm     = 0755

	// File paths
	DockerComposeFileName = "docker-compose.yml"
	EnvFileName           = ".env"
	LiteLLMConfigFileName = "litellm_config.yaml"
	FixModelsFileName     = "fix-moni-models.sql"

	// SQL table names (LiteLLM)
	LiteLLMVerificationTokenTable = "LiteLLM_VerificationToken"

	// SQL table names (BionicGPT)
	TableModels  = "models"
	TablePrompts = "prompts"
	TableTeams   = "teams"

	// Model configuration
	ModelIDEmbeddings      = 1
	ModelIDLLM             = 2
	ModelNameEmbeddings    = "nomic-embed-text"
	ModelNameMoni          = "moni" // Alias for ModelNameLLM
	ModelNameLLM           = "moni"
	ModelTypeEmbeddings    = "Embeddings"
	ModelTypeLLM           = "LLM"
	ModelBaseLiteLLM       = "http://litellm-proxy:4000"
	ModelContextEmbeddings = 8192
	ModelContextLLM        = 128000
	ModelTPMLimit          = 10000 // Embeddings TPM
	ModelRPMLimit          = 10000 // Embeddings RPM
	ModelLLMTPMLimit       = 30000 // LLM TPM
	ModelLLMRPMLimit       = 500   // LLM RPM

	// Prompt configuration
	PromptVisibility      = "Company"
	PromptName            = "moni"
	PromptMaxHistory      = 3
	PromptMaxChunks       = 10
	PromptMaxTokens       = 4096
	PromptTrimRatio       = 80
	PromptTemperature     = 0.7
	PromptType            = "Model"
	PromptCategoryID      = 1
	PromptDescription     = "Moni - Powered by Azure OpenAI o3-mini"

	// Docker Compose service names
	ServiceApp      = "app"
	ServiceLiteLLM  = "litellm-proxy"
	ServicePostgres = "postgres"
	ServiceLiteLLMDB = "litellm-db"

	// Environment variable names (for validation)
	EnvVarLiteLLMMasterKey = "LITELLM_MASTER_KEY"
	EnvVarOpenAIAPIKey     = "OPENAI_API_KEY"
	EnvVarEmbeddingsAPIKey = "EMBEDDINGS_API_KEY"

	// LiteLLM API endpoints
	LiteLLMHealthEndpoint     = "/health/readiness"
	LiteLLMKeyGenerateEndpoint = "/key/generate"
	LiteLLMKeyDeleteEndpoint   = "/key/delete"
	LiteLLMModelsEndpoint      = "/v1/models"

	// API key configuration
	APIKeyAlias          = "moni-application"
	APIKeyDurationNever  = "" // Empty string means never expire

	// Model names for virtual key generation
	ModelMoni          = "Moni"
	ModelMoni41        = "Moni-4.1"
	ModelMoniO3        = "Moni-o3"
	ModelNomicEmbed    = "nomic-embed-text"

	// Backup configuration for API key rotation
	EnvFileBackupFormat = ".env.backup.20060102_150405"
)

// RotateAPIKeysConfig contains configuration for API key rotation
type RotateAPIKeysConfig struct {
	InstallDir   string // Installation directory (default: /opt/bionicgpt)
	DryRun       bool   // Show what would be done without making changes
	SkipBackup   bool   // Skip .env file backup
	SkipVerify   bool   // Skip verification after rotation
	SkipRestart  bool   // Skip app restart after rotation
}

// LiteLLMKeyGenerateRequest represents the request to generate a new virtual key
type LiteLLMKeyGenerateRequest struct {
	Models   []string          `json:"models"`
	Duration interface{}       `json:"duration"` // null for never expire
	KeyAlias string            `json:"key_alias"`
	Metadata map[string]string `json:"metadata"`
}

// LiteLLMKeyGenerateResponse represents the response from key generation
type LiteLLMKeyGenerateResponse struct {
	Key       string                 `json:"key"`
	KeyName   string                 `json:"key_name,omitempty"`
	KeyAlias  string                 `json:"key_alias,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
	ExpiresAt interface{}            `json:"expires_at,omitempty"`
}

// LiteLLMKeyDeleteRequest represents the request to delete virtual keys
type LiteLLMKeyDeleteRequest struct {
	Keys []string `json:"keys"`
}

// Timeouts and retry configuration (durations, not constants)
var (
	// PostgreSQL readiness timeout
	PostgresReadyTimeout = 60 * time.Second
	PostgresReadyRetry   = 2 * time.Second

	// LiteLLM database readiness timeout
	LiteLLMDBReadyTimeout = 60 * time.Second
	LiteLLMDBReadyRetry   = 2 * time.Second

	// Service stabilization delay after restart
	ServiceStabilizationDelay = 10 * time.Second

	// Initial service startup delay
	ServiceStartupDelay = 15 * time.Second
)
