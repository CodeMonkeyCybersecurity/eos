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

import "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"

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
	AppName      string // Display name for the application
	JWTSecret    string // JWT secret for authentication (retrieved from Vault)
	LogLevel     string // Log level (default: INFO)
	Timezone     string // Timezone (default: Australia/Perth)

	// Network configuration
	Port int // External port to expose (default: shared.PortBionicGPT = 8513)

	// Azure OpenAI Configuration (via LiteLLM proxy)
	AzureEndpoint           string // Azure OpenAI endpoint URL
	AzureChatDeployment     string // Azure OpenAI chat deployment name (e.g., gpt-4-deployment)
	AzureEmbeddingsDeployment string // Azure OpenAI embeddings deployment name (e.g., embeddings-deployment)
	AzureAPIKey             string // Azure OpenAI API key (retrieved from Vault)
	AzureAPIVersion         string // Azure OpenAI API version (default: 2024-02-15-preview)

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

	// Default BionicGPT version
	DefaultBionicGPTVersion = "1.11.7"

	// Docker image references
	ImageBionicGPT       = "ghcr.io/bionic-gpt/bionicgpt"
	ImageMigrations      = "ghcr.io/bionic-gpt/bionicgpt-db-migrations"
	ImageRAGEngine       = "ghcr.io/bionic-gpt/bionicgpt-rag-engine"
	ImageEmbeddings      = "ghcr.io/bionic-gpt/bionicgpt-embeddings-api"
	ImageChunking        = "downloads.unstructured.io/unstructured-io/unstructured-api"
	ImagePostgreSQL      = "ankane/pgvector"
	ImageLiteLLM         = "ghcr.io/berriai/litellm"

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
	VaultPathBionicGPT = "secret/bionicgpt" // Base path in Vault for BionicGPT secrets
)
