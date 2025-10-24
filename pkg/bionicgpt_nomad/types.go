// Package bionicgpt_nomad provides enterprise-grade BionicGPT deployment
// using Nomad orchestration, Hecate reverse proxy, and Authentik SSO.
//
// Architecture:
//   - Cloud Node: Hecate (Caddy), Authentik, Consul Server
//   - Local Node: Nomad, Consul Client, BionicGPT stack
//   - VPN: Tailscale connecting cloud ↔ local
//   - Secrets: HashiCorp Vault
//
// Deployment Flow:
//   Phase 0: Check prerequisites (Tailscale, Vault secrets)
//   Phase 3: Preflight checks (Nomad, Consul, Docker, etc.)
//   Phase 4: Configure Authentik (OAuth2 provider, groups, application)
//   Phase 5: Setup Consul (WAN join, service discovery)
//   Phase 6: Deploy to Nomad (BionicGPT, PostgreSQL, LiteLLM, oauth2-proxy)
//   Phase 7: Configure Hecate (Caddy routing to oauth2-proxy)
//   Phase 8: Wait for health checks
//
// Code Monkey Cybersecurity - "Cybersecurity. With humans."
package bionicgpt_nomad

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

// EnterpriseConfig contains configuration for BionicGPT enterprise deployment
type EnterpriseConfig struct {
	// Core deployment settings
	Domain    string // Public domain (e.g., chat.example.com) [REQUIRED]
	CloudNode string // Cloud node hostname for Hecate/Authentik (Tailscale name) [REQUIRED]
	Namespace string // Nomad namespace (default: "default")

	// Authentication settings
	AuthURL         string // Authentik URL (e.g., https://auth.example.com) [REQUIRED]
	SuperadminGroup string // Authentik group for superadmins (default: "bionicgpt-superadmin")
	DemoGroup       string // Authentik group for demo tenant (default: "bionicgpt-demo-tenant")
	GroupPrefix     string // Prefix for BionicGPT groups (default: "bionicgpt-")

	// Azure OpenAI configuration (via LiteLLM proxy)
	AzureEndpoint             string // Azure OpenAI endpoint URL
	AzureChatDeployment       string // Azure OpenAI chat deployment name
	AzureEmbeddingsDeployment string // Azure OpenAI embeddings deployment name (optional if using local)

	// Local embeddings configuration (Ollama)
	UseLocalEmbeddings   bool   // Use local embeddings via Ollama (default: true)
	LocalEmbeddingsModel string // Local embeddings model (default: "nomic-embed-text")

	// Infrastructure settings
	NomadAddress  string // Nomad API address (default: "http://localhost:4646")
	ConsulAddress string // Consul API address (default: "localhost:8500")

	// Deployment options
	DryRun          bool // Show what would be deployed without deploying
	Force           bool // Force deployment even if already exists
	SkipHealthCheck bool // Skip health check after deployment
}

// EnterpriseInstaller handles BionicGPT enterprise installation
type EnterpriseInstaller struct {
	rc     *eos_io.RuntimeContext
	config *EnterpriseConfig
}

// InstallState tracks the state of BionicGPT enterprise installation
type InstallState struct {
	// Prerequisites
	TailscaleInstalled bool
	TailscaleConnected bool
	VaultSecretsExist  bool

	// Infrastructure
	NomadAccessible  bool
	ConsulAccessible bool
	DockerAvailable  bool
	AuthentikReachable bool

	// Authentik configuration
	OAuth2ProviderCreated bool
	OAuth2ProviderPK      int
	OAuth2ClientID        string
	OAuth2ClientSecret    string
	GroupsCreated         bool
	ApplicationCreated    bool

	// Consul configuration
	ConsulWANJoined       bool
	ServicesRegistered    bool

	// Nomad deployment
	JobsDeployed          bool
	AllocationsHealthy    bool

	// Hecate configuration
	CaddyConfigured       bool

	// Overall status
	Healthy               bool
	DeploymentTime        string
}

// PreflightCheck represents a single preflight check
type PreflightCheck struct {
	Name        string
	Description string
	Check       func() error
	Required    bool
	Passed      bool
	Error       error
}

// Constants for default values
const (
	// Default authentication settings
	DefaultSuperadminGroup = "bionicgpt-superadmin"
	DefaultDemoGroup       = "bionicgpt-demo-tenant"
	DefaultGroupPrefix     = "bionicgpt-"

	// Default infrastructure settings
	// NOTE: For runtime addresses, use shared.GetConsulHTTPAddr() instead
	// These constants are only for documentation/examples
	DefaultNomadAddress  = "http://localhost:4646"
	DefaultConsulAddress = "localhost:8500" // Use shared.GetConsulHTTPAddr() at runtime
	DefaultNamespace     = "default"

	// Default Ollama settings
	DefaultLocalEmbeddingsModel = "nomic-embed-text"

	// Vault paths for secrets (consistent with existing bionicgpt package)
	VaultServiceName = "bionicgpt" // Service name for Vault secrets

	// Nomad job names
	JobBionicGPT  = "bionicgpt"
	JobPostgreSQL = "bionicgpt-postgres"
	JobLiteLLM    = "bionicgpt-litellm"
	JobOllama     = "bionicgpt-ollama"

	// Service names in Consul
	ServiceBionicGPT   = "bionicgpt"
	ServiceOAuth2Proxy = "bionicgpt-oauth2-proxy"
	ServicePostgreSQL  = "bionicgpt-postgres"
	ServiceLiteLLM     = "bionicgpt-litellm"
	ServiceOllama      = "bionicgpt-ollama"
)

// NewDefaultConfig returns an EnterpriseConfig with sensible defaults
func NewDefaultConfig() *EnterpriseConfig {
	return &EnterpriseConfig{
		Namespace:            DefaultNamespace,
		SuperadminGroup:      DefaultSuperadminGroup,
		DemoGroup:            DefaultDemoGroup,
		GroupPrefix:          DefaultGroupPrefix,
		UseLocalEmbeddings:   true,
		LocalEmbeddingsModel: DefaultLocalEmbeddingsModel,
		NomadAddress:         DefaultNomadAddress,
		ConsulAddress:        DefaultConsulAddress,
		DryRun:               false,
		Force:                false,
		SkipHealthCheck:      false,
	}
}
