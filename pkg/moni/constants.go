package moni

import "time"

// Container names
const (
	PostgresContainer   = "bionicgpt-postgres"
	LiteLLMContainer    = "bionicgpt-litellm"
	LiteLLMDBContainer  = "bionicgpt-litellm-db"
	LangfuseDBContainer = "bionicgpt-langfuse-db"
	AppContainer        = "bionicgpt-app"
)

// Service URLs
const (
	LiteLLMURL = "http://localhost:4000"
	AppURL     = "http://localhost:8513"
)

// Database configuration
const (
	DBName = "bionic-gpt"
	DBUser = "postgres"
)

// Paths
const (
	MoniDir              = "/opt/moni"
	MoniEnvFile          = "/opt/moni/.env"
	MoniAPIKeysScript    = "/opt/moni/api_keys.sh"
	MoniCertsDir         = "/opt/moni/certs"
	MoniCertsAlpineDir   = "/opt/moni/certs-alpine"
	MoniCertsStandardDir = "/opt/moni/certs-standard"
	MoniDockerCompose    = "/opt/moni/docker-compose.yml"
)

// Timeouts and intervals
const (
	MaxWaitSeconds     = 120
	CheckIntervalSecs  = 2
	InitWaitSeconds    = 30
	CommandTimeout     = 30 * time.Second
	LongCommandTimeout = 5 * time.Minute
)

// Backup settings
const (
	KeepBackups = 3
)

// SSL Certificate ownership (Alpine PostgreSQL containers)
const (
	CertOwnerUID = 0  // root
	CertOwnerGID = 70 // postgres group in Alpine
	CertKeyPerms = 0640
	CertCrtPerms = 0644
	StandardUID  = 999 // Standard PostgreSQL UID
	TempKeyPerms = 0600
)

// Certificate strategies
const (
	StrategySingleSSLCert = "single-ssl-cert"
	StrategySingleUID70   = "single-uid-70"
	StrategySeparateCerts = "separate-certs"
)

// Model configuration
// CRITICAL: Context size set to 16384 (not 1M) to match Azure GPT-4o-mini
// max completion tokens. This prevents API errors when BionicGPT reads this
// value and sends it as max_tokens in requests.
const (
	ModelContextSize      = 16384
	EmbeddingsContextSize = 8192
	ModelTPMLimit         = 50000
	ModelRPMLimit         = 1000
	ModelFallbackTPMLimit = 30000
	ModelFallbackRPMLimit = 500
	EmbeddingsTPMLimit    = 10000
	EmbeddingsRPMLimit    = 10000
)

// RLS table counts
const (
	ExpectedRLSTables = 15
)
