package moni

import "time"

// WorkerConfig contains configuration for the Moni worker
type WorkerConfig struct {
	// Phase control
	SkipSSL          bool
	SkipDatabase     bool
	SkipSecurity     bool
	SkipVerification bool

	// Validation only
	ValidateCertsOnly bool
	FixCertsOnly      bool
	VerifyDBOnly      bool
	VerifyRLSOnly     bool
	VerifyCSPOnly     bool
	VerifySecurityOnly bool

	// Cleanup
	CleanupBackups bool

	// Paths (overridable for testing)
	WorkDir string
}

// PostgresImage represents a detected PostgreSQL container image
type PostgresImage struct {
	Service     string
	Image       string
	ExpectedUID int
	ActualUID   int // 0 if not detected
}

// SetupPhase represents a phase of the setup process
type SetupPhase struct {
	Number      int
	Name        string
	Description string
	StartTime   time.Time
	EndTime     time.Time
	Success     bool
	Errors      []string
	Warnings    []string
}

// HealthCheckResult contains results from health checks
type HealthCheckResult struct {
	PostgresSSL      bool
	LiteLLMModels    int
	WebSearchEnabled bool
	SystemPromptSet  bool
	ContainerHealth  map[string]bool
	Errors           []string
	Warnings         []string
}

// RLSVerificationResult contains RLS verification results
type RLSVerificationResult struct {
	RLSEnabled               bool
	TablesWithRLS            []string
	TablesWithoutRLS         []string
	PoliciesFound            []RLSPolicy
	CriticalTablesProtected  bool
	Warnings                 []string
	Errors                   []string
}

// RLSPolicy represents a Row Level Security policy
type RLSPolicy struct {
	Table      string
	PolicyName string
	Command    string
}

// CSPVerificationResult contains CSP verification results
type CSPVerificationResult struct {
	CSPPresent        bool
	CSPHeader         string
	SecurityScore     int
	GoodDirectives    []string
	WeakDirectives    []string
	MissingDirectives []string
	Warnings          []string
	Errors            []string
}

// DBVerificationResult contains database verification results
type DBVerificationResult struct {
	ModelCount  int
	MoniExists  bool
	Models      []DBModel
	Prompts     []DBPrompt
	Errors      []string
	Warnings    []string
}

// DBModel represents a database model record
type DBModel struct {
	ID          int
	ModelType   string
	Name        string
	BaseURL     string
	ContextSize int
	TPMLimit    int
	RPMLimit    int
}

// DBPrompt represents a database prompt record
type DBPrompt struct {
	ID          int
	Name        string
	ModelID     int
	ModelName   string
	Description string
}

// EnvCheckResult contains .env file validation results
type EnvCheckResult struct {
	Exists    bool
	Variables map[string]interface{}
	Warnings  []string
	Errors    []string
}

// SetupResult contains the overall setup result
type SetupResult struct {
	Success           bool
	Phases            []SetupPhase
	HealthCheck       *HealthCheckResult
	RLSVerification   *RLSVerificationResult
	CSPVerification   *CSPVerificationResult
	DBVerification    *DBVerificationResult
	StartTime         time.Time
	EndTime           time.Time
	CriticalIssues    []string
}
