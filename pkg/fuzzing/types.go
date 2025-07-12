package fuzzing

import (
	"context"
	"time"
)

// Config represents the configuration for fuzzing operations
type Config struct {
	// Test execution settings
	Duration      time.Duration `json:"duration"`
	ParallelJobs  int           `json:"parallel_jobs"`
	Verbose       bool          `json:"verbose"`
	
	// Test category settings
	SecurityFocus       bool `json:"security_focus"`
	ArchitectureTesting bool `json:"architecture_testing"`
	
	// Output settings
	LogDir        string `json:"log_dir"`
	ReportFormat  string `json:"report_format"`
	
	// CI/CD specific settings
	CIMode          bool   `json:"ci_mode"`
	CIProfile       string `json:"ci_profile"`
	FailFast        bool   `json:"fail_fast"`
	
	// Overnight testing settings
	LongDuration   time.Duration `json:"long_duration"`
	MediumDuration time.Duration `json:"medium_duration"`
	ShortDuration  time.Duration `json:"short_duration"`
}

// TestResult represents the result of a fuzz test execution
type TestResult struct {
	TestName     string        `json:"test_name"`
	Package      string        `json:"package"`
	Duration     time.Duration `json:"duration"`
	Executions   int64         `json:"executions"`
	ExecRate     float64       `json:"exec_rate"`
	NewInputs    int           `json:"new_inputs"`
	Success      bool          `json:"success"`
	ErrorMessage string        `json:"error_message,omitempty"`
	CrashData    *CrashData    `json:"crash_data,omitempty"`
}

// CrashData represents information about a crash found during fuzzing
type CrashData struct {
	Input       string `json:"input"`
	StackTrace  string `json:"stack_trace"`
	PanicReason string `json:"panic_reason"`
	Severity    string `json:"severity"`
}

// TestCategory represents different categories of fuzz tests
type TestCategory struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Packages    []string `json:"packages"`
	Priority    int      `json:"priority"`
	Duration    time.Duration `json:"duration"`
}

// FuzzSession represents a complete fuzzing session
type FuzzSession struct {
	ID            string         `json:"id"`
	StartTime     time.Time      `json:"start_time"`
	EndTime       time.Time      `json:"end_time"`
	Config        Config         `json:"config"`
	Results       []TestResult   `json:"results"`
	Summary       SessionSummary `json:"summary"`
	LogDir        string         `json:"log_dir"`
}

// SessionSummary provides summary statistics for a fuzzing session
type SessionSummary struct {
	TotalTests      int           `json:"total_tests"`
	PassedTests     int           `json:"passed_tests"`
	FailedTests     int           `json:"failed_tests"`
	CrashesFound    int           `json:"crashes_found"`
	TotalExecutions int64         `json:"total_executions"`
	TotalDuration   time.Duration `json:"total_duration"`
	SuccessRate     float64       `json:"success_rate"`
	SecurityAlert   bool          `json:"security_alert"`
}

// TestDiscovery represents discovered fuzz tests
type TestDiscovery struct {
	SecurityCritical []FuzzTest `json:"security_critical"`
	Architecture     []FuzzTest `json:"architecture"`
	Component        []FuzzTest `json:"component"`
}

// FuzzTest represents a single fuzz test
type FuzzTest struct {
	Name        string `json:"name"`
	Package     string `json:"package"`
	Function    string `json:"function"`
	Category    string `json:"category"`
	Priority    int    `json:"priority"`
	Description string `json:"description"`
}

// FuzzRunner defines the interface for different fuzzing execution strategies
type FuzzRunner interface {
	DiscoverTests(ctx context.Context) (*TestDiscovery, error)
	RunTest(ctx context.Context, test FuzzTest, config Config) (*TestResult, error)
	RunSession(ctx context.Context, config Config) (*FuzzSession, error)
	GenerateReport(session *FuzzSession) (string, error)
}

// ProfileConfig defines predefined fuzzing profiles
type ProfileConfig struct {
	Quick     Config `json:"quick"`
	Security  Config `json:"security"`
	Overnight Config `json:"overnight"`
	CI        Config `json:"ci"`
}

// DefaultProfiles returns the default fuzzing profiles
func DefaultProfiles() ProfileConfig {
	return ProfileConfig{
		Quick: Config{
			Duration:     30 * time.Second,
			ParallelJobs: 4,
			SecurityFocus: true,
			ArchitectureTesting: false,
			Verbose: false,
			CIMode: false,
			FailFast: true,
		},
		Security: Config{
			Duration:     5 * time.Minute,
			ParallelJobs: 4,
			SecurityFocus: true,
			ArchitectureTesting: false,
			Verbose: true,
			CIMode: false,
			FailFast: false,
		},
		Overnight: Config{
			Duration:       30 * time.Minute,
			LongDuration:   8 * time.Hour,
			MediumDuration: 2 * time.Hour,
			ShortDuration:  30 * time.Minute,
			ParallelJobs:   4,
			SecurityFocus: true,
			ArchitectureTesting: true,
			Verbose: true,
			CIMode: false,
			FailFast: false,
		},
		CI: Config{
			Duration:     60 * time.Second,
			ParallelJobs: 4,
			SecurityFocus: true,
			ArchitectureTesting: false,
			Verbose: false,
			CIMode: true,
			FailFast: true,
		},
	}
}

// Constants for test categories
const (
	CategorySecurityCritical = "security-critical"
	CategoryArchitecture     = "architecture"
	CategoryComponent        = "component"
)

// Constants for CI profiles
const (
	CIProfilePRValidation   = "pr-validation"
	CIProfileSecurityFocus  = "security-focused"
	CIProfileArchitecture   = "architecture"
	CIProfileFull          = "full"
)

// Constants for report formats
const (
	ReportFormatMarkdown = "markdown"
	ReportFormatJSON     = "json"
	ReportFormatText     = "text"
)