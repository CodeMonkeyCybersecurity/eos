package delphi_config

import (
	"time"
)

// ValidationResult represents the result of a single validation check
type ValidationResult struct {
	Level   string `json:"level"`   // error, warning, info
	Source  string `json:"source"`  // validation source (database, env, files, etc.)
	Message string `json:"message"` // human-readable message
}

// ValidationSummary contains the complete validation results
type ValidationSummary struct {
	Success   bool               `json:"success"`
	Timestamp time.Time          `json:"timestamp"`
	Errors    []ValidationResult `json:"errors"`
	Warnings  []ValidationResult `json:"warnings"`
	Info      []ValidationResult `json:"info"`
}

// DatabaseConfig represents database validation configuration
type DatabaseConfig struct {
	DSN               string              `json:"dsn" mapstructure:"dsn"`
	RequiredTables    []string            `json:"required_tables" mapstructure:"required_tables"`
	RequiredColumns   map[string][]string `json:"required_columns" mapstructure:"required_columns"`
	RequiredEnums     map[string][]string `json:"required_enums" mapstructure:"required_enums"`
	RequiredFunctions []string            `json:"required_functions" mapstructure:"required_functions"`
	OptionalTables    []string            `json:"optional_tables" mapstructure:"optional_tables"`
}

// LLMConfig represents LLM provider configuration
type LLMConfig struct {
	Provider       string            `json:"provider" mapstructure:"provider"` // openai, azure
	APIKey         string            `json:"-"`                                // sensitive, not serialized
	EndpointURL    string            `json:"endpoint_url,omitempty" mapstructure:"endpoint_url"`
	DeploymentName string            `json:"deployment_name,omitempty" mapstructure:"deployment_name"`
	Model          string            `json:"model,omitempty" mapstructure:"model"`
	MaxTokens      int               `json:"max_tokens,omitempty" mapstructure:"max_tokens"`
	Temperature    float64           `json:"temperature,omitempty" mapstructure:"temperature"`
	Timeout        time.Duration     `json:"timeout,omitempty" mapstructure:"timeout"`
	Headers        map[string]string `json:"headers,omitempty" mapstructure:"headers"`
}

// SMTPConfig represents email configuration
type SMTPConfig struct {
	Host      string            `json:"host" mapstructure:"host"`
	Port      int               `json:"port" mapstructure:"port"`
	Username  string            `json:"username" mapstructure:"username"`
	Password  string            `json:"-"` // sensitive, not serialized
	FromEmail string            `json:"from_email" mapstructure:"from_email"`
	FromName  string            `json:"from_name,omitempty" mapstructure:"from_name"`
	TLS       bool              `json:"tls" mapstructure:"tls"`
	StartTLS  bool              `json:"starttls" mapstructure:"starttls"`
	Headers   map[string]string `json:"headers,omitempty" mapstructure:"headers"`
}

// ParserConfig represents parser-specific settings
type ParserConfig struct {
	FailureThreshold      int           `json:"failure_threshold" mapstructure:"failure_threshold"`
	FailureTimeout        time.Duration `json:"failure_timeout" mapstructure:"failure_timeout"`
	ABTestPercentage      int           `json:"ab_test_percentage" mapstructure:"ab_test_percentage"`
	CircuitBreakerEnabled bool          `json:"circuit_breaker_enabled" mapstructure:"circuit_breaker_enabled"`
	MaxRetries            int           `json:"max_retries" mapstructure:"max_retries"`
	RetryDelay            time.Duration `json:"retry_delay" mapstructure:"retry_delay"`
}

// SecurityConfig represents security-related settings
type SecurityConfig struct {
	WebhookAuthToken   string   `json:"-"` // sensitive, not serialized
	AllowedOrigins     []string `json:"allowed_origins,omitempty" mapstructure:"allowed_origins"`
	RateLimitEnabled   bool     `json:"rate_limit_enabled" mapstructure:"rate_limit_enabled"`
	RateLimitPerMinute int      `json:"rate_limit_per_minute" mapstructure:"rate_limit_per_minute"`
	RequireHTTPS       bool     `json:"require_https" mapstructure:"require_https"`
}

// WazuhConfig represents Wazuh API configuration
type WazuhConfig struct {
	APIURL      string        `json:"api_url" mapstructure:"api_url"`
	APIUser     string        `json:"api_user" mapstructure:"api_user"`
	APIPassword string        `json:"-"` // sensitive, not serialized
	VerifySSL   bool          `json:"verify_ssl" mapstructure:"verify_ssl"`
	Timeout     time.Duration `json:"timeout" mapstructure:"timeout"`
}

// FilePathsConfig represents file and directory paths
type FilePathsConfig struct {
	LogDirectory      string `json:"log_directory" mapstructure:"log_directory"`
	PromptFile        string `json:"prompt_file" mapstructure:"prompt_file"`
	PromptDirectory   string `json:"prompt_directory" mapstructure:"prompt_directory"`
	EmailTemplatePath string `json:"email_template_path" mapstructure:"email_template_path"`
	DataDirectory     string `json:"data_directory,omitempty" mapstructure:"data_directory"`
	BackupDirectory   string `json:"backup_directory,omitempty" mapstructure:"backup_directory"`
}

// NotificationChannelsConfig represents PostgreSQL notification channels
type NotificationChannelsConfig struct {
	Channels          map[string]string `json:"channels" mapstructure:"channels"`
	RequiredFunctions []string          `json:"required_functions" mapstructure:"required_functions"`
	RequiredTriggers  []string          `json:"required_triggers" mapstructure:"required_triggers"`
}

// DelphiConfig represents the complete Delphi pipeline configuration
type DelphiConfig struct {
	Database             DatabaseConfig             `json:"database" mapstructure:"database"`
	LLM                  LLMConfig                  `json:"llm" mapstructure:"llm"`
	SMTP                 SMTPConfig                 `json:"smtp" mapstructure:"smtp"`
	Parser               ParserConfig               `json:"parser" mapstructure:"parser"`
	Security             SecurityConfig             `json:"security" mapstructure:"security"`
	Wazuh                WazuhConfig                `json:"wazuh" mapstructure:"wazuh"`
	FilePaths            FilePathsConfig            `json:"file_paths" mapstructure:"file_paths"`
	NotificationChannels NotificationChannelsConfig `json:"notification_channels" mapstructure:"notification_channels"`
}

// DefaultDelphiConfig returns a configuration with sensible defaults
func DefaultDelphiConfig() *DelphiConfig {
	return &DelphiConfig{
		Database: DatabaseConfig{
			RequiredTables: []string{"alerts", "parser_metrics"},
			RequiredColumns: map[string][]string{
				"alerts": {
					"agent_enriched_at", "structured_at", "formatted_at",
					"prompt_type", "parser_used", "parser_success",
				},
			},
			RequiredEnums: map[string][]string{
				"alert_state": {
					"new", "agent_enriched", "summarized",
					"structured", "formatted", "sent",
				},
			},
			RequiredFunctions: []string{
				"trg_alert_new_notify",
				"trg_alert_agent_enriched_notify",
				"trg_alert_response_notify",
				"trg_alert_structured_notify",
				"trg_alert_formatted_notify",
			},
		},
		Parser: ParserConfig{
			FailureThreshold:      5,
			FailureTimeout:        5 * time.Minute,
			ABTestPercentage:      0,
			CircuitBreakerEnabled: true,
			MaxRetries:            3,
			RetryDelay:            30 * time.Second,
		},
		Security: SecurityConfig{
			RateLimitEnabled:   true,
			RateLimitPerMinute: 60,
			RequireHTTPS:       true,
		},
		FilePaths: FilePathsConfig{
			LogDirectory:      "/var/log/stackstorm",
			PromptFile:        "/srv/eos/system-prompts/default.txt",
			PromptDirectory:   "/srv/eos/system-prompts/",
			EmailTemplatePath: "/opt/stackstorm/packs/delphi/email.html",
		},
		NotificationChannels: NotificationChannelsConfig{
			Channels: map[string]string{
				"new_alert":        "delphi-listener → delphi-agent-enricher",
				"agent_enriched":   "delphi-agent-enricher → llm-worker",
				"new_response":     "llm-worker → email-structurer",
				"alert_structured": "email-structurer → email-formatter",
				"alert_formatted":  "email-formatter → email-sender",
				"alert_sent":       "email-sender → final (archive/metrics)",
			},
		},
		Wazuh: WazuhConfig{
			VerifySSL: true,
			Timeout:   30 * time.Second,
		},
		LLM: LLMConfig{
			MaxTokens:   4000,
			Temperature: 0.7,
			Timeout:     30 * time.Second,
		},
		SMTP: SMTPConfig{
			Port:     587,
			TLS:      true,
			StartTLS: true,
		},
	}
}

// Validator interface for configuration validation
type Validator interface {
	Validate() []ValidationResult
	Name() string
}
