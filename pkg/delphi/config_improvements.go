// pkg/delphi/config/typed_config.go
package delphi

import (
    "fmt"
    "os"
    "strconv"
    "time"
    
    "github.com/go-playground/validator/v10"
    "go.uber.org/zap"
)

// DelphiConfig represents the complete Delphi configuration with validation
type DelphiConfig struct {
    // Database Configuration
    Database DatabaseConfig `validate:"required"`
    
    // Queue Configuration  
    Queue QueueConfig `validate:"required"`
    
    // Wazuh Integration
    Wazuh WazuhConfig `validate:"required"`
    
    // LLM Configuration
    LLM LLMConfig `validate:"required"`
    
    // Email Configuration
    Email EmailConfig `validate:"required"`
    
    // Service Configuration
    Services ServicesConfig `validate:"required"`
    
    // Monitoring Configuration
    Monitoring MonitoringConfig `validate:"required"`
}

type DatabaseConfig struct {
    Host         string `validate:"required,hostname_rfc1123" env:"DELPHI_DB_HOST"`
    Port         int    `validate:"required,min=1,max=65535" env:"DELPHI_DB_PORT"`
    Database     string `validate:"required,min=1" env:"DELPHI_DB_NAME"`
    Username     string `validate:"required,min=1" env:"DELPHI_DB_USER"`
    Password     string `validate:"required,min=8" env:"DELPHI_DB_PASSWORD"`
    SSLMode      string `validate:"oneof=disable require verify-ca verify-full" env:"DELPHI_DB_SSLMODE"`
    MaxConns     int    `validate:"min=1,max=100" env:"DELPHI_DB_MAX_CONNS"`
    MaxIdleConns int    `validate:"min=1,max=50" env:"DELPHI_DB_MAX_IDLE_CONNS"`
    ConnTimeout  time.Duration `validate:"min=1s,max=30s" env:"DELPHI_DB_CONN_TIMEOUT"`
}

type QueueConfig struct {
    Type     string `validate:"oneof=redis postgresql" env:"DELPHI_QUEUE_TYPE"`
    Host     string `validate:"required,hostname_rfc1123" env:"DELPHI_QUEUE_HOST"`
    Port     int    `validate:"required,min=1,max=65535" env:"DELPHI_QUEUE_PORT"`
    Password string `env:"DELPHI_QUEUE_PASSWORD"`
    Database int    `validate:"min=0,max=15" env:"DELPHI_QUEUE_DB"`
    
    // Stream Configuration
    StreamName    string        `validate:"required,min=1" env:"DELPHI_STREAM_NAME"`
    ConsumerGroup string        `validate:"required,min=1" env:"DELPHI_CONSUMER_GROUP"`
    BatchSize     int           `validate:"min=1,max=1000" env:"DELPHI_BATCH_SIZE"`
    ReadTimeout   time.Duration `validate:"min=1s,max=60s" env:"DELPHI_READ_TIMEOUT"`
}

type WazuhConfig struct {
    BaseURL      string        `validate:"required,url" env:"WAZUH_API_URL"`
    Username     string        `validate:"required,min=1" env:"WAZUH_API_USER"`
    Password     string        `validate:"required,min=8" env:"WAZUH_API_PASSWORD"`
    Timeout      time.Duration `validate:"min=5s,max=60s" env:"WAZUH_API_TIMEOUT"`
    RetryCount   int           `validate:"min=1,max=10" env:"WAZUH_API_RETRY_COUNT"`
    RetryBackoff time.Duration `validate:"min=1s,max=30s" env:"WAZUH_API_RETRY_BACKOFF"`
    
    // JWT Token Management
    TokenRefreshBuffer time.Duration `validate:"min=1m,max=30m" env:"WAZUH_TOKEN_REFRESH_BUFFER"`
}

type LLMConfig struct {
    Provider    string `validate:"oneof=openai anthropic azure" env:"LLM_PROVIDER"`
    Model       string `validate:"required,min=1" env:"LLM_MODEL"`
    APIKey      string `validate:"required,min=1" env:"LLM_API_KEY"`
    BaseURL     string `validate:"omitempty,url" env:"LLM_BASE_URL"`
    MaxTokens   int    `validate:"min=100,max=4096" env:"LLM_MAX_TOKENS"`
    Temperature float32 `validate:"min=0,max=2" env:"LLM_TEMPERATURE"`
    
    // Rate Limiting
    RequestsPerMinute int `validate:"min=1,max=1000" env:"LLM_REQUESTS_PER_MINUTE"`
    RequestsPerHour   int `validate:"min=1,max=10000" env:"LLM_REQUESTS_PER_HOUR"`
    
    // Circuit Breaker
    MaxFailures  int           `validate:"min=1,max=100" env:"LLM_MAX_FAILURES"`
    ResetTimeout time.Duration `validate:"min=1m,max=60m" env:"LLM_RESET_TIMEOUT"`
}

type EmailConfig struct {
    SMTPHost     string `validate:"required,hostname_rfc1123" env:"SMTP_HOST"`
    SMTPPort     int    `validate:"required,min=1,max=65535" env:"SMTP_PORT"`
    SMTPUsername string `validate:"required,email" env:"SMTP_USERNAME"`
    SMTPPassword string `validate:"required,min=1" env:"SMTP_PASSWORD"`
    SMTPTLSMode  string `validate:"oneof=none starttls tls" env:"SMTP_TLS_MODE"`
    
    // Rate Limiting
    MaxEmailsPerMinute int `validate:"min=1,max=100" env:"EMAIL_MAX_PER_MINUTE"`
    MaxEmailsPerHour   int `validate:"min=1,max=1000" env:"EMAIL_MAX_PER_HOUR"`
    
    // Retry Configuration
    MaxRetries   int           `validate:"min=1,max=10" env:"EMAIL_MAX_RETRIES"`
    RetryBackoff time.Duration `validate:"min=30s,max=1h" env:"EMAIL_RETRY_BACKOFF"`
    
    // Email Formatting
    DefaultSender    string `validate:"required,email" env:"EMAIL_DEFAULT_SENDER"`
    DefaultRecipient string `validate:"required,email" env:"EMAIL_DEFAULT_RECIPIENT"`
    SubjectPrefix    string `validate:"max=50" env:"EMAIL_SUBJECT_PREFIX"`
}

type ServicesConfig struct {
    WorkerCount        int           `validate:"min=1,max=20" env:"DELPHI_WORKER_COUNT"`
    HealthCheckPort    int           `validate:"min=1024,max=65535" env:"DELPHI_HEALTH_PORT"`
    MetricsPort        int           `validate:"min=1024,max=65535" env:"DELPHI_METRICS_PORT"`
    GracefulShutdown   time.Duration `validate:"min=5s,max=60s" env:"DELPHI_GRACEFUL_SHUTDOWN"`
    ProcessingTimeout  time.Duration `validate:"min=30s,max=10m" env:"DELPHI_PROCESSING_TIMEOUT"`
    
    // Resource Limits
    MaxMemoryMB int `validate:"min=128,max=4096" env:"DELPHI_MAX_MEMORY_MB"`
    MaxCPUPercent int `validate:"min=10,max=100" env:"DELPHI_MAX_CPU_PERCENT"`
}

type MonitoringConfig struct {
    EnableMetrics    bool   `env:"DELPHI_ENABLE_METRICS"`
    MetricsEndpoint  string `validate:"omitempty,uri" env:"DELPHI_METRICS_ENDPOINT"`
    LogLevel         string `validate:"oneof=debug info warn error" env:"DELPHI_LOG_LEVEL"`
    LogFormat        string `validate:"oneof=json text" env:"DELPHI_LOG_FORMAT"`
    
    // Alerting
    AlertWebhookURL  string        `validate:"omitempty,url" env:"DELPHI_ALERT_WEBHOOK"`
    AlertThreshold   int           `validate:"min=1,max=100" env:"DELPHI_ALERT_THRESHOLD"`
    AlertCooldown    time.Duration `validate:"min=1m,max=24h" env:"DELPHI_ALERT_COOLDOWN"`
}

// ConfigLoader handles loading and validating configuration
type ConfigLoader struct {
    validator *validator.Validate
    logger    *zap.Logger
}

func NewConfigLoader(logger *zap.Logger) *ConfigLoader {
    v := validator.New()
    
    // Register custom validators
    if err := v.RegisterValidation("hostname_rfc1123", validateHostname); err != nil {
        logger.Error("Failed to register hostname validator", zap.Error(err))
    }
    
    return &ConfigLoader{
        validator: v,
        logger:    logger,
    }
}

func (cl *ConfigLoader) Load() (*DelphiConfig, error) {
    config := &DelphiConfig{}
    
    // Load from environment variables
    if err := cl.loadFromEnv(config); err != nil {
        return nil, fmt.Errorf("failed to load configuration from environment: %w", err)
    }
    
    // Set defaults
    cl.setDefaults(config)
    
    // Validate configuration
    if err := cl.validator.Struct(config); err != nil {
        return nil, fmt.Errorf("configuration validation failed: %w", err)
    }
    
    cl.logger.Info("Configuration loaded successfully",
        zap.String("queue_type", config.Queue.Type),
        zap.String("llm_provider", config.LLM.Provider),
        zap.String("log_level", config.Monitoring.LogLevel))
    
    return config, nil
}

func (cl *ConfigLoader) loadFromEnv(config *DelphiConfig) error {
    // Database
    config.Database.Host = getEnvOrDefault("DELPHI_DB_HOST", "localhost")
    config.Database.Port = getEnvIntOrDefault("DELPHI_DB_PORT", 5432)
    config.Database.Database = os.Getenv("DELPHI_DB_NAME")
    config.Database.Username = os.Getenv("DELPHI_DB_USER")
    config.Database.Password = os.Getenv("DELPHI_DB_PASSWORD")
    config.Database.SSLMode = getEnvOrDefault("DELPHI_DB_SSLMODE", "require")
    config.Database.MaxConns = getEnvIntOrDefault("DELPHI_DB_MAX_CONNS", 25)
    config.Database.MaxIdleConns = getEnvIntOrDefault("DELPHI_DB_MAX_IDLE_CONNS", 5)
    config.Database.ConnTimeout = getEnvDurationOrDefault("DELPHI_DB_CONN_TIMEOUT", 10*time.Second)
    
    // Queue
    config.Queue.Type = getEnvOrDefault("DELPHI_QUEUE_TYPE", "redis")
    config.Queue.Host = getEnvOrDefault("DELPHI_QUEUE_HOST", "localhost")
    config.Queue.Port = getEnvIntOrDefault("DELPHI_QUEUE_PORT", 6379)
    config.Queue.Password = os.Getenv("DELPHI_QUEUE_PASSWORD")
    config.Queue.Database = getEnvIntOrDefault("DELPHI_QUEUE_DB", 0)
    config.Queue.StreamName = getEnvOrDefault("DELPHI_STREAM_NAME", "delphi:alerts")
    config.Queue.ConsumerGroup = getEnvOrDefault("DELPHI_CONSUMER_GROUP", "delphi-workers")
    config.Queue.BatchSize = getEnvIntOrDefault("DELPHI_BATCH_SIZE", 10)
    config.Queue.ReadTimeout = getEnvDurationOrDefault("DELPHI_READ_TIMEOUT", 5*time.Second)
    
    // Continue for other configuration sections...
    
    return nil
}

func (cl *ConfigLoader) setDefaults(config *DelphiConfig) {
    // Set intelligent defaults based on environment
    if config.Services.WorkerCount == 0 {
        config.Services.WorkerCount = 4
    }
    
    if config.LLM.Temperature == 0 {
        config.LLM.Temperature = 0.3
    }
    
    if config.Monitoring.LogLevel == "" {
        config.Monitoring.LogLevel = "info"
    }
}

// Helper functions
func getEnvOrDefault(key, defaultVal string) string {
    if val := os.Getenv(key); val != "" {
        return val
    }
    return defaultVal
}

func getEnvIntOrDefault(key string, defaultVal int) int {
    if val := os.Getenv(key); val != "" {
        if intVal, err := strconv.Atoi(val); err == nil {
            return intVal
        }
    }
    return defaultVal
}

func getEnvDurationOrDefault(key string, defaultVal time.Duration) time.Duration {
    if val := os.Getenv(key); val != "" {
        if duration, err := time.ParseDuration(val); err == nil {
            return duration
        }
    }
    return defaultVal
}

func validateHostname(fl validator.FieldLevel) bool {
    // Simple hostname validation - could be more sophisticated
    hostname := fl.Field().String()
    return len(hostname) > 0 && len(hostname) <= 253
}