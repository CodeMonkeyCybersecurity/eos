package httpclient

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"
)

// Config represents HTTP client configuration options
type Config struct {
	// Basic configuration
	Timeout   time.Duration     `json:"timeout" yaml:"timeout"`
	UserAgent string            `json:"user_agent" yaml:"user_agent"`
	Headers   map[string]string `json:"headers" yaml:"headers"`

	// Retry configuration
	RetryConfig *RetryConfig `json:"retry" yaml:"retry"`

	// TLS configuration
	TLSConfig *TLSConfig `json:"tls" yaml:"tls"`

	// Authentication configuration
	AuthConfig *AuthConfig `json:"auth" yaml:"auth"`

	// Rate limiting configuration
	RateLimitConfig *RateLimitConfig `json:"rate_limit" yaml:"rate_limit"`

	// Connection pool configuration
	PoolConfig *PoolConfig `json:"pool" yaml:"pool"`

	// Observability configuration
	LogConfig *LogConfig `json:"log" yaml:"log"`
}

// RetryConfig defines retry behavior for failed requests
type RetryConfig struct {
	MaxRetries      int           `json:"max_retries" yaml:"max_retries"`
	InitialDelay    time.Duration `json:"initial_delay" yaml:"initial_delay"`
	MaxDelay        time.Duration `json:"max_delay" yaml:"max_delay"`
	Multiplier      float64       `json:"multiplier" yaml:"multiplier"`
	Jitter          bool          `json:"jitter" yaml:"jitter"`
	RetryableStatus []int         `json:"retryable_status" yaml:"retryable_status"`
}

// TLSConfig defines TLS security settings
type TLSConfig struct {
	InsecureSkipVerify bool     `json:"insecure_skip_verify" yaml:"insecure_skip_verify"`
	MinVersion         uint16   `json:"min_version" yaml:"min_version"`
	MaxVersion         uint16   `json:"max_version" yaml:"max_version"`
	CipherSuites       []uint16 `json:"cipher_suites" yaml:"cipher_suites"`
	RootCAFile         string   `json:"root_ca_file" yaml:"root_ca_file"`
	ClientCertFile     string   `json:"client_cert_file" yaml:"client_cert_file"`
	ClientKeyFile      string   `json:"client_key_file" yaml:"client_key_file"`
}

// AuthConfig defines authentication settings
type AuthConfig struct {
	Type          AuthType          `json:"type" yaml:"type"`
	Token         string            `json:"token" yaml:"token"`
	Username      string            `json:"username" yaml:"username"`
	Password      string            `json:"password" yaml:"password"`
	CustomHeaders map[string]string `json:"custom_headers" yaml:"custom_headers"`
	RefreshFunc   TokenRefreshFunc  `json:"-" yaml:"-"`
	TokenHeader   string            `json:"token_header" yaml:"token_header"`
	TokenPrefix   string            `json:"token_prefix" yaml:"token_prefix"`
}

// RateLimitConfig defines rate limiting behavior
type RateLimitConfig struct {
	RequestsPerSecond float64       `json:"requests_per_second" yaml:"requests_per_second"`
	BurstSize         int           `json:"burst_size" yaml:"burst_size"`
	WindowSize        time.Duration `json:"window_size" yaml:"window_size"`
}

// PoolConfig defines connection pool settings
type PoolConfig struct {
	MaxIdleConns        int           `json:"max_idle_conns" yaml:"max_idle_conns"`
	MaxIdleConnsPerHost int           `json:"max_idle_conns_per_host" yaml:"max_idle_conns_per_host"`
	MaxConnsPerHost     int           `json:"max_conns_per_host" yaml:"max_conns_per_host"`
	IdleConnTimeout     time.Duration `json:"idle_conn_timeout" yaml:"idle_conn_timeout"`
	DialTimeout         time.Duration `json:"dial_timeout" yaml:"dial_timeout"`
	KeepAlive           time.Duration `json:"keep_alive" yaml:"keep_alive"`
}

// LogConfig defines logging behavior
type LogConfig struct {
	LogRequests  bool `json:"log_requests" yaml:"log_requests"`
	LogResponses bool `json:"log_responses" yaml:"log_responses"`
	LogHeaders   bool `json:"log_headers" yaml:"log_headers"`
	LogBody      bool `json:"log_body" yaml:"log_body"`
}

// AuthType represents different authentication methods
type AuthType string

const (
	AuthTypeNone   AuthType = "none"
	AuthTypeBearer AuthType = "bearer"
	AuthTypeBasic  AuthType = "basic"
	AuthTypeCustom AuthType = "custom"
	AuthTypeAPIKey AuthType = "api_key"
)

// TokenRefreshFunc is a function that can refresh an authentication token
type TokenRefreshFunc func(ctx context.Context) (string, error)

// DefaultConfig returns a secure default configuration
func DefaultConfig() *Config {
	return &Config{
		Timeout:   30 * time.Second,
		UserAgent: "Eos/1.0 (https://cybermonkey.net.au)",
		Headers:   make(map[string]string),

		RetryConfig: &RetryConfig{
			MaxRetries:      3,
			InitialDelay:    2 * time.Second,
			MaxDelay:        30 * time.Second,
			Multiplier:      2.0,
			Jitter:          true,
			RetryableStatus: []int{429, 500, 502, 503, 504},
		},

		TLSConfig: &TLSConfig{
			InsecureSkipVerify: false,
			MinVersion:         tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			},
		},

		AuthConfig: &AuthConfig{
			Type:          AuthTypeNone,
			CustomHeaders: make(map[string]string),
			TokenHeader:   "Authorization",
			TokenPrefix:   "Bearer",
		},

		RateLimitConfig: &RateLimitConfig{
			RequestsPerSecond: 10.0,
			BurstSize:         20,
			WindowSize:        time.Minute,
		},

		PoolConfig: &PoolConfig{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			MaxConnsPerHost:     50,
			IdleConnTimeout:     90 * time.Second,
			DialTimeout:         5 * time.Second,
			KeepAlive:           30 * time.Second,
		},

		LogConfig: &LogConfig{
			LogRequests:  false,
			LogResponses: false,
			LogHeaders:   false,
			LogBody:      false,
		},
	}
}

// SecurityConfig returns a high-security configuration
func SecurityConfig() *Config {
	config := DefaultConfig()

	// Enhanced TLS security
	config.TLSConfig.MinVersion = tls.VersionTLS13
	config.TLSConfig.CipherSuites = []uint16{
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,
		tls.TLS_AES_128_GCM_SHA256,
	}

	// Strict timeouts
	config.Timeout = 10 * time.Second
	config.PoolConfig.DialTimeout = 3 * time.Second
	config.PoolConfig.KeepAlive = 15 * time.Second

	// Conservative retry settings
	config.RetryConfig.MaxRetries = 2
	config.RetryConfig.InitialDelay = 1 * time.Second
	config.RetryConfig.MaxDelay = 10 * time.Second

	// Lower rate limits for security
	config.RateLimitConfig.RequestsPerSecond = 5.0
	config.RateLimitConfig.BurstSize = 10

	return config
}

// TestConfig returns a configuration suitable for testing
func TestConfig() *Config {
	config := DefaultConfig()

	// Allow insecure TLS for testing
	config.TLSConfig.InsecureSkipVerify = true

	// Shorter timeouts for faster tests
	config.Timeout = 5 * time.Second
	config.PoolConfig.DialTimeout = 1 * time.Second

	// No retries in tests
	config.RetryConfig.MaxRetries = 0

	// Enable logging for debugging
	config.LogConfig.LogRequests = true
	config.LogConfig.LogResponses = true

	return config
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if c.Timeout <= 0 {
		return &ConfigError{Field: "Timeout", Message: "must be positive"}
	}

	if c.RetryConfig != nil {
		if c.RetryConfig.MaxRetries < 0 {
			return &ConfigError{Field: "RetryConfig.MaxRetries", Message: "cannot be negative"}
		}
		if c.RetryConfig.MaxRetries > 0 {
			if c.RetryConfig.InitialDelay <= 0 {
				return &ConfigError{Field: "RetryConfig.InitialDelay", Message: "must be positive"}
			}
			if c.RetryConfig.Multiplier <= 1.0 {
				return &ConfigError{Field: "RetryConfig.Multiplier", Message: "must be greater than 1.0"}
			}
		}
	}

	if c.RateLimitConfig != nil {
		if c.RateLimitConfig.RequestsPerSecond <= 0 {
			return &ConfigError{Field: "RateLimitConfig.RequestsPerSecond", Message: "must be positive"}
		}
		if c.RateLimitConfig.BurstSize <= 0 {
			return &ConfigError{Field: "RateLimitConfig.BurstSize", Message: "must be positive"}
		}
	}

	return nil
}

// ConfigError represents a configuration validation error
type ConfigError struct {
	Field   string
	Message string
}

func (e *ConfigError) Error() string {
	return fmt.Sprintf("invalid config field %s: %s", e.Field, e.Message)
}
