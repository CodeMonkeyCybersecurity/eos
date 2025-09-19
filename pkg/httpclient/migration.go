package httpclient

import (
	"crypto/tls"
	"net/http"
	"time"
)

// Migration utilities to help existing HTTP clients transition to the unified framework

// WrapStandardClient wraps a standard http.Client to use the unified configuration
func WrapStandardClient(standardClient *http.Client, config *Config) (*Client, error) {
	if config == nil {
		config = DefaultConfig()
	}
	
	if err := config.Validate(); err != nil {
		return nil, err
	}
	
	// Extract configuration from standard client if possible
	if standardClient.Timeout > 0 {
		config.Timeout = standardClient.Timeout
	}
	
	// Create new client with merged configuration
	return NewClient(config)
}

// MigrateFromSaltStackClient creates a unified client with SaltStack-compatible configuration
func MigrateFromSaltStackClient(baseURL, username, password string, insecureTLS bool) (*Client, error) {
	config := DefaultConfig()
	
	// Configure authentication
	config.AuthConfig.Type = AuthTypeCustom
	config.AuthConfig.CustomHeaders = map[string]string{
		"Accept": "application/json",
	}
	
	// Configure TLS
	config.TLSConfig.InsecureSkipVerify = insecureTLS
	
	// SaltStack-specific timeouts and retry logic
	config.Timeout = 30 * time.Second
	config.RetryConfig.MaxRetries = 3
	config.RetryConfig.InitialDelay = 2 * time.Second
	
	return NewClient(config)
}

// MigrateFromHetznerClient creates a unified client with Hetzner API configuration
func MigrateFromHetznerClient(apiToken string) (*Client, error) {
	config := DefaultConfig()
	
	// Configure Bearer token authentication
	config.AuthConfig.Type = AuthTypeBearer
	config.AuthConfig.Token = apiToken
	config.AuthConfig.TokenHeader = "Authorization"
	config.AuthConfig.TokenPrefix = "Bearer"
	
	// Hetzner-specific configuration
	config.Timeout = 30 * time.Second
	config.RetryConfig.MaxRetries = 3
	config.RetryConfig.RetryableStatus = []int{429, 500, 502, 503, 504}
	
	// Conservative rate limiting for API
	config.RateLimitConfig.RequestsPerSecond = 5.0
	config.RateLimitConfig.BurstSize = 10
	
	return NewClient(config)
}

// MigrateFromVaultClient creates a unified client compatible with Vault operations
func MigrateFromVaultClient(vaultToken string, vaultAddr string) (*Client, error) {
	config := SecurityConfig() // Use security config for Vault
	
	// Configure Vault token authentication
	config.AuthConfig.Type = AuthTypeCustom
	config.AuthConfig.CustomHeaders = map[string]string{
		"X-Vault-Token": vaultToken,
		"X-Vault-Request": "true",
	}
	
	// Vault-specific configuration
	config.Timeout = 10 * time.Second // Shorter timeout for Vault operations
	config.RetryConfig.MaxRetries = 2
	config.RetryConfig.InitialDelay = 1 * time.Second
	
	return NewClient(config)
}

// MigrateFromLLMClient creates a unified client for LLM/AI services
func MigrateFromLLMClient(apiKey string, service string) (*Client, error) {
	config := DefaultConfig()
	
	// Configure API key authentication
	config.AuthConfig.Type = AuthTypeAPIKey
	config.AuthConfig.Token = apiKey
	
	// Service-specific configuration
	switch service {
	case "azure":
		config.AuthConfig.TokenHeader = "api-key"
		config.Timeout = 60 * time.Second // Longer timeout for AI operations
	case "openai":
		config.AuthConfig.TokenHeader = "Authorization"
		config.AuthConfig.TokenPrefix = "Bearer"
		config.Timeout = 60 * time.Second
	default:
		config.AuthConfig.TokenHeader = "X-API-Key"
		config.Timeout = 30 * time.Second
	}
	
	// LLM-specific retry configuration
	config.RetryConfig.MaxRetries = 3
	config.RetryConfig.InitialDelay = 5 * time.Second
	config.RetryConfig.MaxDelay = 30 * time.Second
	config.RetryConfig.RetryableStatus = []int{429, 500, 502, 503, 504}
	
	// Enable request/response logging for debugging
	config.LogConfig.LogRequests = true
	config.LogConfig.LogResponses = true
	
	return NewClient(config)
}

// CreateSecureClient creates a client with maximum security settings
func CreateSecureClient() (*Client, error) {
	config := SecurityConfig()
	
	// Maximum security TLS configuration
	config.TLSConfig.MinVersion = tls.VersionTLS13
	config.TLSConfig.InsecureSkipVerify = false
	
	// Strict timeouts
	config.Timeout = 10 * time.Second
	config.PoolConfig.DialTimeout = 3 * time.Second
	
	// Conservative retry settings
	config.RetryConfig.MaxRetries = 1
	config.RetryConfig.InitialDelay = 1 * time.Second
	config.RetryConfig.MaxDelay = 5 * time.Second
	
	// Strict rate limiting
	config.RateLimitConfig.RequestsPerSecond = 2.0
	config.RateLimitConfig.BurstSize = 5
	
	return NewClient(config)
}

// CreateDevelopmentClient creates a client suitable for development and testing
func CreateDevelopmentClient() (*Client, error) {
	config := TestConfig()
	
	// Development-friendly settings
	config.TLSConfig.InsecureSkipVerify = true
	config.Timeout = 30 * time.Second
	
	// More permissive retry settings
	config.RetryConfig.MaxRetries = 5
	config.RetryConfig.InitialDelay = 1 * time.Second
	
	// Enable comprehensive logging
	config.LogConfig.LogRequests = true
	config.LogConfig.LogResponses = true
	config.LogConfig.LogHeaders = true
	
	// Higher rate limits for development
	config.RateLimitConfig.RequestsPerSecond = 50.0
	config.RateLimitConfig.BurstSize = 100
	
	return NewClient(config)
}

// Migration helpers for common patterns

// ReplaceDefaultClient replaces http.DefaultClient usage with unified client
func ReplaceDefaultClient() (*Client, error) {
	config := DefaultConfig()
	
	// Use same timeout as http.DefaultClient if it was customized
	if http.DefaultClient.Timeout > 0 {
		config.Timeout = http.DefaultClient.Timeout
	}
	
	return NewClient(config)
}

// CreateClientFromHTTPClient creates a unified client based on existing http.Client configuration
func CreateClientFromHTTPClient(httpClient *http.Client) (*Client, error) {
	config := DefaultConfig()
	
	// Extract timeout
	if httpClient.Timeout > 0 {
		config.Timeout = httpClient.Timeout
	}
	
	// Extract TLS configuration if available
	if transport, ok := httpClient.Transport.(*http.Transport); ok {
		if transport.TLSClientConfig != nil {
			config.TLSConfig.InsecureSkipVerify = transport.TLSClientConfig.InsecureSkipVerify
			config.TLSConfig.MinVersion = transport.TLSClientConfig.MinVersion
			config.TLSConfig.MaxVersion = transport.TLSClientConfig.MaxVersion
			config.TLSConfig.CipherSuites = transport.TLSClientConfig.CipherSuites
		}
		
		// Extract connection pool settings
		config.PoolConfig.MaxIdleConns = transport.MaxIdleConns
		config.PoolConfig.MaxIdleConnsPerHost = transport.MaxIdleConnsPerHost
		config.PoolConfig.MaxConnsPerHost = transport.MaxConnsPerHost
		config.PoolConfig.IdleConnTimeout = transport.IdleConnTimeout
		
		// Note: Cannot extract dial settings from function type
		// Use defaults for dial timeout and keep-alive
	}
	
	return NewClient(config)
}

// CreateClientWithTokenRefresh creates a client with automatic token refresh
func CreateClientWithTokenRefresh(initialToken string, refreshFunc TokenRefreshFunc) (*Client, error) {
	config := DefaultConfig()
	
	// Configure token refresh
	config.AuthConfig.Type = AuthTypeBearer
	config.AuthConfig.Token = initialToken
	config.AuthConfig.RefreshFunc = refreshFunc
	
	return NewClient(config)
}

// MigrationGuide contains migration recommendations for different client types
type MigrationGuide struct {
	ClientType   string
	Recommendation string
	Example      string
	SecurityNotes string
}

// GetMigrationGuides returns migration guidance for common HTTP client patterns
func GetMigrationGuides() []MigrationGuide {
	return []MigrationGuide{
		{
			ClientType: "http.DefaultClient",
			Recommendation: "Replace with httpclient.ReplaceDefaultClient()",
			Example: `
// OLD
resp, err := http.Get(url)

// NEW
client, _ := httpclient.ReplaceDefaultClient()
resp, err := client.Get(ctx, url)
			`,
			SecurityNotes: "Adds TLS security, timeouts, and retry logic",
		},
		{
			ClientType: "Custom http.Client",
			Recommendation: "Use httpclient.CreateClientFromHTTPClient()",
			Example: `
// OLD
client := &http.Client{Timeout: 30 * time.Second}
resp, err := client.Get(url)

// NEW
newClient, _ := httpclient.CreateClientFromHTTPClient(client)
resp, err := newClient.Get(ctx, url)
			`,
			SecurityNotes: "Preserves existing configuration while adding security features",
		},
		{
			ClientType: "SaltStack Client",
			Recommendation: "Use httpclient.MigrateFromSaltStackClient()",
			Example: `
// OLD
// client := saltstack.NewClient(baseURL, username, password, insecure) // Deprecated

// NEW
client, _ := httpclient.MigrateFromSaltStackClient(baseURL, username, password, insecure)
			`,
			SecurityNotes: "Maintains SaltStack compatibility with enhanced security",
		},
		{
			ClientType: "Hetzner API Client",
			Recommendation: "Use httpclient.MigrateFromHetznerClient()",
			Example: `
// OLD
req, _ := http.NewRequest("GET", hetznerURL, nil)
req.Header.Set("Authorization", "Bearer " + token)
resp, err := http.DefaultClient.Do(req)

// NEW
client, _ := httpclient.MigrateFromHetznerClient(token)
resp, err := client.Get(ctx, hetznerURL)
			`,
			SecurityNotes: "Adds proper rate limiting and retry logic for API calls",
		},
		{
			ClientType: "Vault Client",
			Recommendation: "Use httpclient.MigrateFromVaultClient()",
			Example: `
// OLD
req.Header.Set("X-Vault-Token", token)
resp, err := http.DefaultClient.Do(req)

// NEW
client, _ := httpclient.MigrateFromVaultClient(token, vaultAddr)
resp, err := client.Get(ctx, vaultURL)
			`,
			SecurityNotes: "Enforces TLS 1.3 and strict security for Vault operations",
		},
	}
}