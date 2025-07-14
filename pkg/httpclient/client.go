package httpclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"go.uber.org/zap"
	"golang.org/x/time/rate"
)

// Client represents an enhanced HTTP client with advanced features
type Client struct {
	httpClient  *http.Client
	config      *Config
	rateLimiter *rate.Limiter
	logger      *zap.Logger
}

// NewClient creates a new HTTP client with the provided configuration
func NewClient(config *Config) (*Client, error) {
	if config == nil {
		config = DefaultConfig()
	}
	
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	
	tlsConfig, err := buildTLSConfig(config.TLSConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to build TLS config: %w", err)
	}
	
	transport := &http.Transport{
		TLSClientConfig:     tlsConfig,
		MaxIdleConns:        config.PoolConfig.MaxIdleConns,
		MaxIdleConnsPerHost: config.PoolConfig.MaxIdleConnsPerHost,
		MaxConnsPerHost:     config.PoolConfig.MaxConnsPerHost,
		IdleConnTimeout:     config.PoolConfig.IdleConnTimeout,
		DialContext: (&net.Dialer{
			Timeout:   config.PoolConfig.DialTimeout,
			KeepAlive: config.PoolConfig.KeepAlive,
		}).DialContext,
	}
	
	httpClient := &http.Client{
		Timeout:   config.Timeout,
		Transport: transport,
	}
	
	var rateLimiter *rate.Limiter
	if config.RateLimitConfig != nil {
		rateLimiter = rate.NewLimiter(
			rate.Limit(config.RateLimitConfig.RequestsPerSecond),
			config.RateLimitConfig.BurstSize,
		)
	}
	
	logger := zap.L().Named("httpclient")
	
	return &Client{
		httpClient:  httpClient,
		config:      config,
		rateLimiter: rateLimiter,
		logger:      logger,
	}, nil
}

// NewClientWithContext creates a new HTTP client with context-aware logger
func NewClientWithContext(ctx context.Context, config *Config) (*Client, error) {
	client, err := NewClient(config)
	if err != nil {
		return nil, err
	}
	
	// Use the base logger from otelzap for now
	client.logger = zap.L().Named("httpclient")
	return client, nil
}

// Do executes an HTTP request with retry logic and authentication
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	return c.DoWithContext(req.Context(), req)
}

// DoWithContext executes an HTTP request with context and enhanced features
func (c *Client) DoWithContext(ctx context.Context, req *http.Request) (*http.Response, error) {
	// Apply rate limiting
	if c.rateLimiter != nil {
		if err := c.rateLimiter.Wait(ctx); err != nil {
			return nil, fmt.Errorf("rate limit wait failed: %w", err)
		}
	}
	
	// Set request context
	req = req.WithContext(ctx)
	
	// Apply authentication
	if err := c.applyAuthentication(ctx, req); err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}
	
	// Apply default headers
	c.applyHeaders(req)
	
	// Execute request with retry logic
	return c.executeWithRetry(ctx, req)
}

// Get performs a GET request
func (c *Client) Get(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create GET request: %w", err)
	}
	return c.DoWithContext(ctx, req)
}

// Post performs a POST request
func (c *Client) Post(ctx context.Context, url string, contentType string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create POST request: %w", err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	return c.DoWithContext(ctx, req)
}

// Put performs a PUT request
func (c *Client) Put(ctx context.Context, url string, contentType string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create PUT request: %w", err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	return c.DoWithContext(ctx, req)
}

// Delete performs a DELETE request
func (c *Client) Delete(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create DELETE request: %w", err)
	}
	return c.DoWithContext(ctx, req)
}

// executeWithRetry executes a request with configurable retry logic
func (c *Client) executeWithRetry(ctx context.Context, req *http.Request) (*http.Response, error) {
	var lastErr error
	var body []byte
	
	// Read body once if present (for retries)
	if req.Body != nil {
		var err error
		body, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read request body: %w", err)
		}
		if err := req.Body.Close(); err != nil {
			// Log error but don't fail the request
		}
	}
	
	retryConfig := c.config.RetryConfig
	maxAttempts := retryConfig.MaxRetries + 1
	
	for attempt := 0; attempt < maxAttempts; attempt++ {
		// Recreate body for retry attempts
		if body != nil {
			req.Body = io.NopCloser(bytes.NewReader(body))
		}
		
		// Log request if configured
		if c.config.LogConfig.LogRequests {
			c.logRequest(req, attempt)
		}
		
		// Execute the request
		start := time.Now()
		resp, err := c.httpClient.Do(req)
		duration := time.Since(start)
		
		// Log response if configured
		if c.config.LogConfig.LogResponses {
			c.logResponse(resp, err, duration, attempt)
		}
		
		if err != nil {
			lastErr = err
			if attempt < maxAttempts-1 {
				delay := c.calculateRetryDelay(attempt, retryConfig)
				c.logger.Debug("Request failed, retrying",
					zap.Error(err),
					zap.Int("attempt", attempt+1),
					zap.Int("max_attempts", maxAttempts),
					zap.Duration("retry_delay", delay))
				
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(delay):
					continue
				}
			}
			continue
		}
		
		// Check if response status is retryable
		if c.isRetryableStatus(resp.StatusCode, retryConfig) && attempt < maxAttempts-1 {
			if err := resp.Body.Close(); err != nil {
				// Log error but continue with retry
			}
			delay := c.calculateRetryDelay(attempt, retryConfig)
			c.logger.Debug("Retryable status code, retrying",
				zap.Int("status_code", resp.StatusCode),
				zap.Int("attempt", attempt+1),
				zap.Int("max_attempts", maxAttempts),
				zap.Duration("retry_delay", delay))
			
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
				continue
			}
		}
		
		return resp, nil
	}
	
	return nil, fmt.Errorf("request failed after %d attempts: %w", maxAttempts, lastErr)
}

// applyAuthentication applies the configured authentication to the request
func (c *Client) applyAuthentication(ctx context.Context, req *http.Request) error {
	auth := c.config.AuthConfig
	if auth == nil || auth.Type == AuthTypeNone {
		return nil
	}
	
	switch auth.Type {
	case AuthTypeBearer:
		token := auth.Token
		if auth.RefreshFunc != nil {
			refreshedToken, err := auth.RefreshFunc(ctx)
			if err != nil {
				return fmt.Errorf("token refresh failed: %w", err)
			}
			token = refreshedToken
		}
		
		header := auth.TokenHeader
		if header == "" {
			header = "Authorization"
		}
		
		prefix := auth.TokenPrefix
		if prefix == "" {
			prefix = "Bearer"
		}
		
		req.Header.Set(header, fmt.Sprintf("%s %s", prefix, token))
		
	case AuthTypeBasic:
		if auth.Username == "" || auth.Password == "" {
			return fmt.Errorf("username and password required for basic auth")
		}
		credentials := base64.StdEncoding.EncodeToString([]byte(auth.Username + ":" + auth.Password))
		req.Header.Set("Authorization", "Basic "+credentials)
		
	case AuthTypeAPIKey:
		if auth.Token == "" {
			return fmt.Errorf("token required for API key auth")
		}
		header := auth.TokenHeader
		if header == "" {
			header = "X-API-Key"
		}
		req.Header.Set(header, auth.Token)
		
	case AuthTypeCustom:
		for key, value := range auth.CustomHeaders {
			req.Header.Set(key, value)
		}
	}
	
	return nil
}

// applyHeaders applies default headers to the request
func (c *Client) applyHeaders(req *http.Request) {
	// Set User-Agent if not already set
	if req.Header.Get("User-Agent") == "" && c.config.UserAgent != "" {
		req.Header.Set("User-Agent", c.config.UserAgent)
	}
	
	// Apply custom headers
	for key, value := range c.config.Headers {
		if req.Header.Get(key) == "" {
			req.Header.Set(key, value)
		}
	}
}

// calculateRetryDelay calculates the delay for retry attempts with exponential backoff
func (c *Client) calculateRetryDelay(attempt int, config *RetryConfig) time.Duration {
	delay := time.Duration(float64(config.InitialDelay) * math.Pow(config.Multiplier, float64(attempt)))
	
	if delay > config.MaxDelay {
		delay = config.MaxDelay
	}
	
	// Add jitter if enabled
	if config.Jitter {
		jitter := time.Duration(rand.Float64() * float64(delay) * 0.1)
		delay += jitter
	}
	
	return delay
}

// isRetryableStatus checks if a status code is retryable
func (c *Client) isRetryableStatus(statusCode int, config *RetryConfig) bool {
	for _, code := range config.RetryableStatus {
		if statusCode == code {
			return true
		}
	}
	return false
}

// logRequest logs HTTP request details
func (c *Client) logRequest(req *http.Request, attempt int) {
	fields := []zap.Field{
		zap.String("method", req.Method),
		zap.String("url", req.URL.String()),
		zap.Int("attempt", attempt+1),
	}
	
	if c.config.LogConfig.LogHeaders {
		headers := make(map[string]string)
		for k, v := range req.Header {
			// Sanitize sensitive headers
			if isSensitiveHeader(k) {
				headers[k] = "[REDACTED]"
			} else {
				headers[k] = strings.Join(v, ", ")
			}
		}
		fields = append(fields, zap.Any("headers", headers))
	}
	
	if c.config.LogConfig.LogBody && req.Body != nil {
		// Note: This would consume the body, so it should be used carefully
		fields = append(fields, zap.String("body", "[BODY_LOGGING_ENABLED]"))
	}
	
	c.logger.Debug("HTTP request", fields...)
}

// logResponse logs HTTP response details
func (c *Client) logResponse(resp *http.Response, err error, duration time.Duration, attempt int) {
	fields := []zap.Field{
		zap.Duration("duration", duration),
		zap.Int("attempt", attempt+1),
	}
	
	if err != nil {
		fields = append(fields, zap.Error(err))
		c.logger.Debug("HTTP request failed", fields...)
		return
	}
	
	fields = append(fields,
		zap.Int("status_code", resp.StatusCode),
		zap.String("status", resp.Status),
	)
	
	if c.config.LogConfig.LogHeaders {
		headers := make(map[string]string)
		for k, v := range resp.Header {
			headers[k] = strings.Join(v, ", ")
		}
		fields = append(fields, zap.Any("response_headers", headers))
	}
	
	c.logger.Debug("HTTP response", fields...)
}

// isSensitiveHeader checks if a header contains sensitive information
func isSensitiveHeader(header string) bool {
	sensitiveHeaders := []string{
		"authorization",
		"x-auth-token",
		"x-api-key",
		"cookie",
		"x-forwarded-authorization",
	}
	
	headerLower := strings.ToLower(header)
	for _, sensitive := range sensitiveHeaders {
		if headerLower == sensitive || strings.Contains(headerLower, "token") || strings.Contains(headerLower, "key") {
			return true
		}
	}
	return false
}

// buildTLSConfig creates a TLS configuration from the provided config
func buildTLSConfig(config *TLSConfig) (*tls.Config, error) {
	if config == nil {
		// Use default secure TLS config
		return &tls.Config{
			MinVersion: tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			},
			PreferServerCipherSuites: true,
		}, nil
	}
	
	tlsConfig := &tls.Config{
		InsecureSkipVerify: config.InsecureSkipVerify,
		MinVersion:         config.MinVersion,
		MaxVersion:         config.MaxVersion,
		CipherSuites:       config.CipherSuites,
	}
	
	// Load root CA if specified
	if config.RootCAFile != "" {
		caCert, err := os.ReadFile(config.RootCAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read root CA file: %w", err)
		}
		
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse root CA certificate")
		}
		tlsConfig.RootCAs = caCertPool
	}
	
	// Load client certificate if specified
	if config.ClientCertFile != "" && config.ClientKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(config.ClientCertFile, config.ClientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}
	
	return tlsConfig, nil
}

// SetLogger sets a custom logger for the client
func (c *Client) SetLogger(logger *zap.Logger) {
	c.logger = logger.Named("httpclient")
}

// GetConfig returns the client configuration
func (c *Client) GetConfig() *Config {
	return c.config
}

// Close closes the underlying HTTP client connections
func (c *Client) Close() error {
	if transport, ok := c.httpClient.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
	return nil
}