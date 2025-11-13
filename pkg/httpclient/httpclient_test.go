// pkg/httpclient/httpclient_test.go
package httpclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewClient tests client creation with various configurations
func TestNewClient(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
		errMsg  string
	}{
		{
			name:    "default config",
			config:  DefaultConfig(),
			wantErr: false,
		},
		{
			name:    "nil config uses default",
			config:  nil,
			wantErr: false,
		},
		{
			name: "invalid timeout",
			config: &Config{
				Timeout: -1 * time.Second,
			},
			wantErr: true,
			errMsg:  "invalid timeout",
		},
		{
			name: "with TLS config",
			config: &Config{
				Timeout: 30 * time.Second,
				TLSConfig: &TLSConfig{
					MinVersion:         tls.VersionTLS12,
					InsecureSkipVerify: false,
				},
			},
			wantErr: false,
		},
		{
			name: "with rate limiter",
			config: &Config{
				Timeout: 30 * time.Second,
				RateLimitConfig: &RateLimitConfig{
					RequestsPerSecond: 10,
					BurstSize:         5,
				},
			},
			wantErr: false,
		},
		{
			name: "with invalid CA file",
			config: &Config{
				Timeout: 30 * time.Second,
				TLSConfig: &TLSConfig{
					RootCAFile: "/nonexistent/ca.pem",
				},
			},
			wantErr: true,
			errMsg:  "failed to build TLS config",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.config)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, client)
				assert.NotNil(t, client.httpClient)
			}
		})
	}
}

// TestClientGet tests GET requests
func TestClientGet(t *testing.T) {
	// Create test server
	var requestCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)

		switch r.URL.Path {
		case "/success":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("success"))
		case "/error":
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("internal error"))
		case "/timeout":
			time.Sleep(2 * time.Second)
			w.WriteHeader(http.StatusOK)
		case "/auth":
			auth := r.Header.Get("Authorization")
			if auth == "" {
				w.WriteHeader(http.StatusUnauthorized)
			} else {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("authenticated"))
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	tests := []struct {
		name       string
		config     *Config
		url        string
		wantStatus int
		wantErr    bool
	}{
		{
			name:       "successful GET",
			config:     DefaultConfig(),
			url:        server.URL + "/success",
			wantStatus: http.StatusOK,
			wantErr:    false,
		},
		{
			name:       "server error",
			config:     DefaultConfig(),
			url:        server.URL + "/error",
			wantStatus: http.StatusInternalServerError,
			wantErr:    false,
		},
		{
			name: "timeout",
			config: &Config{
				Timeout: 100 * time.Millisecond,
			},
			url:     server.URL + "/timeout",
			wantErr: true,
		},
		{
			name: "with bearer auth",
			config: &Config{
				Timeout: 30 * time.Second,
				AuthConfig: &AuthConfig{
					Type:  AuthTypeBearer,
					Token: "test-token",
				},
			},
			url:        server.URL + "/auth",
			wantStatus: http.StatusOK,
			wantErr:    false,
		},
		{
			name:    "invalid URL",
			config:  DefaultConfig(),
			url:     "://invalid-url",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.config)
			require.NoError(t, err)

			ctx := context.Background()
			resp, err := client.Get(ctx, tt.url)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.Equal(t, tt.wantStatus, resp.StatusCode)
				resp.Body.Close()
			}
		})
	}
}

// TestClientPost tests POST requests
func TestClientPost(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		// Check content type
		contentType := r.Header.Get("Content-Type")
		if contentType != "application/json" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Read body
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	defer server.Close()

	client, err := NewClient(DefaultConfig())
	require.NoError(t, err)

	tests := []struct {
		name        string
		body        string
		contentType string
		wantStatus  int
		wantErr     bool
	}{
		{
			name:        "successful POST",
			body:        `{"test": "data"}`,
			contentType: "application/json",
			wantStatus:  http.StatusOK,
			wantErr:     false,
		},
		{
			name:        "wrong content type",
			body:        `{"test": "data"}`,
			contentType: "text/plain",
			wantStatus:  http.StatusBadRequest,
			wantErr:     false,
		},
		{
			name:        "empty body",
			body:        "",
			contentType: "application/json",
			wantStatus:  http.StatusOK,
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			resp, err := client.Post(ctx, server.URL, tt.contentType, strings.NewReader(tt.body))

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantStatus, resp.StatusCode)

				if resp.StatusCode == http.StatusOK {
					body, err := io.ReadAll(resp.Body)
					assert.NoError(t, err)
					assert.Equal(t, tt.body, string(body))
				}
				resp.Body.Close()
			}
		})
	}
}

// TestAuthentication tests various authentication methods
func TestAuthentication(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")

		switch {
		case strings.HasPrefix(auth, "Bearer "):
			token := strings.TrimPrefix(auth, "Bearer ")
			if token == "valid-token" {
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusUnauthorized)
			}
		case strings.HasPrefix(auth, "Basic "):
			encoded := strings.TrimPrefix(auth, "Basic ")
			decoded, err := base64.StdEncoding.DecodeString(encoded)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if string(decoded) == "user:pass" {
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusUnauthorized)
			}
		default:
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer server.Close()

	tests := []struct {
		name       string
		authConfig *AuthConfig
		wantStatus int
	}{
		{
			name: "bearer auth success",
			authConfig: &AuthConfig{
				Type:  AuthTypeBearer,
				Token: "valid-token",
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "bearer auth failure",
			authConfig: &AuthConfig{
				Type:  AuthTypeBearer,
				Token: "invalid-token",
			},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "basic auth success",
			authConfig: &AuthConfig{
				Type:     AuthTypeBasic,
				Username: "user",
				Password: "pass",
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "basic auth failure",
			authConfig: &AuthConfig{
				Type:     AuthTypeBasic,
				Username: "wrong",
				Password: "creds",
			},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "no auth",
			authConfig: &AuthConfig{
				Type: AuthTypeNone,
			},
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := DefaultConfig()
			config.AuthConfig = tt.authConfig

			client, err := NewClient(config)
			require.NoError(t, err)

			ctx := context.Background()
			resp, err := client.Get(ctx, server.URL)
			require.NoError(t, err)
			assert.Equal(t, tt.wantStatus, resp.StatusCode)
			resp.Body.Close()
		})
	}
}

// TestRetryLogic tests retry functionality
func TestRetryLogic(t *testing.T) {
	var attempts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current := atomic.AddInt32(&attempts, 1)

		if current < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	config := DefaultConfig()
	config.RetryConfig = &RetryConfig{
		MaxRetries:      3,
		InitialDelay:    10 * time.Millisecond,
		MaxDelay:        100 * time.Millisecond,
		Multiplier:      2,
		RetryableStatus: []int{http.StatusServiceUnavailable},
	}

	client, err := NewClient(config)
	require.NoError(t, err)

	ctx := context.Background()
	resp, err := client.Get(ctx, server.URL)

	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, int32(3), atomic.LoadInt32(&attempts))
	resp.Body.Close()
}

// TestRateLimiting tests rate limiting functionality
func TestRateLimiting(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := DefaultConfig()
	config.RateLimitConfig = &RateLimitConfig{
		RequestsPerSecond: 5, // 5 requests per second
		BurstSize:         2,
	}

	client, err := NewClient(config)
	require.NoError(t, err)

	// Measure time for multiple requests
	start := time.Now()
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		resp, err := client.Get(ctx, server.URL)
		assert.NoError(t, err)
		resp.Body.Close()
	}

	elapsed := time.Since(start)
	// With 5 RPS and burst of 2, 5 requests should take at least ~600ms
	// (2 immediate, then 3 more at 200ms intervals)
	assert.GreaterOrEqual(t, elapsed, 500*time.Millisecond)
}

// TestConcurrentRequests tests thread safety
func TestConcurrentRequests(t *testing.T) {
	var requestCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		time.Sleep(10 * time.Millisecond) // Simulate work
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := NewClient(DefaultConfig())
	require.NoError(t, err)

	const numGoroutines = 20
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	errors := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()

			ctx := context.Background()
			resp, err := client.Get(ctx, server.URL)
			if err != nil {
				errors <- err
				return
			}
			resp.Body.Close()
		}()
	}

	wg.Wait()
	close(errors)

	// Check for errors
	for err := range errors {
		t.Errorf("Concurrent request failed: %v", err)
	}

	assert.Equal(t, int32(numGoroutines), atomic.LoadInt32(&requestCount))
}

// TestHeaderInjection tests for header injection vulnerabilities
func TestHeaderInjection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo back headers for verification
		for name, values := range r.Header {
			for _, value := range values {
				w.Header().Add("Echo-"+name, value)
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Headers = map[string]string{
		"X-Test-Header": "test\r\nX-Injected: malicious",
		"X-Normal":      "normal value",
	}

	client, err := NewClient(config)
	require.NoError(t, err)

	ctx := context.Background()
	resp, err := client.Get(ctx, server.URL)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Verify headers were properly sanitized or handled
	injected := resp.Header.Get("Echo-X-Injected")
	assert.Empty(t, injected, "Header injection vulnerability detected")
}

// TestTLSValidation tests TLS certificate validation
func TestTLSValidation(t *testing.T) {
	// Create HTTPS test server with self-signed cert
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	tests := []struct {
		name    string
		config  *TLSConfig
		wantErr bool
	}{
		{
			name: "reject invalid cert by default",
			config: &TLSConfig{
				InsecureSkipVerify: false,
			},
			wantErr: true,
		},
		{
			name: "accept invalid cert when configured",
			config: &TLSConfig{
				InsecureSkipVerify: true,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := DefaultConfig()
			config.TLSConfig = tt.config

			client, err := NewClient(config)
			require.NoError(t, err)

			ctx := context.Background()
			resp, err := client.Get(ctx, server.URL)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				resp.Body.Close()
			}
		})
	}
}

// TestDefaultClient tests the default client functionality
func TestDefaultClient(t *testing.T) {
	// Test that default client is initialized
	defaultClient := DefaultClient()
	assert.NotNil(t, defaultClient)
	assert.NotNil(t, defaultClient.httpClient)

	// Test getting underlying HTTP client
	httpClient := DefaultHTTPClient()
	assert.NotNil(t, httpClient)

	// Test replacing default client
	newConfig := DefaultConfig()
	newConfig.Timeout = 5 * time.Second
	newClient, err := NewClient(newConfig)
	require.NoError(t, err)

	SetDefaultClient(newClient)
	assert.Equal(t, newClient, DefaultClient())

	// Test setting standard http.Client
	stdClient := &http.Client{
		Timeout: 10 * time.Second,
	}
	err = SetDefaultHTTPClient(stdClient)
	assert.NoError(t, err)
}

// TestBodyReading tests various body reading scenarios
func TestBodyReading(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Body-Length", fmt.Sprintf("%d", len(body)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	defer server.Close()

	client, err := NewClient(DefaultConfig())
	require.NoError(t, err)

	tests := []struct {
		name string
		body io.Reader
	}{
		{
			name: "string reader",
			body: strings.NewReader("test body"),
		},
		{
			name: "bytes buffer",
			body: bytes.NewBuffer([]byte("buffer body")),
		},
		{
			name: "empty body",
			body: nil,
		},
		{
			name: "large body",
			body: strings.NewReader(strings.Repeat("x", 1024*1024)), // 1MB
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			resp, err := client.Post(ctx, server.URL, "text/plain", tt.body)
			assert.NoError(t, err)
			resp.Body.Close()
		})
	}
}
