// pkg/httpclient/httpclient.go

package httpclient

import (
	"crypto/tls"
	"net/http"
	"time"
)

var defaultClient *Client

func init() {
	// Initialize default client with secure configuration
	var err error
	defaultClient, err = NewClient(DefaultConfig())
	if err != nil {
		// Fallback to basic client if initialization fails
		basicConfig := &Config{
			Timeout:   30 * time.Second,
			UserAgent: "Eos/1.0",
			Headers:   make(map[string]string),
			TLSConfig: &TLSConfig{
				MinVersion:         tls.VersionTLS12,
				InsecureSkipVerify: false,
			},
			AuthConfig: &AuthConfig{
				Type:          AuthTypeNone,
				CustomHeaders: make(map[string]string),
			},
			RetryConfig: &RetryConfig{
				MaxRetries: 0, // No retries in fallback
			},
			PoolConfig: &PoolConfig{
				MaxIdleConns: 10,
				DialTimeout:  5 * time.Second,
				KeepAlive:    30 * time.Second,
			},
			LogConfig: &LogConfig{},
		}
		defaultClient, _ = NewClient(basicConfig)
	}
}

// DefaultClient returns a preconfigured enhanced HTTP client used across Eos
func DefaultClient() *Client {
	return defaultClient
}

// DefaultHTTPClient returns the underlying http.Client for compatibility
func DefaultHTTPClient() *http.Client {
	return defaultClient.httpClient
}

// SetDefaultClient allows replacing the default client for testing purposes
func SetDefaultClient(client *Client) {
	defaultClient = client
}

// SetDefaultHTTPClient allows replacing with a standard http.Client (wraps it in enhanced client)
func SetDefaultHTTPClient(client *http.Client) error {
	enhanced, err := CreateClientFromHTTPClient(client)
	if err != nil {
		return err
	}
	defaultClient = enhanced
	return nil
}
