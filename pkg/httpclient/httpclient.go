// pkg/httpclient/httpclient.go

package httpclient

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"
)

var defaultClient = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // NOTE: Consider hardening in production
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	},
}

// DefaultClient returns a preconfigured HTTP client used across Eos
func DefaultClient() *http.Client {
	return defaultClient
}

// SetDefaultClient allows replacing the default client for testing purposes
func SetDefaultClient(client *http.Client) {
	defaultClient = client
}
