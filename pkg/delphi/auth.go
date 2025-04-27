// pkg/delphi/auth.go
package delphi

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"go.uber.org/zap"
)

// Authenticate logs in to the Wazuh API using the current Delphi config
// and returns a JWT token.
func Authenticate(cfg *Config, log *zap.Logger) (string, error) {
	authURL := fmt.Sprintf("%s/security/user/authenticate?raw=true", strings.TrimRight(cfg.Endpoint, "/"))

	req, err := http.NewRequest("POST", authURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create auth request: %w", err)
	}
	req.SetBasicAuth(cfg.APIUser, cfg.APIPassword)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: !cfg.VerifyCertificates,
			},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("auth request failed: %w", err)
	}
	defer shared.SafeClose(resp.Body, log)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read auth response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("authentication failed (%d): %s", resp.StatusCode, string(body))
	}

	token := strings.TrimSpace(string(body))
	if token == "" {
		return "", fmt.Errorf("authentication succeeded but no token received")
	}

	return token, nil
}

// AuthenticatedGetJSON performs a GET request using the stored JWT token
// and returns the response body and HTTP status code.
func AuthenticatedGetJSON(cfg *Config, path string, log *zap.Logger) (string, int) {
	resp, err := AuthenticatedGet(cfg, path)
	if err != nil {
		fmt.Printf("❌ Request failed: %v\n", err)
		os.Exit(1)
	}
	defer shared.SafeClose(resp.Body, log)

	body, _ := io.ReadAll(resp.Body)
	return string(body), resp.StatusCode
}

// AuthenticateUser tries to log in using an arbitrary username/password pair.
// Useful for testing or rotating credentials.
func AuthenticateUser(cfg *Config, username, password string, log *zap.Logger) (string, error) {
	url := fmt.Sprintf("%s://%s:%s/security/user/authenticate?raw=true",
		cfg.Protocol, cfg.FQDN, cfg.Port)

	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.SetBasicAuth(username, password)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: !cfg.VerifyCertificates,
			},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("auth request failed: %w", err)
	}
	defer shared.SafeClose(resp.Body, log)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read auth response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("authentication failed (%d): %s", resp.StatusCode, string(body))
	}

	return strings.TrimSpace(string(body)), nil
}
