// Package config provides SaltStack configuration utilities
package config

import (
	"os"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/saltstack/client"
)

// GetFromEnv retrieves Salt configuration from environment variables
func GetFromEnv() *client.ClientConfig {
	return &client.ClientConfig{
		BaseURL:    GetURLFromEnv(),
		Username:   GetUsernameFromEnv(),
		Password:   GetPasswordFromEnv(),
		Eauth:      GetEauthFromEnv(),
		Timeout:    30 * time.Second,
		MaxRetries: 3,
		RetryDelay: 2 * time.Second,
	}
}

// GetURLFromEnv gets the Salt API URL from environment variables
func GetURLFromEnv() string {
	// Check various environment variables that might contain the Salt URL
	if url := os.Getenv("SALT_API_URL"); url != "" {
		return url
	}
	if url := os.Getenv("SALTSTACK_URL"); url != "" {
		return url
	}
	// Default empty to trigger fallback behavior
	return ""
}

// GetUsernameFromEnv gets the Salt username from environment variables
func GetUsernameFromEnv() string {
	if username := os.Getenv("SALT_API_USER"); username != "" {
		return username
	}
	if username := os.Getenv("SALTSTACK_USER"); username != "" {
		return username
	}
	return ""
}

// GetPasswordFromEnv gets the Salt password from environment variables
func GetPasswordFromEnv() string {
	if password := os.Getenv("SALT_API_PASS"); password != "" {
		return password
	}
	if password := os.Getenv("SALTSTACK_PASS"); password != "" {
		return password
	}
	return ""
}

// GetEauthFromEnv gets the Salt authentication method from environment variables
func GetEauthFromEnv() string {
	if eauth := os.Getenv("SALT_API_EAUTH"); eauth != "" {
		return eauth
	}
	// Default to PAM authentication
	return "pam"
}
