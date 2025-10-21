// Package azure provides validation functions for Azure OpenAI configuration
package azure

import (
	"fmt"
	"net/url"
	"strings"
)

// ValidateEndpoint validates an Azure OpenAI endpoint URL
// Must be: https://{resource}.openai.azure.com or https://{resource}.services.ai.azure.com
func ValidateEndpoint(endpoint string) error {
	if endpoint == "" {
		return fmt.Errorf("azure OpenAI endpoint cannot be empty")
	}

	// Must start with https://
	if !strings.HasPrefix(endpoint, "https://") {
		return fmt.Errorf("azure OpenAI endpoint must start with https://\nProvided: %s", endpoint)
	}

	// Validate it's a valid URL
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("invalid URL format: %w", err)
	}

	// Check for valid Azure OpenAI domains
	// Standard: .openai.azure.com
	// Azure AI Foundry: .services.ai.azure.com (new format)
	validDomains := []string{
		".openai.azure.com",
		".services.ai.azure.com",
	}

	validDomain := false
	for _, domain := range validDomains {
		if strings.HasSuffix(parsed.Host, domain) {
			validDomain = true
			break
		}
	}

	if !validDomain {
		return fmt.Errorf(
			"azure OpenAI endpoint must end with .openai.azure.com or .services.ai.azure.com\n"+
				"Provided: %s\n"+
				"Valid examples:\n"+
				"  - https://myresource.openai.azure.com\n"+
				"  - https://myproject.services.ai.azure.com",
			endpoint)
	}

	return nil
}

// ValidateAPIKey validates the Azure OpenAI API key format
func ValidateAPIKey(apiKey string) error {
	if apiKey == "" {
		return fmt.Errorf("azure OpenAI API key cannot be empty")
	}

	apiKeyLen := len(apiKey)

	// Azure keys can be in various formats:
	// - Legacy: 32 hex characters
	// - Standard: 43-44 base64 characters
	// - Azure AI Foundry: 88+ base64 characters
	// Just validate it looks like a reasonable key (printable ASCII, no spaces)

	if apiKeyLen < 20 {
		return fmt.Errorf("API key seems too short (%d characters) - please check you copied the complete key", apiKeyLen)
	}

	// Check for valid characters (alphanumeric + base64 chars)
	for _, ch := range apiKey {
		isValid := (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
			(ch >= '0' && ch <= '9') || ch == '+' || ch == '/' || ch == '=' || ch == '-' || ch == '_'
		if !isValid {
			return fmt.Errorf("API key contains invalid character: %c\nAPI keys should only contain alphanumeric and base64 characters", ch)
		}
	}

	return nil
}

// ValidateDeployment validates the deployment name format
func ValidateDeployment(deployment string) error {
	if deployment == "" {
		return fmt.Errorf("azure OpenAI deployment name cannot be empty")
	}

	// Azure deployment names: alphanumeric with hyphens, periods, and underscores
	// Examples: gpt-4, gpt-4.1, gpt-35-turbo, my_deployment, o3-mini-language
	for _, ch := range deployment {
		isValid := (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') || ch == '-' || ch == '.' || ch == '_'
		if !isValid {
			return fmt.Errorf(
				"deployment name must be alphanumeric with hyphens, periods, or underscores\n"+
					"Provided: %s\n"+
					"Valid examples: gpt-4, gpt-35-turbo, text-embedding-ada-002, o3-mini-language",
				deployment)
		}
	}

	return nil
}

// RedactEndpoint redacts sensitive parts of the endpoint for logging
func RedactEndpoint(endpoint string) string {
	// Extract just the resource name for logging
	// https://myresource.openai.azure.com -> myresource.openai.azure.com
	if strings.HasPrefix(endpoint, "https://") {
		return endpoint[8:] // Remove https://
	}
	return endpoint
}

// RedactAPIKey redacts the API key for logging (shows first/last 4 chars)
func RedactAPIKey(apiKey string) string {
	if len(apiKey) <= 8 {
		return "****"
	}
	return apiKey[:4] + "..." + apiKey[len(apiKey)-4:]
}
