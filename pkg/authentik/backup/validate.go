// pkg/authentik/backup/validate.go
package backup

import (
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/authentik"
)

// CheckWazuhConfiguration checks if the config contains Wazuh/Wazuh related items
func CheckWazuhConfiguration(config *authentik.AuthentikConfig) bool {
	keywords := []string{"wazuh", "wazuh", "analyst", "soc", "siem"}

	// Check providers
	for _, provider := range config.Providers {
		lowerName := strings.ToLower(provider.Name)
		for _, keyword := range keywords {
			if strings.Contains(lowerName, keyword) {
				return true
			}
		}
	}

	// Check applications
	for _, app := range config.Applications {
		lowerName := strings.ToLower(app.Name)
		lowerSlug := strings.ToLower(app.Slug)
		for _, keyword := range keywords {
			if strings.Contains(lowerName, keyword) || strings.Contains(lowerSlug, keyword) {
				return true
			}
		}
	}

	// Check groups
	for _, group := range config.Groups {
		lowerName := strings.ToLower(group.Name)
		for _, keyword := range keywords {
			if strings.Contains(lowerName, keyword) {
				return true
			}
		}
	}

	return false
}

// CheckRolesMapping checks if the config contains the critical Roles property mapping
func CheckRolesMapping(config *authentik.AuthentikConfig) bool {
	for _, mapping := range config.PropertyMappings {
		// Check if this is a SAML mapping with the critical "Roles" attribute name
		if mapping.SAMLName == "Roles" {
			return true
		}
	}
	return false
}
