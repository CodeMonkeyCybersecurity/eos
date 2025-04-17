/* pkg/delphi/api.go */

package delphi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

// GetFieldValue returns the value of a DelphiConfig field by name
func GetFieldValue(cfg *Config, field string) string {
	switch field {
	case "protocol":
		return cfg.Protocol
	case "host":
		return cfg.FQDN
	case "port":
		return cfg.Port
	case "user":
		return cfg.APIUser
	case "password":
		return cfg.APIPassword
	default:
		return ""
	}
}

// SetFieldValue updates a field in DelphiConfig by name
func SetFieldValue(cfg *Config, field, value string) {
	switch field {
	case "protocol":
		cfg.Protocol = value
	case "host":
		cfg.FQDN = value
	case "port":
		cfg.Port = value
	case "user":
		cfg.APIUser = value
	case "password":
		cfg.APIPassword = value
	}
}

// HandleAPIResponse prettifies and prints the API response or exits on error
func HandleAPIResponse(label string, body []byte, code int) {
	if code != http.StatusOK {
		fmt.Printf("❌ Failed to retrieve %s (%d): %s\n", label, code, string(body))
		os.Exit(1)
	}

	var prettyJSON map[string]interface{}
	if err := json.Unmarshal(body, &prettyJSON); err != nil {
		fmt.Printf("❌ Failed to parse JSON: %v\n", err)
		os.Exit(1)
	}

	output, _ := json.MarshalIndent(prettyJSON, "", "  ")
	fmt.Printf("✅ %s:\n%s\n", label, string(output))
}
