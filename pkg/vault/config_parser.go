// pkg/vault/config_parser.go
// Vault HCL configuration parsing and manipulation

package vault

import (
	"fmt"
	"regexp"
	"strconv"
)

// Pre-compiled regex patterns for efficiency
var (
	// Matches: address = "0.0.0.0:8200"
	addressPortRegex = regexp.MustCompile(`address\s*=\s*"[^:]*:(\d+)"`)

	// Matches: cluster_address = "0.0.0.0:8201"
	clusterPortRegex = regexp.MustCompile(`cluster_address\s*=\s*"[^:]*:(\d+)"`)

	// For updating: capture everything before port, then port can be replaced
	addressUpdateRegex = regexp.MustCompile(`(address\s*=\s*"[^:]*:)\d+(")`)
	clusterUpdateRegex = regexp.MustCompile(`(cluster_address\s*=\s*"[^:]*:)\d+(")`)
)

// VaultPorts represents the API and cluster ports
type VaultPorts struct {
	APIPort     int
	ClusterPort int
}

// ExtractPorts extracts API and cluster ports from Vault HCL configuration
func ExtractPorts(config string) (*VaultPorts, error) {
	ports := &VaultPorts{
		APIPort:     8200, // Default if not found
		ClusterPort: 8201, // Default if not found
	}

	// Extract API port
	if matches := addressPortRegex.FindStringSubmatch(config); len(matches) > 1 {
		port, err := strconv.Atoi(matches[1])
		if err != nil {
			return nil, fmt.Errorf("invalid API port in config: %s", matches[1])
		}
		ports.APIPort = port
	}

	// Extract cluster port
	if matches := clusterPortRegex.FindStringSubmatch(config); len(matches) > 1 {
		port, err := strconv.Atoi(matches[1])
		if err != nil {
			return nil, fmt.Errorf("invalid cluster port in config: %s", matches[1])
		}
		ports.ClusterPort = port
	}

	return ports, nil
}

// UpdateConfigPorts updates port numbers in Vault HCL configuration
// Pass 0 for ports that should not be changed
func UpdateConfigPorts(config string, apiPort, clusterPort int) string {
	result := config

	// Update API port if specified
	if apiPort > 0 {
		result = addressUpdateRegex.ReplaceAllString(result, fmt.Sprintf(`${1}%d${2}`, apiPort))
	}

	// Update cluster port if specified
	if clusterPort > 0 {
		result = clusterUpdateRegex.ReplaceAllString(result, fmt.Sprintf(`${1}%d${2}`, clusterPort))
	}

	return result
}

// ValidatePort validates that a port number is in the valid range
func ValidatePort(port int) error {
	if port < 1024 || port > 65535 {
		return fmt.Errorf("port %d out of valid range (1024-65535)", port)
	}
	return nil
}
