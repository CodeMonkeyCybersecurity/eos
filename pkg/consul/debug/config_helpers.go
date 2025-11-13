package debug

import (
	"fmt"
	"os"
	"regexp"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

// extractConfigValue extracts a single configuration value from HCL config
// Example: bind_addr = "192.168.1.1" -> returns "192.168.1.1"
func extractConfigValue(config, key string) string {
	// Look for pattern: key = "value" or key = 'value'
	patterns := []string{
		fmt.Sprintf(`%s\s*=\s*"([^"]*)"`, key),
		fmt.Sprintf(`%s\s*=\s*'([^']*)'`, key),
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(config)
		if len(matches) > 1 {
			return matches[1]
		}
	}

	return ""
}

// extractConfigArray extracts array values from HCL config
// Example: retry_join = ["node1", "node2"] -> returns []string{"node1", "node2"}
func extractConfigArray(config, key string) []string {
	// Look for pattern: key = [ "val1", "val2", ... ]
	pattern := fmt.Sprintf(`%s\s*=\s*\[(.*?)\]`, key)
	re := regexp.MustCompile(pattern)
	matches := re.FindStringSubmatch(config)

	if len(matches) < 2 {
		return nil
	}

	// Extract quoted values from the array
	arrayContent := matches[1]
	valuePattern := regexp.MustCompile(`"([^"]*)"`)
	valueMatches := valuePattern.FindAllStringSubmatch(arrayContent, -1)

	result := []string{}
	for _, match := range valueMatches {
		if len(match) > 1 {
			result = append(result, match[1])
		}
	}

	return result
}

// extractRetryJoinFromConfig reads the Consul config and extracts retry_join addresses
func extractRetryJoinFromConfig(rc *eos_io.RuntimeContext) []string {
	configPath := "/etc/consul.d/consul.hcl"

	// Read configuration
	content, err := os.ReadFile(configPath)
	if err != nil {
		return nil
	}

	return extractConfigArray(string(content), "retry_join")
}
