// pkg/parse/yaml.go
// DEPRECATED: This functionality has been consolidated into pkg/eos_io/yaml.go
// Use eos_io.ParseYAMLString() instead

package parse

import (
	"context"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"gopkg.in/yaml.v3"
)

// ExtractYAMLMap extracts a YAML string into a map
// DEPRECATED: Use eos_io.ParseYAMLString() for new code
func ExtractYAMLMap(input string) (map[string]interface{}, error) {
	m := make(map[string]interface{})
	err := yaml.Unmarshal([]byte(input), &m)
	return m, err
}

// ExtractYAMLMapWithContext extracts a YAML string into a map with context support
// DEPRECATED: Use eos_io.ParseYAMLString() for new code
func ExtractYAMLMapWithContext(ctx context.Context, input string) (map[string]interface{}, error) {
	return eos_io.ParseYAMLString(ctx, input)
}
