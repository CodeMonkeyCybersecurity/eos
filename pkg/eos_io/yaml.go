/* pkg/eos_io/yaml.go */

package eos_io

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

func WriteYAML(filePath string, in interface{}) error {
	data, err := yaml.Marshal(in)
	if err != nil {
		return fmt.Errorf("failed to marshal YAML: %w", err)
	}
	return os.WriteFile(filePath, data, 0644)
}

func ReadYAML(filePath string, out interface{}) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read YAML file: %w", err)
	}
	return yaml.Unmarshal(data, out)
}
