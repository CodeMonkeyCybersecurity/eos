// pkg/eosio/yaml.go

package eosio

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/flags"
	"gopkg.in/yaml.v3"
)

func WriteYAML(filePath string, in interface{}) error {
	data, err := yaml.Marshal(in)
	if err != nil {
		return fmt.Errorf("failed to marshal YAML: %w", err)
	}
	if flags.IsDryRun() {
		fmt.Printf("🧪 Dry run: would write to %s:\n%s\n", filePath, string(data))
		return nil
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
