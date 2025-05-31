// pkg/parse/yaml.go

package parse

import (
	"gopkg.in/yaml.v3"
)

func ExtractYAMLMap(input string) (map[string]interface{}, error) {
	m := make(map[string]interface{})
	err := yaml.Unmarshal([]byte(input), &m)
	return m, err
}