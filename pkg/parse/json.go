//pkg/parse/json.go

package parse

import (
	"encoding/json"
)

func ExtractJSONMap(input string) (map[string]interface{}, error) {
	m := make(map[string]interface{})
	err := json.Unmarshal([]byte(input), &m)
	return m, err
}
