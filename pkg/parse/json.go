//pkg/parse/json.go

package parse

import (
	"encoding/json"
	"fmt"
)

const (
	// SECURITY: Maximum JSON size to prevent memory exhaustion attacks
	MaxJSONSize = 10 * 1024 * 1024 // 10MB limit
)

func ExtractJSONMap(input string) (map[string]interface{}, error) {
	// SECURITY: Check size before parsing to prevent large payload DoS
	if len(input) > MaxJSONSize {
		return nil, fmt.Errorf("JSON string too large: %d bytes (max %d)", len(input), MaxJSONSize)
	}

	m := make(map[string]interface{})
	err := json.Unmarshal([]byte(input), &m)
	return m, err
}
