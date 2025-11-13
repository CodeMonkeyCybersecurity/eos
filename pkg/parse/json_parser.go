// Package parse provides infrastructure implementations for parsing operations
package parse

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"

	"go.uber.org/zap"
)

// JSONParserImpl implements the JSONParser interface
type JSONParserImpl struct {
	logger *zap.Logger
}

// NewJSONParser creates a new JSON parser implementation
func NewJSONParser(logger *zap.Logger) *JSONParserImpl {
	return &JSONParserImpl{
		logger: logger,
	}
}

// Parse parses JSON string into a map
func (j *JSONParserImpl) Parse(ctx context.Context, input string) (map[string]interface{}, error) {
	// SECURITY: Check size before parsing to prevent large payload DoS
	if len(input) > MaxJSONSize {
		j.logger.Error("JSON string too large",
			zap.Int("size", len(input)),
			zap.Int("max_size", MaxJSONSize))
		return nil, fmt.Errorf("JSON string too large: %d bytes (max %d)", len(input), MaxJSONSize)
	}

	var result map[string]interface{}

	if err := json.Unmarshal([]byte(input), &result); err != nil {
		j.logger.Error("Failed to parse JSON", zap.Error(err), zap.String("input_preview", j.previewString(input)))
		return nil, fmt.Errorf("JSON parse error: %w", err)
	}

	return result, nil
}

// ParseArray parses JSON string into an array
func (j *JSONParserImpl) ParseArray(ctx context.Context, input string) ([]interface{}, error) {
	// SECURITY: Check size before parsing
	if len(input) > MaxJSONSize {
		j.logger.Error("JSON array too large",
			zap.Int("size", len(input)),
			zap.Int("max_size", MaxJSONSize))
		return nil, fmt.Errorf("JSON array too large: %d bytes (max %d)", len(input), MaxJSONSize)
	}

	var result []interface{}

	if err := json.Unmarshal([]byte(input), &result); err != nil {
		j.logger.Error("Failed to parse JSON array", zap.Error(err), zap.String("input_preview", j.previewString(input)))
		return nil, fmt.Errorf("JSON array parse error: %w", err)
	}

	return result, nil
}

// ParseToStruct parses JSON string into a struct
func (j *JSONParserImpl) ParseToStruct(ctx context.Context, input string, target interface{}) error {
	// SECURITY: Check size before parsing
	if len(input) > MaxJSONSize {
		j.logger.Error("JSON string too large for struct parsing",
			zap.Int("size", len(input)),
			zap.Int("max_size", MaxJSONSize))
		return fmt.Errorf("JSON string too large: %d bytes (max %d)", len(input), MaxJSONSize)
	}

	if err := json.Unmarshal([]byte(input), target); err != nil {
		j.logger.Error("Failed to parse JSON to struct", zap.Error(err), zap.String("input_preview", j.previewString(input)))
		return fmt.Errorf("JSON struct parse error: %w", err)
	}

	return nil
}

// Format formats data as JSON string
func (j *JSONParserImpl) Format(ctx context.Context, data interface{}, pretty bool) (string, error) {
	var result []byte
	var err error

	if pretty {
		result, err = json.MarshalIndent(data, "", "  ")
	} else {
		result, err = json.Marshal(data)
	}

	if err != nil {
		j.logger.Error("Failed to format JSON", zap.Error(err), zap.Bool("pretty", pretty))
		return "", fmt.Errorf("JSON format error: %w", err)
	}

	return string(result), nil
}

// Validate validates JSON against a schema (basic validation)
func (j *JSONParserImpl) Validate(ctx context.Context, input string, schema interface{}) error {
	// Basic JSON validation - just check if it's valid JSON
	var temp interface{}
	if err := json.Unmarshal([]byte(input), &temp); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}

	// TODO: Implement proper JSON schema validation using github.com/xeipuuv/gojsonschema
	j.logger.Info("JSON validation completed (basic validation only)")
	return nil
}

// ExtractPath extracts value from JSON using JSONPath (simplified implementation)
func (j *JSONParserImpl) ExtractPath(ctx context.Context, input string, jsonPath string) (interface{}, error) {
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(input), &data); err != nil {
		return nil, fmt.Errorf("failed to parse JSON for path extraction: %w", err)
	}

	// Simple path extraction - supports basic dot notation like "user.name"
	// For more complex JSONPath, would need to integrate a JSONPath library
	if jsonPath == "" || jsonPath == "." {
		return data, nil
	}

	// Remove leading dot if present
	path := jsonPath
	if path[0] == '.' {
		path = path[1:]
	}

	// Split path by dots
	keys := regexp.MustCompile(`\.`).Split(path, -1)

	current := interface{}(data)
	for _, key := range keys {
		if currentMap, ok := current.(map[string]interface{}); ok {
			if value, exists := currentMap[key]; exists {
				current = value
			} else {
				return nil, fmt.Errorf("path not found: %s", jsonPath)
			}
		} else {
			return nil, fmt.Errorf("cannot traverse path at key '%s': not a map", key)
		}
	}

	return current, nil
}

// previewString returns a preview of the input string for logging
func (j *JSONParserImpl) previewString(input string) string {
	const maxLen = 100
	if len(input) <= maxLen {
		return input
	}
	return input[:maxLen] + "..."
}
