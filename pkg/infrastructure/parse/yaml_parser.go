// Package parse provides infrastructure implementations for parsing operations
package parse

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// YAMLParserImpl implements the YAMLParser interface
type YAMLParserImpl struct {
	logger *zap.Logger
}

// NewYAMLParser creates a new YAML parser implementation
func NewYAMLParser(logger *zap.Logger) *YAMLParserImpl {
	return &YAMLParserImpl{
		logger: logger,
	}
}

// Parse parses YAML string into a map
func (y *YAMLParserImpl) Parse(ctx context.Context, input string) (map[string]interface{}, error) {
	var result map[string]interface{}
	
	if err := yaml.Unmarshal([]byte(input), &result); err != nil {
		y.logger.Error("Failed to parse YAML", zap.Error(err), zap.String("input_preview", y.previewString(input)))
		return nil, fmt.Errorf("YAML parse error: %w", err)
	}
	
	return result, nil
}

// ParseMultiDocument parses YAML string with multiple documents
func (y *YAMLParserImpl) ParseMultiDocument(ctx context.Context, input string) ([]map[string]interface{}, error) {
	decoder := yaml.NewDecoder(strings.NewReader(input))
	
	var documents []map[string]interface{}
	
	for {
		var doc map[string]interface{}
		err := decoder.Decode(&doc)
		
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			y.logger.Error("Failed to parse YAML document", zap.Error(err))
			return nil, fmt.Errorf("YAML multi-document parse error: %w", err)
		}
		
		if doc != nil {
			documents = append(documents, doc)
		}
	}
	
	return documents, nil
}

// ParseToStruct parses YAML string into a struct
func (y *YAMLParserImpl) ParseToStruct(ctx context.Context, input string, target interface{}) error {
	if err := yaml.Unmarshal([]byte(input), target); err != nil {
		y.logger.Error("Failed to parse YAML to struct", zap.Error(err), zap.String("input_preview", y.previewString(input)))
		return fmt.Errorf("YAML struct parse error: %w", err)
	}
	
	return nil
}

// Format formats data as YAML string
func (y *YAMLParserImpl) Format(ctx context.Context, data interface{}) (string, error) {
	result, err := yaml.Marshal(data)
	if err != nil {
		y.logger.Error("Failed to format YAML", zap.Error(err))
		return "", fmt.Errorf("YAML format error: %w", err)
	}
	
	return string(result), nil
}

// Validate validates YAML against a schema (basic validation)
func (y *YAMLParserImpl) Validate(ctx context.Context, input string, schema interface{}) error {
	// Basic YAML validation - just check if it's valid YAML
	var temp interface{}
	if err := yaml.Unmarshal([]byte(input), &temp); err != nil {
		return fmt.Errorf("invalid YAML: %w", err)
	}
	
	// TODO: Implement proper YAML schema validation
	y.logger.Info("YAML validation completed (basic validation only)")
	return nil
}

// ConvertToJSON converts YAML to JSON
func (y *YAMLParserImpl) ConvertToJSON(ctx context.Context, input string) (string, error) {
	// Parse YAML first
	var yamlData interface{}
	if err := yaml.Unmarshal([]byte(input), &yamlData); err != nil {
		return "", fmt.Errorf("failed to parse YAML for JSON conversion: %w", err)
	}
	
	// Convert to JSON
	jsonData, err := json.Marshal(yamlData)
	if err != nil {
		return "", fmt.Errorf("failed to convert YAML to JSON: %w", err)
	}
	
	return string(jsonData), nil
}

// previewString returns a preview of the input string for logging
func (y *YAMLParserImpl) previewString(input string) string {
	const maxLen = 100
	if len(input) <= maxLen {
		return input
	}
	return input[:maxLen] + "..."
}