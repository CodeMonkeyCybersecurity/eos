// Package config provides infrastructure implementations for configuration management
package config

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// MultiFormatParser implements Parser supporting multiple formats
type MultiFormatParser struct {
	logger *zap.Logger
}

// NewMultiFormatParser creates a new multi-format parser
func NewMultiFormatParser(logger *zap.Logger) *MultiFormatParser {
	return &MultiFormatParser{
		logger: logger.Named("multi_format_parser"),
	}
}

// Parse parses raw bytes into a generic structure
func (p *MultiFormatParser) Parse(ctx context.Context, data []byte, format Format) (map[string]interface{}, error) {
	var result map[string]interface{}

	switch format {
	case FormatJSON:
		if err := json.Unmarshal(data, &result); err != nil {
			return nil, fmt.Errorf("failed to parse JSON: %w", err)
		}
	case FormatYAML:
		if err := yaml.Unmarshal(data, &result); err != nil {
			return nil, fmt.Errorf("failed to parse YAML: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported format: %s", format)
	}

	p.logger.Debug("Config parsed successfully",
		zap.String("format", string(format)),
		zap.Int("size", len(data)))

	return result, nil
}

// Marshal converts a structure into formatted bytes
func (p *MultiFormatParser) Marshal(ctx context.Context, v interface{}, format Format) ([]byte, error) {
	var data []byte
	var err error

	switch format {
	case FormatJSON:
		data, err = json.MarshalIndent(v, "", "  ")
	case FormatYAML:
		data, err = yaml.Marshal(v)
	default:
		return nil, fmt.Errorf("unsupported format: %s", format)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to marshal %s: %w", format, err)
	}

	p.logger.Debug("Config marshaled successfully",
		zap.String("format", string(format)),
		zap.Int("size", len(data)))

	return data, nil
}

// DetectFormat attempts to detect the format of configuration data
func (p *MultiFormatParser) DetectFormat(ctx context.Context, data []byte, hint string) (Format, error) {
	// First try hint based on file extension
	if hint != "" {
		ext := strings.ToLower(filepath.Ext(hint))
		switch ext {
		case ".json":
			return FormatJSON, nil
		case ".yaml", ".yml":
			return FormatYAML, nil
		}
	}

	// Try to detect from content
	// First try JSON
	var jsonTest interface{}
	if json.Unmarshal(data, &jsonTest) == nil {
		return FormatJSON, nil
	}

	// Then try YAML
	var yamlTest interface{}
	if yaml.Unmarshal(data, &yamlTest) == nil {
		return FormatYAML, nil
	}

	return "", fmt.Errorf("unable to detect format")
}

// Unmarshal parses bytes directly into a target structure
func (p *MultiFormatParser) Unmarshal(ctx context.Context, data []byte, format Format, target interface{}) error {
	switch format {
	case FormatJSON:
		if err := json.Unmarshal(data, target); err != nil {
			return fmt.Errorf("failed to unmarshal JSON: %w", err)
		}
	case FormatYAML:
		if err := yaml.Unmarshal(data, target); err != nil {
			return fmt.Errorf("failed to unmarshal YAML: %w", err)
		}
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}

	p.logger.Debug("Config unmarshaled successfully",
		zap.String("format", string(format)))

	return nil
}
