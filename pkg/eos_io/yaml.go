/* pkg/eos_io/yaml.go */

package eos_io

import (
	"context"
	"fmt"
	"os"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// WriteYAML writes data to a YAML file with structured logging
func WriteYAML(ctx context.Context, filePath string, in interface{}) error {
	logger := otelzap.Ctx(ctx)
	logger.Debug("📝 Writing YAML file", zap.String("path", filePath))

	data, err := yaml.Marshal(in)
	if err != nil {
		logger.Error("❌ Failed to marshal YAML", zap.Error(err))
		return fmt.Errorf("failed to marshal YAML: %w", err)
	}

	if err := os.WriteFile(filePath, data, 0644); err != nil {
		logger.Error("❌ Failed to write YAML file",
			zap.String("path", filePath),
			zap.Error(err))
		return fmt.Errorf("failed to write YAML file: %w", err)
	}

	logger.Debug("✅ YAML file written successfully",
		zap.String("path", filePath),
		zap.Int("size", len(data)))
	return nil
}

// ReadYAML reads a YAML file into the provided interface with structured logging
func ReadYAML(ctx context.Context, filePath string, out interface{}) error {
	logger := otelzap.Ctx(ctx)
	logger.Debug("📖 Reading YAML file", zap.String("path", filePath))

	data, err := os.ReadFile(filePath)
	if err != nil {
		logger.Error("❌ Failed to read YAML file",
			zap.String("path", filePath),
			zap.Error(err))
		return fmt.Errorf("failed to read YAML file: %w", err)
	}

	if err := yaml.Unmarshal(data, out); err != nil {
		logger.Error("❌ Failed to unmarshal YAML",
			zap.String("path", filePath),
			zap.Error(err))
		return fmt.Errorf("failed to unmarshal YAML: %w", err)
	}

	logger.Debug("✅ YAML file read successfully",
		zap.String("path", filePath),
		zap.Int("size", len(data)))
	return nil
}

// ParseYAMLString parses a YAML string into a map - consolidates parse/yaml.go functionality
func ParseYAMLString(ctx context.Context, input string) (map[string]interface{}, error) {
	logger := otelzap.Ctx(ctx)
	logger.Debug("🔄 Parsing YAML string", zap.Int("length", len(input)))

	m := make(map[string]interface{})
	if err := yaml.Unmarshal([]byte(input), &m); err != nil {
		logger.Error("❌ Failed to parse YAML string", zap.Error(err))
		return nil, fmt.Errorf("failed to parse YAML string: %w", err)
	}

	logger.Debug("✅ YAML string parsed successfully", zap.Int("keys", len(m)))
	return m, nil
}

// Backward compatibility functions (deprecated)

// WriteYAMLCompat provides backward compatibility without context
// DEPRECATED: Use WriteYAML with context
func WriteYAMLCompat(filePath string, in interface{}) error {
	return WriteYAML(context.Background(), filePath, in)
}

// ReadYAMLCompat provides backward compatibility without context
// DEPRECATED: Use ReadYAML with context
func ReadYAMLCompat(filePath string, out interface{}) error {
	return ReadYAML(context.Background(), filePath, out)
}
