/* pkg/eos_io/yaml.go */

package eos_io

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

const (
	// SECURITY: Maximum YAML file size to prevent YAML bomb attacks
	MaxYAMLSize = 10 * 1024 * 1024 // 10MB limit
)

// WriteYAML writes data to a YAML file with structured logging
func WriteYAML(ctx context.Context, filePath string, in interface{}) error {
	logger := otelzap.Ctx(ctx)
	logger.Debug(" Writing YAML file", zap.String("path", filePath))

	data, err := yaml.Marshal(in)
	if err != nil {
		logger.Error(" Failed to marshal YAML", zap.Error(err))
		return fmt.Errorf("failed to marshal YAML: %w", err)
	}

	// SECURITY: Use 0640 instead of 0644 for config files (owner: rw, group: r, others: none)
	if err := os.WriteFile(filePath, data, shared.SecureConfigFilePerm); err != nil {
		logger.Error(" Failed to write YAML file",
			zap.String("path", filePath),
			zap.Error(err))
		return fmt.Errorf("failed to write YAML file: %w", err)
	}

	logger.Debug(" YAML file written successfully",
		zap.String("path", filePath),
		zap.Int("size", len(data)))
	return nil
}

// ReadYAML reads a YAML file into the provided interface with structured logging
func ReadYAML(ctx context.Context, filePath string, out interface{}) error {
	logger := otelzap.Ctx(ctx)
	logger.Debug(" Reading YAML file", zap.String("path", filePath))

	// SECURITY: Check file size before reading to prevent YAML bomb attacks
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		logger.Error(" Failed to stat YAML file",
			zap.String("path", filePath),
			zap.Error(err))
		return fmt.Errorf("failed to stat YAML file: %w", err)
	}

	if fileInfo.Size() > MaxYAMLSize {
		logger.Error(" YAML file too large",
			zap.String("path", filePath),
			zap.Int64("size", fileInfo.Size()),
			zap.Int64("max_size", MaxYAMLSize))
		return fmt.Errorf("YAML file too large: %d bytes (max %d)", fileInfo.Size(), MaxYAMLSize)
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		logger.Error(" Failed to read YAML file",
			zap.String("path", filePath),
			zap.Error(err))
		return fmt.Errorf("failed to read YAML file: %w", err)
	}

	// SECURITY: Use strict YAML decoder with KnownFields to reject unknown fields
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	// Note: KnownFields(true) would reject unknown fields, but this breaks compatibility
	// with existing configs. Consider enabling in future major version.

	if err := decoder.Decode(out); err != nil {
		logger.Error(" Failed to unmarshal YAML",
			zap.String("path", filePath),
			zap.Error(err))
		return fmt.Errorf("failed to unmarshal YAML: %w", err)
	}

	logger.Debug(" YAML file read successfully",
		zap.String("path", filePath),
		zap.Int("size", len(data)))
	return nil
}

// ParseYAMLString parses a YAML string into a map - consolidates parse/yaml.go functionality
func ParseYAMLString(ctx context.Context, input string) (map[string]interface{}, error) {
	logger := otelzap.Ctx(ctx)
	logger.Debug(" Parsing YAML string", zap.Int("length", len(input)))

	// SECURITY: Check size before parsing to prevent YAML bomb attacks
	if len(input) > MaxYAMLSize {
		logger.Error(" YAML string too large",
			zap.Int("size", len(input)),
			zap.Int("max_size", MaxYAMLSize))
		return nil, fmt.Errorf("YAML string too large: %d bytes (max %d)", len(input), MaxYAMLSize)
	}

	m := make(map[string]interface{})
	decoder := yaml.NewDecoder(strings.NewReader(input))
	// Note: KnownFields(true) would reject unknown fields, but this breaks compatibility

	if err := decoder.Decode(&m); err != nil {
		logger.Error(" Failed to parse YAML string", zap.Error(err))
		return nil, fmt.Errorf("failed to parse YAML string: %w", err)
	}

	logger.Debug(" YAML string parsed successfully", zap.Int("keys", len(m)))
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
