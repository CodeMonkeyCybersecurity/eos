// Package display provides shared output formatting utilities for Eos commands.
package display

import (
	"encoding/json"
	"fmt"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// OutputJSON formats and outputs data as JSON to the terminal via logger.
// This is the standard way to output JSON data in Eos commands.
func OutputJSON(logger otelzap.LoggerWithCtx, data interface{}) error {
	output, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	logger.Info("terminal prompt:", zap.String("output", string(output)))
	return nil
}

// OutputYAML formats and outputs data as YAML-style output to the terminal via logger.
// Currently uses JSON marshaling as a simplified YAML representation.
// TODO: Consider using a proper YAML library if stricter YAML formatting is needed.
func OutputYAML(logger otelzap.LoggerWithCtx, data interface{}) error {
	// Simplified YAML output using JSON for now
	// Future: Import "gopkg.in/yaml.v3" for proper YAML formatting
	output, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}
	logger.Info("terminal prompt:", zap.String("output", string(output)))
	return nil
}
