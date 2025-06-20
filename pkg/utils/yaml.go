// pkg/utils/yaml.go
// DEPRECATED: This file contains duplicate YAML functionality.
// Use pkg/eos_io/yaml.go for YAML operations instead.

package utils

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

//
//---------------------------- YAML ---------------------------- //
//

// ProcessMap recursively processes and formats nested YAML structures for display
// DEPRECATED: Use structured logging or pkg/eos_io for YAML operations
func ProcessMap(ctx context.Context, data map[string]interface{}, indent string) string {
	logger := otelzap.Ctx(ctx)
	logger.Debug("🔄 Processing YAML map structure", 
		zap.Int("keys", len(data)),
		zap.String("indent", indent))
	
	var result strings.Builder
	
	for key, value := range data {
		switch v := value.(type) {
		case map[string]interface{}:
			result.WriteString(fmt.Sprintf("%s%s:\n", indent, key))
			result.WriteString(ProcessMap(ctx, v, indent+"  "))
		case []interface{}:
			result.WriteString(fmt.Sprintf("%s%s:\n", indent, key))
			for _, item := range v {
				if itemMap, ok := item.(map[string]interface{}); ok {
					result.WriteString(ProcessMap(ctx, itemMap, indent+"  "))
				} else {
					result.WriteString(fmt.Sprintf("%s  - %v\n", indent, item))
				}
			}
		default:
			result.WriteString(fmt.Sprintf("%s%s: %v\n", indent, key, v))
		}
	}
	
	return result.String()
}

// PrintProcessedMap displays the processed YAML structure to stderr
func PrintProcessedMap(ctx context.Context, data map[string]interface{}, indent string) {
	logger := otelzap.Ctx(ctx)
	logger.Info("📋 Displaying YAML structure")
	
	output := ProcessMap(ctx, data, indent)
	_, _ = fmt.Fprint(os.Stderr, output)
	
	logger.Debug("✅ YAML structure displayed", zap.Int("output_length", len(output)))
}
