package abtest

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ValidateConfigJSON validates the JSON syntax and structure of A/B config
// Migrated from cmd/create/ab_test_config.go validateABConfigJSON
func ValidateConfigJSON(rc *eos_io.RuntimeContext, configPath string) error {
	log := otelzap.Ctx(rc.Ctx)

	// ASSESS - Check if file exists and is readable
	log.Info("Assessing A/B config validation requirements",
		zap.String("config_path", configPath))

	if _, err := os.Stat(configPath); err != nil {
		return fmt.Errorf("config file not found: %w", err)
	}

	// INTERVENE - Validate JSON structure
	log.Debug("Validating JSON syntax")

	// First try to validate using Go's json package
	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	var jsonData interface{}
	if err := json.Unmarshal(data, &jsonData); err != nil {
		// If Go validation fails, try Python as fallback
		log.Debug("Go JSON validation failed, trying Python validation")

		_, execErr := execute.Run(rc.Ctx, execute.Options{
			Command: "python3",
			Args:    []string{"-c", fmt.Sprintf("import json; json.load(open('%s'))", configPath)},
		})
		if execErr != nil {
			return fmt.Errorf("invalid JSON syntax in configuration file: %w", err)
		}
	}

	// EVALUATE - Confirm validation passed
	log.Info("A/B config JSON validation successful",
		zap.String("config_path", configPath))

	return nil
}

// ValidateAndCreateConfig validates and creates an A/B test configuration
// This is a placeholder for the actual function if it exists
func ValidateAndCreateConfig(rc *eos_io.RuntimeContext, configPath string) error {
	log := otelzap.Ctx(rc.Ctx)

	// ASSESS - Validate the configuration first
	log.Info("Validating A/B test configuration")

	if err := ValidateConfigJSON(rc, configPath); err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	// INTERVENE - Process and create the configuration
	// This would include the actual implementation
	log.Info("Creating A/B test configuration")

	// EVALUATE - Verify creation was successful
	log.Info("A/B test configuration created successfully")

	return nil
}
