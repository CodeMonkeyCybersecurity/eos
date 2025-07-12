// Package config provides infrastructure implementations for configuration management
package config

import (
	"context"
	"fmt"
	"reflect"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/domain/config"
	"go.uber.org/zap"
)

// SchemaValidator implements config.Validator
type SchemaValidator struct {
	logger *zap.Logger
}

// NewSchemaValidator creates a new schema validator
func NewSchemaValidator(logger *zap.Logger) config.Validator {
	return &SchemaValidator{
		logger: logger.Named("config.schema_validator"),
	}
}

// ValidateSchema validates data against a JSON schema
func (v *SchemaValidator) ValidateSchema(ctx context.Context, data interface{}, schema config.Schema) error {
	// Basic validation implementation
	// In a real implementation, you might use a proper JSON schema validator

	if err := v.ValidateRequired(ctx, data, schema.Required); err != nil {
		return err
	}

	v.logger.Debug("Schema validation completed",
		zap.String("version", schema.Version))

	return nil
}

// ValidateRequired ensures all required fields are present
func (v *SchemaValidator) ValidateRequired(ctx context.Context, data interface{}, required []string) error {
	dataMap, ok := data.(map[string]interface{})
	if !ok {
		return fmt.Errorf("data must be a map for required field validation")
	}

	for _, field := range required {
		if _, exists := dataMap[field]; !exists {
			return fmt.Errorf("required field missing: %s", field)
		}
	}

	v.logger.Debug("Required fields validation passed",
		zap.Strings("required", required))

	return nil
}

// ValidateTypes validates field types match expectations
func (v *SchemaValidator) ValidateTypes(ctx context.Context, data interface{}, types config.TypeMap) error {
	dataMap, ok := data.(map[string]interface{})
	if !ok {
		return fmt.Errorf("data must be a map for type validation")
	}

	for field, expectedType := range types {
		value, exists := dataMap[field]
		if !exists {
			continue // Skip validation for missing fields
		}

		if err := v.validateFieldType(field, value, expectedType); err != nil {
			return err
		}
	}

	v.logger.Debug("Type validation completed")

	return nil
}

// ValidateConstraints validates business rule constraints
func (v *SchemaValidator) ValidateConstraints(ctx context.Context, data interface{}, constraints []config.Constraint) error {
	dataMap, ok := data.(map[string]interface{})
	if !ok {
		return fmt.Errorf("data must be a map for constraint validation")
	}

	for _, constraint := range constraints {
		if err := v.validateConstraint(dataMap, constraint); err != nil {
			return err
		}
	}

	v.logger.Debug("Constraint validation completed",
		zap.Int("constraints", len(constraints)))

	return nil
}

// validateFieldType validates a single field type
func (v *SchemaValidator) validateFieldType(field string, value interface{}, expectedType config.DataType) error {
	actualType := reflect.TypeOf(value)
	if actualType == nil {
		return nil // nil values are allowed
	}

	switch expectedType {
	case config.TypeString:
		if actualType.Kind() != reflect.String {
			return fmt.Errorf("field %s: expected string, got %s", field, actualType.Kind())
		}
	case config.TypeInt:
		if actualType.Kind() != reflect.Int && actualType.Kind() != reflect.Int64 && actualType.Kind() != reflect.Float64 {
			return fmt.Errorf("field %s: expected integer, got %s", field, actualType.Kind())
		}
	case config.TypeFloat:
		if actualType.Kind() != reflect.Float32 && actualType.Kind() != reflect.Float64 {
			return fmt.Errorf("field %s: expected float, got %s", field, actualType.Kind())
		}
	case config.TypeBool:
		if actualType.Kind() != reflect.Bool {
			return fmt.Errorf("field %s: expected boolean, got %s", field, actualType.Kind())
		}
	case config.TypeArray:
		if actualType.Kind() != reflect.Slice && actualType.Kind() != reflect.Array {
			return fmt.Errorf("field %s: expected array, got %s", field, actualType.Kind())
		}
	case config.TypeObject:
		if actualType.Kind() != reflect.Map && actualType.Kind() != reflect.Struct {
			return fmt.Errorf("field %s: expected object, got %s", field, actualType.Kind())
		}
	}

	return nil
}

// validateConstraint validates a single constraint
func (v *SchemaValidator) validateConstraint(data map[string]interface{}, constraint config.Constraint) error {
	value, exists := data[constraint.Field]
	if !exists {
		return nil // Skip validation for missing fields
	}

	switch constraint.Operator {
	case config.OpEquals:
		if !reflect.DeepEqual(value, constraint.Value) {
			return fmt.Errorf("constraint failed: %s", constraint.Message)
		}
	case config.OpNotEquals:
		if reflect.DeepEqual(value, constraint.Value) {
			return fmt.Errorf("constraint failed: %s", constraint.Message)
		}
	// Add more operators as needed
	default:
		return fmt.Errorf("unsupported constraint operator: %s", constraint.Operator)
	}

	return nil
}
