// pkg/apiclient/validation.go
// Type validation for API parameters and fields
//
// VALIDATES:
//   - UUIDs (RFC 4122 format)
//   - Email addresses (RFC 5322 format)
//   - Booleans (true/false, 1/0, yes/no)
//   - Integers, floats
//   - Enums (must be in allowed values list)
//   - JSON (valid JSON syntax)
//
// ERROR MESSAGES: Include remediation steps and examples

package apiclient

import (
	"encoding/json"
	"fmt"
	"net/mail"
	"regexp"
	"strconv"
	"strings"
)

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Parameter/Field Validation
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// ValidateValue validates a value against a parameter type
// Returns error with remediation if validation fails
//
// Parameters:
//   - value: Value to validate (string representation)
//   - paramType: Expected parameter type (uuid, email, boolean, etc.)
//   - allowedValues: Allowed values for enum types (optional)
//
// Example:
//
//	err := ValidateValue("123e4567-e89b-12d3-a456-426614174000", ParameterTypeUUID, nil)
//	if err != nil {
//	    return fmt.Errorf("invalid UUID: %w", err)
//	}
func ValidateValue(value interface{}, paramType ParameterType, allowedValues []string) error {
	// Convert value to string for validation
	var str string
	switch v := value.(type) {
	case string:
		str = v
	case int, int64, float64:
		str = fmt.Sprintf("%v", v)
	case bool:
		str = fmt.Sprintf("%v", v)
	default:
		// JSON type - validate as-is
		if paramType == ParameterTypeJSON {
			return validateJSON(value)
		}
		str = fmt.Sprintf("%v", v)
	}

	switch paramType {
	case ParameterTypeString, ParameterTypePassword:
		return nil // Strings always valid (no format requirements)

	case ParameterTypeUUID:
		return validateUUID(str)

	case ParameterTypeEmail:
		return validateEmail(str)

	case ParameterTypeBoolean:
		return validateBoolean(str)

	case ParameterTypeInteger:
		return validateInteger(str)

	case ParameterTypeFloat:
		return validateFloat(str)

	case ParameterTypeEnum:
		return validateEnum(str, allowedValues)

	case ParameterTypeJSON:
		return validateJSON(value)

	default:
		return fmt.Errorf("unknown parameter type: %s", paramType)
	}
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Type-Specific Validators
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

var uuidRegex = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// validateUUID validates a UUID (RFC 4122 format)
// Accepts: "123e4567-e89b-12d3-a456-426614174000"
// Rejects: "not-a-uuid", "123", ""
func validateUUID(value string) error {
	if value == "" {
		return fmt.Errorf("UUID cannot be empty\n" +
			"Format: 8-4-4-4-12 hexadecimal digits\n" +
			"Example: 123e4567-e89b-12d3-a456-426614174000")
	}

	// Normalize to lowercase for regex matching
	normalized := strings.ToLower(value)

	if !uuidRegex.MatchString(normalized) {
		return fmt.Errorf("invalid UUID format: %s\n"+
			"Format: 8-4-4-4-12 hexadecimal digits\n"+
			"Example: 123e4567-e89b-12d3-a456-426614174000",
			value)
	}

	return nil
}

// validateEmail validates an email address (RFC 5322 format)
// Uses Go's net/mail parser for correctness
func validateEmail(value string) error {
	if value == "" {
		return fmt.Errorf("email cannot be empty\n" +
			"Format: user@example.com")
	}

	_, err := mail.ParseAddress(value)
	if err != nil {
		return fmt.Errorf("invalid email address: %s\n"+
			"Format: user@example.com\n"+
			"Error: %v",
			value, err)
	}

	return nil
}

// validateBoolean validates a boolean value
// Accepts: "true", "false", "1", "0", "yes", "no", "t", "f", "y", "n" (case-insensitive)
// Rejects: "maybe", "123", ""
func validateBoolean(value string) error {
	if value == "" {
		return fmt.Errorf("boolean cannot be empty\n" +
			"Accepted values: true, false, 1, 0, yes, no")
	}

	normalized := strings.ToLower(strings.TrimSpace(value))

	validBooleans := map[string]bool{
		"true":  true,
		"false": true,
		"1":     true,
		"0":     true,
		"yes":   true,
		"no":    true,
		"t":     true,
		"f":     true,
		"y":     true,
		"n":     true,
	}

	if !validBooleans[normalized] {
		return fmt.Errorf("invalid boolean value: %s\n"+
			"Accepted values: true, false, 1, 0, yes, no",
			value)
	}

	return nil
}

// validateInteger validates an integer value
func validateInteger(value string) error {
	if value == "" {
		return fmt.Errorf("integer cannot be empty\n" +
			"Format: whole number (e.g., 42, -10, 0)")
	}

	_, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid integer: %s\n"+
			"Format: whole number (e.g., 42, -10, 0)\n"+
			"Error: %v",
			value, err)
	}

	return nil
}

// validateFloat validates a floating-point value
func validateFloat(value string) error {
	if value == "" {
		return fmt.Errorf("float cannot be empty\n" +
			"Format: number with decimal (e.g., 3.14, -0.5, 42.0)")
	}

	_, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return fmt.Errorf("invalid float: %s\n"+
			"Format: number with decimal (e.g., 3.14, -0.5, 42.0)\n"+
			"Error: %v",
			value, err)
	}

	return nil
}

// validateEnum validates an enum value against allowed values list
func validateEnum(value string, allowedValues []string) error {
	if value == "" {
		return fmt.Errorf("enum value cannot be empty\n" +
			"Allowed values: %s",
			strings.Join(allowedValues, ", "))
	}

	if len(allowedValues) == 0 {
		return fmt.Errorf("enum validation failed: no allowed values defined")
	}

	// Check if value is in allowed list
	for _, allowed := range allowedValues {
		if value == allowed {
			return nil
		}
	}

	return fmt.Errorf("invalid enum value: %s\n"+
		"Allowed values: %s",
		value, strings.Join(allowedValues, ", "))
}

// validateJSON validates JSON syntax
func validateJSON(value interface{}) error {
	// If already a struct/map, it's valid
	switch value.(type) {
	case map[string]interface{}, []interface{}:
		return nil
	}

	// If string, try to parse as JSON
	str, ok := value.(string)
	if !ok {
		return fmt.Errorf("JSON value must be string, map, or array")
	}

	if str == "" {
		return fmt.Errorf("JSON cannot be empty")
	}

	var js interface{}
	if err := json.Unmarshal([]byte(str), &js); err != nil {
		return fmt.Errorf("invalid JSON syntax: %v\n"+
			"Example: {\"key\": \"value\"} or [\"item1\", \"item2\"]",
			err)
	}

	return nil
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Conversion Helpers (string → typed value)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// ConvertToTypedValue converts a string value to its typed representation
// Used for building API request bodies with correct types
//
// Example:
//
//	// Convert "true" string to bool true
//	typed, err := ConvertToTypedValue("true", ParameterTypeBoolean, nil)
//	// typed == true (bool)
func ConvertToTypedValue(value string, paramType ParameterType, allowedValues []string) (interface{}, error) {
	// Validate first
	if err := ValidateValue(value, paramType, allowedValues); err != nil {
		return nil, err
	}

	switch paramType {
	case ParameterTypeString, ParameterTypeEmail, ParameterTypeUUID, ParameterTypePassword, ParameterTypeEnum:
		return value, nil

	case ParameterTypeBoolean:
		return parseBoolean(value), nil

	case ParameterTypeInteger:
		i, _ := strconv.ParseInt(value, 10, 64)
		return i, nil

	case ParameterTypeFloat:
		f, _ := strconv.ParseFloat(value, 64)
		return f, nil

	case ParameterTypeJSON:
		var js interface{}
		_ = json.Unmarshal([]byte(value), &js)
		return js, nil

	default:
		return value, nil
	}
}

// parseBoolean converts string to bool (after validation)
func parseBoolean(value string) bool {
	normalized := strings.ToLower(strings.TrimSpace(value))
	return normalized == "true" || normalized == "1" || normalized == "yes" || normalized == "t" || normalized == "y"
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Batch Validation (for multiple parameters)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// ValidateParameters validates a map of parameters against their definitions
// Returns map of validation errors (key = parameter name, value = error)
//
// Example:
//
//	params := map[string]interface{}{
//	    "pk": "invalid-uuid",
//	    "is_active": "maybe",
//	}
//	definitions := map[string]Parameter{
//	    "pk": {Type: ParameterTypeUUID},
//	    "is_active": {Type: ParameterTypeBoolean},
//	}
//	errors := ValidateParameters(params, definitions)
//	// errors["pk"] = "invalid UUID format: invalid-uuid"
//	// errors["is_active"] = "invalid boolean value: maybe"
func ValidateParameters(params map[string]interface{}, definitions []Parameter) map[string]error {
	errors := make(map[string]error)

	// Create lookup map for definitions
	defMap := make(map[string]Parameter)
	for _, def := range definitions {
		defMap[def.Name] = def
	}

	// Validate each parameter
	for name, value := range params {
		def, ok := defMap[name]
		if !ok {
			// Unknown parameter - skip (API might accept it)
			continue
		}

		if err := ValidateValue(value, def.Type, def.Values); err != nil {
			errors[name] = err
		}
	}

	// Check for required parameters
	for _, def := range definitions {
		if def.Required {
			if _, ok := params[def.Name]; !ok {
				errors[def.Name] = fmt.Errorf("required parameter missing: %s\n"+
					"Description: %s",
					def.Name, def.Description)
			}
		}
	}

	return errors
}

// ValidateFields validates a map of fields against their definitions
// Same as ValidateParameters but for request body fields (POST/PATCH/PUT)
func ValidateFields(fields map[string]interface{}, definitions []Field) map[string]error {
	errors := make(map[string]error)

	// Create lookup map for definitions
	defMap := make(map[string]Field)
	for _, def := range definitions {
		defMap[def.Name] = def
	}

	// Validate each field
	for name, value := range fields {
		def, ok := defMap[name]
		if !ok {
			// Unknown field - skip (API might accept it)
			continue
		}

		if err := ValidateValue(value, def.Type, def.Values); err != nil {
			errors[name] = err
		}
	}

	// Check for required fields
	for _, def := range definitions {
		if def.Required {
			if _, ok := fields[def.Name]; !ok {
				errors[def.Name] = fmt.Errorf("required field missing: %s\n"+
					"Description: %s",
					def.Name, def.Description)
			}
		}
	}

	return errors
}
