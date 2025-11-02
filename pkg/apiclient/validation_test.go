// pkg/apiclient/validation_test.go
// Comprehensive unit tests for type validation
//
// COVERAGE: UUID, email, boolean, integer, float, enum, JSON validation
// PATTERNS: Table-driven tests with valid/invalid cases
// SECURITY: Tests injection prevention, malformed input handling

package apiclient

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Test: UUID Validation
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

func TestValidateValue_UUID(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		// Valid UUIDs
		{"valid UUID v4", "123e4567-e89b-12d3-a456-426614174000", false},
		{"valid UUID lowercase", "550e8400-e29b-41d4-a716-446655440000", false},
		{"valid UUID uppercase", "550E8400-E29B-41D4-A716-446655440000", false},
		{"valid UUID mixed case", "550e8400-E29B-41d4-A716-446655440000", false},

		// Invalid UUIDs
		{"empty string", "", true},
		{"too short", "123e4567", true},
		{"too long", "123e4567-e89b-12d3-a456-426614174000-extra", true},
		{"wrong format", "not-a-uuid", true},
		{"missing hyphens", "123e4567e89b12d3a456426614174000", true},
		{"wrong hyphen positions", "123e4567-e89b-12-d3a456-426614174000", true},
		{"non-hex characters", "123e4567-e89g-12d3-a456-426614174000", true},

		// Security: Injection attempts
		{"SQL injection", "'; DROP TABLE users--", true},
		{"path traversal", "../../../etc/passwd", true},
		{"XSS attempt", "<script>alert('xss')</script>", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateValue(tt.value, ParameterTypeUUID, nil)
			if tt.wantErr {
				assert.Error(t, err, "Expected error for: %s", tt.value)
			} else {
				assert.NoError(t, err, "Expected no error for: %s", tt.value)
			}
		})
	}
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Test: Email Validation
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

func TestValidateValue_Email(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		// Valid emails (RFC 5322)
		{"simple email", "user@example.com", false},
		{"email with subdomain", "user@mail.example.com", false},
		{"email with plus", "user+tag@example.com", false},
		{"email with dots", "first.last@example.com", false},
		{"email with numbers", "user123@example.com", false},

		// Invalid emails
		{"empty string", "", true},
		{"no @", "userexample.com", true},
		{"multiple @", "user@@example.com", true},
		{"no domain", "user@", true},
		{"no user", "@example.com", true},
		{"spaces", "user @example.com", true},
		{"missing TLD", "user@example", true}, // Note: This might pass depending on net/mail parser

		// Security: Injection attempts
		{"SQL injection", "user'; DROP TABLE users--@example.com", true},
		{"command injection", "user`whoami`@example.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateValue(tt.value, ParameterTypeEmail, nil)
			if tt.wantErr {
				assert.Error(t, err, "Expected error for: %s", tt.value)
			} else {
				assert.NoError(t, err, "Expected no error for: %s", tt.value)
			}
		})
	}
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Test: Boolean Validation
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

func TestValidateValue_Boolean(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		// Valid boolean values (human-friendly)
		{"true lowercase", "true", false},
		{"true uppercase", "TRUE", false},
		{"true mixed", "True", false},
		{"false lowercase", "false", false},
		{"false uppercase", "FALSE", false},
		{"1 as true", "1", false},
		{"0 as false", "0", false},
		{"yes", "yes", false},
		{"no", "no", false},
		{"y", "y", false},
		{"n", "n", false},
		{"t", "t", false},
		{"f", "f", false},

		// Invalid boolean values
		{"empty string", "", true},
		{"invalid word", "maybe", true},
		{"number", "2", true},
		{"negative", "-1", true},
		{"decimal", "1.0", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateValue(tt.value, ParameterTypeBoolean, nil)
			if tt.wantErr {
				assert.Error(t, err, "Expected error for: %s", tt.value)
			} else {
				assert.NoError(t, err, "Expected no error for: %s", tt.value)
			}
		})
	}
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Test: Integer Validation
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

func TestValidateValue_Integer(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		// Valid integers
		{"zero", "0", false},
		{"positive", "42", false},
		{"negative", "-42", false},
		{"large number", "999999999", false},

		// Invalid integers
		{"empty string", "", true},
		{"decimal", "42.5", true},
		{"text", "not a number", true},
		{"hex", "0x2A", true},
		{"scientific notation", "1e5", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateValue(tt.value, ParameterTypeInteger, nil)
			if tt.wantErr {
				assert.Error(t, err, "Expected error for: %s", tt.value)
			} else {
				assert.NoError(t, err, "Expected no error for: %s", tt.value)
			}
		})
	}
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Test: Float Validation
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

func TestValidateValue_Float(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		// Valid floats
		{"zero", "0.0", false},
		{"positive decimal", "3.14", false},
		{"negative decimal", "-2.5", false},
		{"integer as float", "42", false},
		{"scientific notation", "1.5e10", false},
		{"negative scientific", "-2.5e-3", false},

		// Invalid floats
		{"empty string", "", true},
		{"text", "not a number", true},
		{"multiple dots", "3.14.15", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateValue(tt.value, ParameterTypeFloat, nil)
			if tt.wantErr {
				assert.Error(t, err, "Expected error for: %s", tt.value)
			} else {
				assert.NoError(t, err, "Expected no error for: %s", tt.value)
			}
		})
	}
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Test: Enum Validation
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

func TestValidateValue_Enum(t *testing.T) {
	allowedValues := []string{"internal", "external", "service_account"}

	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		// Valid enum values
		{"first value", "internal", false},
		{"second value", "external", false},
		{"third value", "service_account", false},

		// Invalid enum values
		{"empty string", "", true},
		{"not in list", "admin", true},
		{"case mismatch", "Internal", true}, // Enum is case-sensitive
		{"partial match", "intern", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateValue(tt.value, ParameterTypeEnum, allowedValues)
			if tt.wantErr {
				assert.Error(t, err, "Expected error for: %s", tt.value)
			} else {
				assert.NoError(t, err, "Expected no error for: %s", tt.value)
			}
		})
	}
}

func TestValidateValue_Enum_EmptyList(t *testing.T) {
	// Edge case: empty allowed values list
	err := ValidateValue("anything", ParameterTypeEnum, []string{})
	assert.Error(t, err, "Should error when allowed values list is empty")
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Test: JSON Validation
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

func TestValidateValue_JSON(t *testing.T) {
	tests := []struct {
		name    string
		value   interface{}
		wantErr bool
	}{
		// Valid JSON
		{"object as map", map[string]interface{}{"key": "value"}, false},
		{"array as slice", []interface{}{1, 2, 3}, false},
		{"json string object", `{"key": "value"}`, false},
		{"json string array", `[1, 2, 3]`, false},
		{"nested json", `{"outer": {"inner": "value"}}`, false},

		// Invalid JSON
		{"empty string", "", true},
		{"invalid json string", `{key: value}`, true}, // Missing quotes
		{"unclosed object", `{"key": "value"`, true},
		{"unclosed array", `[1, 2, 3`, true},
		{"plain text", "not json", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateValue(tt.value, ParameterTypeJSON, nil)
			if tt.wantErr {
				assert.Error(t, err, "Expected error for: %v", tt.value)
			} else {
				assert.NoError(t, err, "Expected no error for: %v", tt.value)
			}
		})
	}
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Test: Type Conversion
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

func TestConvertToTypedValue(t *testing.T) {
	tests := []struct {
		name          string
		value         string
		paramType     ParameterType
		allowedValues []string
		expected      interface{}
		wantErr       bool
	}{
		// String types (no conversion)
		{"string remains string", "hello", ParameterTypeString, nil, "hello", false},
		{"uuid remains string", "123e4567-e89b-12d3-a456-426614174000", ParameterTypeUUID, nil, "123e4567-e89b-12d3-a456-426614174000", false},
		{"email remains string", "user@example.com", ParameterTypeEmail, nil, "user@example.com", false},

		// Boolean conversion
		{"true to bool", "true", ParameterTypeBoolean, nil, true, false},
		{"false to bool", "false", ParameterTypeBoolean, nil, false, false},
		{"1 to bool", "1", ParameterTypeBoolean, nil, true, false},
		{"0 to bool", "0", ParameterTypeBoolean, nil, false, false},
		{"yes to bool", "yes", ParameterTypeBoolean, nil, true, false},
		{"no to bool", "no", ParameterTypeBoolean, nil, false, false},

		// Integer conversion
		{"string to int", "42", ParameterTypeInteger, nil, int64(42), false},
		{"negative to int", "-10", ParameterTypeInteger, nil, int64(-10), false},

		// Float conversion
		{"string to float", "3.14", ParameterTypeFloat, nil, 3.14, false},
		{"int to float", "42", ParameterTypeFloat, nil, 42.0, false},

		// Enum (no conversion)
		{"enum remains string", "internal", ParameterTypeEnum, []string{"internal", "external"}, "internal", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ConvertToTypedValue(tt.value, tt.paramType, tt.allowedValues)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result, "Type: %T, Value: %v", result, result)
			}
		})
	}
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Test: Batch Validation
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

func TestValidateParameters(t *testing.T) {
	tests := []struct {
		name        string
		params      map[string]interface{}
		definitions []Parameter
		expectError bool
		errorFields []string
	}{
		{
			name: "all valid parameters",
			params: map[string]interface{}{
				"pk":        "123e4567-e89b-12d3-a456-426614174000",
				"is_active": "true",
			},
			definitions: []Parameter{
				{Name: "pk", Type: ParameterTypeUUID, Required: true},
				{Name: "is_active", Type: ParameterTypeBoolean, Required: false},
			},
			expectError: false,
		},
		{
			name: "missing required parameter",
			params: map[string]interface{}{
				"is_active": "true",
			},
			definitions: []Parameter{
				{Name: "pk", Type: ParameterTypeUUID, Required: true},
				{Name: "is_active", Type: ParameterTypeBoolean, Required: false},
			},
			expectError: true,
			errorFields: []string{"pk"},
		},
		{
			name: "invalid parameter type",
			params: map[string]interface{}{
				"pk":        "not-a-uuid",
				"is_active": "true",
			},
			definitions: []Parameter{
				{Name: "pk", Type: ParameterTypeUUID, Required: true},
				{Name: "is_active", Type: ParameterTypeBoolean, Required: false},
			},
			expectError: true,
			errorFields: []string{"pk"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := ValidateParameters(tt.params, tt.definitions)
			if tt.expectError {
				assert.NotEmpty(t, errors, "Expected validation errors")
				for _, field := range tt.errorFields {
					assert.Contains(t, errors, field, "Expected error for field: %s", field)
				}
			} else {
				assert.Empty(t, errors, "Expected no validation errors")
			}
		})
	}
}

func TestValidateFields(t *testing.T) {
	tests := []struct {
		name        string
		fields      map[string]interface{}
		definitions []Field
		expectError bool
		errorFields []string
	}{
		{
			name: "all valid fields",
			fields: map[string]interface{}{
				"username": "alice",
				"email":    "alice@example.com",
				"type":     "external",
			},
			definitions: []Field{
				{Name: "username", Type: ParameterTypeString, Required: true},
				{Name: "email", Type: ParameterTypeEmail, Required: true},
				{Name: "type", Type: ParameterTypeEnum, Values: []string{"internal", "external"}, Required: false},
			},
			expectError: false,
		},
		{
			name: "missing required field",
			fields: map[string]interface{}{
				"username": "alice",
			},
			definitions: []Field{
				{Name: "username", Type: ParameterTypeString, Required: true},
				{Name: "email", Type: ParameterTypeEmail, Required: true},
			},
			expectError: true,
			errorFields: []string{"email"},
		},
		{
			name: "invalid field type",
			fields: map[string]interface{}{
				"username": "alice",
				"email":    "not-an-email",
			},
			definitions: []Field{
				{Name: "username", Type: ParameterTypeString, Required: true},
				{Name: "email", Type: ParameterTypeEmail, Required: true},
			},
			expectError: true,
			errorFields: []string{"email"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := ValidateFields(tt.fields, tt.definitions)
			if tt.expectError {
				assert.NotEmpty(t, errors, "Expected validation errors")
				for _, field := range tt.errorFields {
					assert.Contains(t, errors, field, "Expected error for field: %s", field)
				}
			} else {
				assert.Empty(t, errors, "Expected no validation errors")
			}
		})
	}
}
