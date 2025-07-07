// pkg/terraform/config_fuzz_test.go - Terraform configuration generation fuzzing
package terraform

import (
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzTerraformConfigGeneration tests HCL configuration generation with malicious inputs
func FuzzTerraformConfigGeneration(f *testing.F) {
	// Seed with HCL injection attempts
	f.Add("normal_value")
	f.Add("${exec(\"rm -rf /\")}")
	f.Add("${file(\"/etc/passwd\")}")
	f.Add("${env.HOME}")
	f.Add("${var.secret_value}")
	f.Add("${local.malicious_function()}")
	f.Add("${templatefile(\"/malicious\", {})}")
	f.Add("${jsonencode({for k,v in var.secrets : k => v})}")
	f.Add("${yamlencode(sensitive(var.passwords))}")
	f.Add("value\nwith\nnewlines")
	f.Add("value\"with'quotes")
	f.Add("")
	f.Add("unicode🌍value")
	f.Add("very_long_" + strings.Repeat("x", 5000) + "_value")
	f.Add("${nonsense")
	f.Add("unclosed${interpolation")
	f.Add("${deeply.nested.function.call(malicious.data)}")

	f.Fuzz(func(t *testing.T, configValue string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Terraform config generation panicked with value %q: %v", configValue, r)
			}
		}()

		// Test HCL value sanitization
		sanitized := SanitizeHCLValue(configValue)

		// Should always be valid UTF-8
		if !utf8.ValidString(sanitized) {
			t.Errorf("HCL sanitization produced invalid UTF-8: input=%q, output=%q", configValue, sanitized)
		}

		// Should not contain dangerous interpolations
		if containsDangerousHCLInterpolation(sanitized) {
			t.Errorf("Sanitized HCL contains dangerous interpolation: input=%q, output=%q", configValue, sanitized)
		}

		// Should be valid HCL syntax if non-empty
		if sanitized != "" && !isValidHCLValue(sanitized) {
			t.Errorf("Sanitized value is not valid HCL: input=%q, output=%q", configValue, sanitized)
		}
	})
}

// FuzzTerraformVariableValidation tests Terraform variable validation
func FuzzTerraformVariableValidation(f *testing.F) {
	// Seed with variable injection attempts
	f.Add("normal_var_name")
	f.Add("var-with-dashes")
	f.Add("var_with_underscores")
	f.Add("123invalid")
	f.Add("")
	f.Add("var.name")
	f.Add("var name with spaces")
	f.Add("var/with/slashes")
	f.Add("var${injection}")
	f.Add("extremely_long_" + strings.Repeat("variable", 100) + "_name")
	f.Add("var\nwith\nnewlines")
	f.Add("unicode_var_🌍")
	f.Add("_private_var")
	f.Add("__dunder_var")

	f.Fuzz(func(t *testing.T, varName string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Variable validation panicked with name %q: %v", varName, r)
			}
		}()

		err := ValidateTerraformVariableName(varName)

		// Should never panic, even with invalid input
		if err != nil {
			// Errors are expected for invalid variable names
			return
		}

		// If validation passes, ensure it's a safe variable name
		if !isValidTerraformIdentifier(varName) {
			t.Errorf("Invalid variable name passed validation: %q", varName)
		}
	})
}

// FuzzTerraformResourceGeneration tests resource block generation
func FuzzTerraformResourceGeneration(f *testing.F) {
	// Seed with resource generation attempts
	f.Add("nomad_job", "minio")
	f.Add("vault_kv_secret_v2", "credentials")
	f.Add("consul_service", "api")
	f.Add("", "")
	f.Add("resource${injection}", "name")
	f.Add("resource_type", "name${injection}")
	f.Add("very_long_" + strings.Repeat("type", 50), "name")
	f.Add("type", "very_long_" + strings.Repeat("name", 50))
	f.Add("type\nwith\nnewlines", "name")
	f.Add("type", "name\nwith\nnewlines")

	f.Fuzz(func(t *testing.T, resourceType, resourceName string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Resource generation panicked with type=%q, name=%q: %v", resourceType, resourceName, r)
			}
		}()

		// Test resource block generation
		block, err := GenerateTerraformResourceBlock(resourceType, resourceName, map[string]interface{}{
			"test_attr": "test_value",
		})

		if err != nil {
			// Errors are expected for invalid inputs
			return
		}

		// If generation succeeds, validate the output
		if !utf8.ValidString(block) {
			t.Errorf("Generated resource block contains invalid UTF-8: type=%q, name=%q", resourceType, resourceName)
		}

		if containsDangerousHCLInterpolation(block) {
			t.Errorf("Generated resource block contains dangerous interpolation: type=%q, name=%q, block=%q", 
				resourceType, resourceName, block)
		}
	})
}

// FuzzTerraformStateFileHandling tests state file operations
func FuzzTerraformStateFileHandling(f *testing.F) {
	// Seed with state manipulation attempts
	f.Add(`{"version": 4, "terraform_version": "1.0.0"}`)
	f.Add(`{"version": 999999999}`)
	f.Add(`{"malicious": "${exec('rm -rf /')"}`)
	f.Add(`{"resources": [{"type": "malicious", "instances": []}]}`)
	f.Add(`invalid json`)
	f.Add(``)
	f.Add(`null`)
	f.Add(`[]`)
	f.Add(`{"very_large_object": "` + strings.Repeat("x", 1000000) + `"}`)
	f.Add(`{"unicode": "🌍"}`)
	f.Add(`{"binary": "\x00\x01\x02"}`)

	f.Fuzz(func(t *testing.T, stateData string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("State file handling panicked with data %q: %v", stateData, r)
			}
		}()

		// Test state file validation and sanitization
		sanitized, err := ValidateAndSanitizeTerraformState(stateData)

		if err != nil {
			// Errors are expected for invalid state data
			return
		}

		// If validation passes, ensure the result is safe
		if !utf8.ValidString(sanitized) {
			t.Errorf("State sanitization produced invalid UTF-8: input=%q", stateData)
		}

		if containsDangerousStateData(sanitized) {
			t.Errorf("Sanitized state contains dangerous data: input=%q, output=%q", stateData, sanitized)
		}
	})
}

// Helper functions for Terraform fuzzing

// SanitizeHCLValue sanitizes HCL configuration values
func SanitizeHCLValue(value string) string {
	// Remove dangerous interpolations
	value = removeDangerousHCLInterpolations(value)
	
	// Remove null bytes
	value = strings.ReplaceAll(value, "\x00", "")
	
	// Limit length
	if len(value) > 1000 {
		value = value[:1000] + "[TRUNCATED]"
	}
	
	// Escape quotes properly
	value = strings.ReplaceAll(value, `"`, `\"`)
	
	return value
}

// ValidateTerraformVariableName validates Terraform variable names
func ValidateTerraformVariableName(name string) error {
	if name == "" {
		return fmt.Errorf("variable name cannot be empty")
	}
	
	if len(name) > 64 {
		return fmt.Errorf("variable name too long")
	}
	
	if !isValidTerraformIdentifier(name) {
		return fmt.Errorf("invalid Terraform identifier")
	}
	
	return nil
}

// GenerateTerraformResourceBlock generates a Terraform resource block
func GenerateTerraformResourceBlock(resourceType, resourceName string, attributes map[string]interface{}) (string, error) {
	// Validate inputs
	if err := ValidateTerraformVariableName(resourceType); err != nil {
		return "", fmt.Errorf("invalid resource type: %w", err)
	}
	
	if err := ValidateTerraformVariableName(resourceName); err != nil {
		return "", fmt.Errorf("invalid resource name: %w", err)
	}
	
	// Generate resource block (simplified)
	block := fmt.Sprintf(`resource "%s" "%s" {`, resourceType, resourceName)
	
	for key, value := range attributes {
		if err := ValidateTerraformVariableName(key); err != nil {
			continue // Skip invalid attribute names
		}
		
		sanitizedValue := SanitizeHCLValue(fmt.Sprintf("%v", value))
		block += fmt.Sprintf(`\n  %s = "%s"`, key, sanitizedValue)
	}
	
	block += "\n}"
	
	return block, nil
}

// ValidateAndSanitizeTerraformState validates and sanitizes Terraform state
func ValidateAndSanitizeTerraformState(stateData string) (string, error) {
	// Basic validation
	if len(stateData) > 10*1024*1024 { // 10MB limit
		return "", fmt.Errorf("state file too large")
	}
	
	if !utf8.ValidString(stateData) {
		return "", fmt.Errorf("invalid UTF-8 in state data")
	}
	
	// Check for dangerous content
	if containsDangerousStateData(stateData) {
		return "", fmt.Errorf("dangerous content in state data")
	}
	
	return stateData, nil
}

func containsDangerousHCLInterpolation(s string) bool {
	dangerousPatterns := []string{
		"${exec(", "${file(", "${env.", "${system(",
		"${shell(", "${command(", "${eval(",
		"rm -rf", "system(", "exec(", "popen(",
		"/etc/passwd", "/etc/shadow", "$HOME",
	}
	
	lower := strings.ToLower(s)
	for _, pattern := range dangerousPatterns {
		if strings.Contains(lower, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

func containsDangerousStateData(s string) bool {
	dangerousPatterns := []string{
		"${exec", "${file", "${env", "${system",
		"rm -rf", "system(", "exec(", "popen(",
		"../../../", "/etc/passwd", "/etc/shadow",
	}
	
	lower := strings.ToLower(s)
	for _, pattern := range dangerousPatterns {
		if strings.Contains(lower, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

func removeDangerousHCLInterpolations(s string) string {
	// Remove dangerous interpolation patterns
	dangerousPatterns := []string{
		"${exec(", "${file(", "${env.", "${system(",
		"${shell(", "${command(", "${eval(",
	}
	
	for _, pattern := range dangerousPatterns {
		s = strings.ReplaceAll(s, pattern, "${sanitized(")
	}
	
	return s
}

func isValidHCLValue(s string) bool {
	// Basic HCL value validation
	if s == "" {
		return true
	}
	
	// Check for unmatched quotes
	quoteCount := strings.Count(s, `"`) - strings.Count(s, `\"`)
	if quoteCount%2 != 0 {
		return false
	}
	
	// Check for unmatched interpolations
	openCount := strings.Count(s, "${")
	closeCount := strings.Count(s, "}")
	if openCount != closeCount {
		return false
	}
	
	return true
}

func isValidTerraformIdentifier(s string) bool {
	if s == "" {
		return false
	}
	
	// Must start with letter or underscore
	if !((s[0] >= 'a' && s[0] <= 'z') || (s[0] >= 'A' && s[0] <= 'Z') || s[0] == '_') {
		return false
	}
	
	// Rest must be letters, digits, or underscores
	for _, r := range s[1:] {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_') {
			return false
		}
	}
	
	return true
}