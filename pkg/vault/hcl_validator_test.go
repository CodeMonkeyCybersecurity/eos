// pkg/vault/hcl_validator_test.go

package vault

import (
	"context"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

func TestValidateAndFixCommonIssues(t *testing.T) {
	// Create a test runtime context
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	tests := []struct {
		name           string
		input          string
		expectFixed    bool
		expectValid    bool
		description    string
	}{
		{
			name: "policy_with_invalid_max_ttl",
			input: `
path "secret/data/test/*" {
  capabilities = ["read", "create"]
  max_ttl = "24h"
}`,
			expectFixed: true,
			expectValid: true,
			description: "Should remove invalid max_ttl from path block",
		},
		{
			name: "valid_policy",
			input: `
path "secret/data/test/*" {
  capabilities = ["read", "create"]
  required_parameters = ["version"]
}`,
			expectFixed: false,
			expectValid: true,
			description: "Should pass valid policy unchanged",
		},
		{
			name: "policy_with_multiple_invalid_attrs",
			input: `
path "secret/data/test/*" {
  capabilities = ["read", "create"]
  max_ttl = "24h"
  ttl = "1h"
  period = "30m"
}`,
			expectFixed: true,
			expectValid: true,
			description: "Should remove all invalid TTL attributes",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Test the validation and fixing
			fixed, err := ValidateAndFixCommonIssues(rc, test.name, test.input)
			
			if test.expectValid && err != nil {
				t.Errorf("Expected valid policy but got error: %v", err)
				return
			}

			if test.expectFixed {
				if fixed == test.input {
					t.Errorf("Expected policy to be fixed but it was unchanged")
				}
				
				// The fixed policy should not contain invalid attributes
				if containsInvalidAttributes(fixed) {
					t.Errorf("Fixed policy still contains invalid attributes: %s", fixed)
				}
			} else {
				if fixed != test.input {
					t.Errorf("Expected policy to remain unchanged but it was modified")
				}
			}

			// Test that the fixed policy validates successfully
			if err := ValidatePolicyString(rc, test.name+"_validation", fixed); err != nil {
				t.Errorf("Fixed policy failed validation: %v", err)
			}
		})
	}
}

func TestPolicyValidator(t *testing.T) {
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	validator := NewVaultPolicyValidator()

	// Test invalid policy
	invalidPolicy := `
path "secret/data/test/*" {
  capabilities = ["read", "invalid_capability"]
  max_ttl = "24h"
}`

	result, err := validator.ValidatePolicy(rc, "test-invalid", invalidPolicy)
	if err != nil {
		t.Fatalf("Validation failed with error: %v", err)
	}

	if result.Valid {
		t.Error("Expected invalid policy to be marked as invalid")
	}

	if len(result.Errors) == 0 {
		t.Error("Expected validation errors but got none")
	}

	// Test valid policy
	validPolicy := `
path "secret/data/test/*" {
  capabilities = ["read", "create"]
  required_parameters = ["version"]
}`

	result, err = validator.ValidatePolicy(rc, "test-valid", validPolicy)
	if err != nil {
		t.Fatalf("Validation failed with error: %v", err)
	}

	if !result.Valid {
		t.Errorf("Expected valid policy to be marked as valid, errors: %v", result.Errors)
	}
}

// Helper function to check if policy contains invalid attributes
func containsInvalidAttributes(policy string) bool {
	invalidAttrs := []string{"max_ttl", "ttl", "default_ttl", "period"}
	for _, attr := range invalidAttrs {
		if contains(policy, attr+" =") || contains(policy, attr+"=") {
			return true
		}
	}
	return false
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || (len(s) > len(substr) && 
		(stringContains(s, substr))))
}

func stringContains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}