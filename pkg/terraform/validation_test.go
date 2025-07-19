// pkg/terraform/validation_test.go

package terraform

import (
	"context"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/stretchr/testify/assert"
)

func TestTerraformValidationTypes(t *testing.T) {
	t.Run("TerraformVersionInfo structure", func(t *testing.T) {
		info := &TerraformVersionInfo{
			Version:      "1.6.0",
			Platform:     "linux_amd64",
			ProviderSHA:  "test-sha",
			Architecture: "amd64",
		}
		
		assert.Equal(t, "1.6.0", info.Version)
		assert.Equal(t, "linux_amd64", info.Platform)
	})

	t.Run("TerraformValidationResult structure", func(t *testing.T) {
		result := &TerraformValidationResult{
			VersionCompatible: true,
			ProvidersValid:    false,
			StateValid:        true,
			QuotasValid:       true,
			Errors:           []string{"test error"},
			Warnings:         []string{"test warning"},
		}
		
		assert.True(t, result.VersionCompatible)
		assert.False(t, result.ProvidersValid)
		assert.Len(t, result.Errors, 1)
		assert.Len(t, result.Warnings, 1)
	})
}

func TestVersionComparison(t *testing.T) {
	tests := []struct {
		name     string
		current  string
		min      string
		max      string
		expected bool
	}{
		{
			name:     "version within range",
			current:  "1.5.0",
			min:      "1.0.0",
			max:      "2.0.0",
			expected: true,
		},
		{
			name:     "version below minimum",
			current:  "0.9.0",
			min:      "1.0.0",
			max:      "2.0.0",
			expected: false,
		},
		{
			name:     "version above maximum",
			current:  "2.1.0",
			min:      "1.0.0",
			max:      "2.0.0",
			expected: false,
		},
		{
			name:     "version with v prefix",
			current:  "v1.5.0",
			min:      "1.0.0",
			max:      "2.0.0",
			expected: true,
		},
		{
			name:     "version with beta suffix",
			current:  "1.5.0-beta1",
			min:      "1.0.0",
			max:      "2.0.0",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isVersionInRange(tt.current, tt.min, tt.max)
			assert.Equal(t, tt.expected, result, 
				"Version %s should be %v for range %s-%s", 
				tt.current, tt.expected, tt.min, tt.max)
		})
	}
}

func TestVersionParsing(t *testing.T) {
	tests := []struct {
		version  string
		expected []int
	}{
		{"1.5.0", []int{1, 5, 0}},
		{"v1.5.0", []int{1, 5, 0}},
		{"1.5.0-beta1", []int{1, 5, 0}},
		{"2.0.1-rc1", []int{2, 0, 1}},
		{"1.6", []int{1, 6}},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			result := parseVersion(tt.version)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestProviderValidationHelpers(t *testing.T) {
	t.Run("allProvidersValid with all valid", func(t *testing.T) {
		validations := []ProviderValidation{
			{Name: "hetzner", Authenticated: true, Error: ""},
			{Name: "consul", Authenticated: true, Error: ""},
		}
		
		assert.True(t, allProvidersValid(validations))
	})

	t.Run("allProvidersValid with authentication failure", func(t *testing.T) {
		validations := []ProviderValidation{
			{Name: "hetzner", Authenticated: false, Error: ""},
			{Name: "consul", Authenticated: true, Error: ""},
		}
		
		assert.False(t, allProvidersValid(validations))
	})

	t.Run("allProvidersValid with error", func(t *testing.T) {
		validations := []ProviderValidation{
			{Name: "hetzner", Authenticated: true, Error: "API error"},
			{Name: "consul", Authenticated: true, Error: ""},
		}
		
		assert.False(t, allProvidersValid(validations))
	})
}

func TestDefaultHecatePrerequisites(t *testing.T) {
	t.Run("DefaultHecatePrerequisites structure", func(t *testing.T) {
		prereqs := DefaultHecatePrerequisites
		
		assert.Equal(t, "1.0.0", prereqs.MinVersion)
		assert.Equal(t, "2.0.0", prereqs.MaxVersion)
		assert.Contains(t, prereqs.RequiredProviders, "hetzner/hcloud")
		assert.Contains(t, prereqs.RequiredProviders, "hashicorp/consul")
		assert.Contains(t, prereqs.RequiredProviders, "hashicorp/vault")
		assert.Equal(t, "/var/lib/hecate/terraform", prereqs.WorkingDirectory)
		assert.Equal(t, "consul", prereqs.StateBackend)
	})
}

func TestValidateTerraformForHecate(t *testing.T) {
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	t.Run("ValidateTerraformForHecate function exists", func(t *testing.T) {
		// This test just ensures the function can be called
		// In a real environment, it would test actual validation
		result, err := ValidateTerraformForHecate(rc)
		
		// We expect this to fail in test environment due to missing terraform
		// but the function should exist and return proper error structure
		if err != nil {
			assert.NotNil(t, result, "Result should be returned even on error")
		} else {
			// If somehow it succeeds, validate the structure
			assert.NotNil(t, result)
			assert.NotNil(t, result.ProviderValidations)
			assert.NotNil(t, result.Errors)
			assert.NotNil(t, result.Warnings)
		}
	})
}

func TestProviderValidationStructure(t *testing.T) {
	t.Run("ProviderValidation with timestamp", func(t *testing.T) {
		validation := ProviderValidation{
			Name:          "test-provider",
			Version:       "1.0.0",
			Authenticated: true,
			Permissions:   []string{"read", "write"},
			LastValidated: time.Now(),
			Error:         "",
		}
		
		assert.Equal(t, "test-provider", validation.Name)
		assert.True(t, validation.Authenticated)
		assert.Len(t, validation.Permissions, 2)
		assert.Empty(t, validation.Error)
		assert.False(t, validation.LastValidated.IsZero())
	})
}

func TestStateValidationStructure(t *testing.T) {
	t.Run("StateValidation with resource count", func(t *testing.T) {
		validation := StateValidation{
			Exists:         true,
			IntegrityValid: true,
			VersionValid:   true,
			BackupExists:   false,
			Size:           1024,
			LastModified:   time.Now(),
			ResourceCount:  5,
			Error:          "",
		}
		
		assert.True(t, validation.Exists)
		assert.True(t, validation.IntegrityValid)
		assert.Equal(t, int64(1024), validation.Size)
		assert.Equal(t, 5, validation.ResourceCount)
		assert.Empty(t, validation.Error)
	})
}

func TestQuotaValidationStructure(t *testing.T) {
	t.Run("QuotaValidation with limits", func(t *testing.T) {
		validation := QuotaValidation{
			DNSRecordsUsed:    10,
			DNSRecordsLimit:   100,
			APICallsRemaining: 3600,
			RateLimitStatus:   "ok",
			Error:             "",
		}
		
		assert.Equal(t, 10, validation.DNSRecordsUsed)
		assert.Equal(t, 100, validation.DNSRecordsLimit)
		assert.Equal(t, 3600, validation.APICallsRemaining)
		assert.Equal(t, "ok", validation.RateLimitStatus)
		assert.Empty(t, validation.Error)
	})
}