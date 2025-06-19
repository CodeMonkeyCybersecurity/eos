// pkg/hashicorp/tools_test.go

package hashicorp

import (
	"context"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsToolSupported(t *testing.T) {
	tests := []struct {
		name     string
		tool     string
		expected bool
	}{
		{
			name:     "terraform is supported",
			tool:     "terraform",
			expected: true,
		},
		{
			name:     "vault is supported",
			tool:     "vault",
			expected: true,
		},
		{
			name:     "consul is supported",
			tool:     "consul",
			expected: true,
		},
		{
			name:     "nomad is supported",
			tool:     "nomad",
			expected: true,
		},
		{
			name:     "packer is supported",
			tool:     "packer",
			expected: true,
		},
		{
			name:     "boundary is supported",
			tool:     "boundary",
			expected: true,
		},
		{
			name:     "unsupported tool returns false",
			tool:     "random-tool",
			expected: false,
		},
		{
			name:     "empty string returns false",
			tool:     "",
			expected: false,
		},
		{
			name:     "case sensitivity test",
			tool:     "Terraform",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsToolSupported(tt.tool)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetSupportedToolsString(t *testing.T) {
	result := GetSupportedToolsString()
	
	// Should contain all supported tools
	assert.Contains(t, result, "terraform")
	assert.Contains(t, result, "vault")
	assert.Contains(t, result, "consul")
	assert.Contains(t, result, "nomad")
	assert.Contains(t, result, "packer")
	assert.Contains(t, result, "boundary")
	
	// Should be comma-separated
	assert.Contains(t, result, ", ")
	
	// Should not be empty
	assert.NotEmpty(t, result)
}

func TestSupportedHCLToolsConstant(t *testing.T) {
	// Verify that all expected tools are in the list
	expectedTools := []string{"terraform", "vault", "consul", "nomad", "packer", "boundary"}
	
	assert.Equal(t, len(expectedTools), len(SupportedHCLTools), "Number of supported tools should match expected")
	
	for _, expectedTool := range expectedTools {
		assert.Contains(t, SupportedHCLTools, expectedTool, "Expected tool %s should be in supported tools list", expectedTool)
	}
}

// TestInstallToolValidation tests the validation logic without actually installing
func TestInstallToolValidation(t *testing.T) {
	ctx := context.Background()
	rc := eos_io.NewContext(ctx, "test")
	
	// Test with unsupported tool
	err := InstallTool(rc, "unsupported-tool")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported HashiCorp tool")
	
	// Test with empty tool name
	err = InstallTool(rc, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported HashiCorp tool")
}

// TestVerificationResult tests the VerificationResult struct
func TestVerificationResult(t *testing.T) {
	result := VerificationResult{
		Tool:        "terraform",
		Installed:   true,
		Version:     "1.5.0",
		Path:        "/usr/bin/terraform",
		PluginCount: 5,
	}
	
	assert.Equal(t, "terraform", result.Tool)
	assert.True(t, result.Installed)
	assert.Equal(t, "1.5.0", result.Version)
	assert.Equal(t, "/usr/bin/terraform", result.Path)
	assert.Equal(t, 5, result.PluginCount)
	assert.Empty(t, result.Error)
}

// TestInstallToolInputValidation tests input validation
func TestInstallToolInputValidation(t *testing.T) {
	tests := []struct {
		name        string
		tool        string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid terraform tool",
			tool:        "terraform",
			expectError: false,
		},
		{
			name:        "valid vault tool",
			tool:        "vault",
			expectError: false,
		},
		{
			name:        "invalid tool name",
			tool:        "invalid-tool",
			expectError: true,
			errorMsg:    "unsupported HashiCorp tool",
		},
		{
			name:        "empty tool name",
			tool:        "",
			expectError: true,
			errorMsg:    "unsupported HashiCorp tool",
		},
		{
			name:        "tool name with special characters",
			tool:        "terraform@1.5.0",
			expectError: true,
			errorMsg:    "unsupported HashiCorp tool",
		},
	}
	
	ctx := context.Background()
	rc := eos_io.NewContext(ctx, "test")
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// We can't actually install tools in tests, but we can test validation
			if tt.expectError {
				err := InstallTool(rc, tt.tool)
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				// For valid tools, we expect the error to come from the installation process
				// not from validation, but we can't test the full installation in unit tests
				supported := IsToolSupported(tt.tool)
				assert.True(t, supported, "Tool should be supported")
			}
		})
	}
}

// Benchmark tests
func BenchmarkIsToolSupported(b *testing.B) {
	for i := 0; i < b.N; i++ {
		IsToolSupported("terraform")
	}
}

func BenchmarkGetSupportedToolsString(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GetSupportedToolsString()
	}
}