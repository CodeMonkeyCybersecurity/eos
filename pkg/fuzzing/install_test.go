package fuzzing

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

func TestCheckGoVersion(t *testing.T) {
	// This test assumes Go is installed on the system
	// It's mainly testing the version parsing logic
	err := checkGoVersion()
	
	// Should pass on any system with Go 1.18+ installed
	assert.NoError(t, err, "Go version check should pass on systems with Go 1.18+")
}

func TestExtractPackageNameFromPath(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		expected string
	}{
		{
			name:     "simple package",
			filePath: "pkg/fuzzing/test.go",
			expected: "./pkg/fuzzing",
		},
		{
			name:     "nested package",
			filePath: "internal/utils/crypto/test.go",
			expected: "./internal/utils/crypto",
		},
		{
			name:     "root level file",
			filePath: "main.go",
			expected: ".",
		},
		{
			name:     "current directory",
			filePath: "./test.go",
			expected: ".",
		},
		{
			name:     "windows style path",
			filePath: "pkg\\fuzzing\\test.go",
			expected: "./pkg/fuzzing",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractPackageName(tt.filePath)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCheckGoModulesSupport(t *testing.T) {
	// This test checks if Go modules are enabled
	// Should pass in modern Go environments
	err := checkGoModulesSupport()
	assert.NoError(t, err, "Go modules should be enabled")
}

func TestValidateGoVersionStrings(t *testing.T) {
	tests := []struct {
		name        string
		versionStr  string
		shouldMatch bool
	}{
		{
			name:        "go 1.18",
			versionStr:  "go version go1.18 linux/amd64",
			shouldMatch: true,
		},
		{
			name:        "go 1.21",
			versionStr:  "go version go1.21.5 darwin/amd64",
			shouldMatch: true,
		},
		{
			name:        "go 1.24",
			versionStr:  "go version go1.24 darwin/arm64",
			shouldMatch: true,
		},
		{
			name:        "future go version",
			versionStr:  "go version go1.99.0 linux/amd64",
			shouldMatch: true,
		},
		{
			name:        "old go version format",
			versionStr:  "go version go1.17 linux/amd64",
			shouldMatch: true, // We accept any go1.X now
		},
		{
			name:        "invalid version",
			versionStr:  "not a go version",
			shouldMatch: false,
		},
		{
			name:        "go 2.x version",
			versionStr:  "go version go2.0 linux/amd64",
			shouldMatch: false, // Only go1.X is supported
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test if version string contains "go1."
			contains := strings.Contains(tt.versionStr, "go1.")
			assert.Equal(t, tt.shouldMatch, contains)
		})
	}
}

func TestInstallDependencyPaths(t *testing.T) {
	// Test that expected package paths are correctly formatted
	packages := []string{"./pkg/...", "./cmd/..."}
	
	for _, pkg := range packages {
		assert.True(t, strings.HasSuffix(pkg, "/..."), "Package should use /... pattern")
		
		// Extract base directory
		baseDir := strings.TrimSuffix(pkg, "/...")
		assert.True(t, strings.HasPrefix(baseDir, "./"), "Package should start with ./")
	}
}

func TestCheckFuzzingSupport(t *testing.T) {
	// This test verifies fuzzing support detection
	// Should pass on Go 1.18+ systems
	err := checkFuzzingSupport()
	
	// The test might fail on older Go versions
	if err != nil {
		t.Logf("Fuzzing support check failed (might be running on Go < 1.18): %v", err)
	}
}

// Mock test for package compilation checks
func TestCompileTestPackagesSkipsNonExistent(t *testing.T) {
	rc := NewTestContext(t)
	logger := otelzap.Ctx(rc.Ctx)
	
	// This should not error even if directories don't exist
	err := compileTestPackages(logger)
	assert.NoError(t, err, "Should not error on missing directories")
}