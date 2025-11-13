// pkg/consul/config/parser_test.go
//
// Tests for Consul config file parser.
//
// Last Updated: 2025-10-25

package config

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseDataDirFromConfigFile_ValidHCL tests parsing valid HCL config
func TestParseDataDirFromConfigFile_ValidHCL(t *testing.T) {
	// Create temp directory
	tmpDir := t.TempDir()

	// Create valid HCL config
	configPath := filepath.Join(tmpDir, "consul.hcl")
	validHCL := `datacenter = "dc1"
node_name = "test-node"
data_dir = "/opt/consul"
log_level = "INFO"
`
	err := os.WriteFile(configPath, []byte(validHCL), 0644)
	require.NoError(t, err)

	// Create runtime context
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	// Parse config
	dataDir, err := ParseDataDirFromConfigFile(rc, []string{configPath})

	// Verify
	assert.NoError(t, err)
	assert.Equal(t, "/opt/consul", dataDir)
}

// TestParseDataDirFromConfigFile_ValidJSON tests parsing valid JSON config
func TestParseDataDirFromConfigFile_ValidJSON(t *testing.T) {
	// Create temp directory
	tmpDir := t.TempDir()

	// Create valid JSON config
	configPath := filepath.Join(tmpDir, "consul.json")
	validJSON := `{
  "datacenter": "dc1",
  "node_name": "test-node",
  "data_dir": "/var/lib/consul",
  "log_level": "INFO"
}`
	err := os.WriteFile(configPath, []byte(validJSON), 0644)
	require.NoError(t, err)

	// Create runtime context
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	// Parse config
	dataDir, err := ParseDataDirFromConfigFile(rc, []string{configPath})

	// Verify
	assert.NoError(t, err)
	assert.Equal(t, "/var/lib/consul", dataDir)
}

// TestParseDataDirFromConfigFile_MissingDataDir tests config without data_dir field
func TestParseDataDirFromConfigFile_MissingDataDir(t *testing.T) {
	// Create temp directory
	tmpDir := t.TempDir()

	// Create HCL config without data_dir
	configPath := filepath.Join(tmpDir, "consul.hcl")
	configWithoutDataDir := `datacenter = "dc1"
node_name = "test-node"
log_level = "INFO"
`
	err := os.WriteFile(configPath, []byte(configWithoutDataDir), 0644)
	require.NoError(t, err)

	// Create runtime context
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	// Parse config
	dataDir, err := ParseDataDirFromConfigFile(rc, []string{configPath})

	// Verify
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "data_dir not set")
	assert.Empty(t, dataDir)
}

// TestParseDataDirFromConfigFile_MalformedHCL tests malformed HCL that's also invalid JSON
func TestParseDataDirFromConfigFile_MalformedConfig(t *testing.T) {
	// Create temp directory
	tmpDir := t.TempDir()

	// Create malformed config
	configPath := filepath.Join(tmpDir, "consul.hcl")
	malformedConfig := `datacenter = "dc1
node_name = "test-node"
data_dir = "/opt/consul
`
	err := os.WriteFile(configPath, []byte(malformedConfig), 0644)
	require.NoError(t, err)

	// Create runtime context
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	// Parse config
	dataDir, err := ParseDataDirFromConfigFile(rc, []string{configPath})

	// Verify
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse")
	assert.Empty(t, dataDir)
}

// TestParseDataDirFromConfigFile_FileNotFound tests missing config file
func TestParseDataDirFromConfigFile_FileNotFound(t *testing.T) {
	// Create runtime context
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	// Try to parse non-existent file
	dataDir, err := ParseDataDirFromConfigFile(rc, []string{"/nonexistent/consul.hcl"})

	// Verify
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse data_dir from any config file")
	assert.Empty(t, dataDir)
}

// TestParseDataDirFromConfigFile_MultipleLocations tests fallback to second location
func TestParseDataDirFromConfigFile_MultipleLocations(t *testing.T) {
	// Create temp directory
	tmpDir := t.TempDir()

	// First location doesn't exist
	firstPath := filepath.Join(tmpDir, "nonexistent.hcl")

	// Second location exists with valid config
	secondPath := filepath.Join(tmpDir, "consul.hcl")
	validHCL := `data_dir = "/opt/consul"`
	err := os.WriteFile(secondPath, []byte(validHCL), 0644)
	require.NoError(t, err)

	// Create runtime context
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	// Parse config with multiple locations
	dataDir, err := ParseDataDirFromConfigFile(rc, []string{firstPath, secondPath})

	// Verify - should use second location
	assert.NoError(t, err)
	assert.Equal(t, "/opt/consul", dataDir)
}

// TestDefaultConfigLocations tests that default locations are returned
func TestDefaultConfigLocations(t *testing.T) {
	locations := DefaultConfigLocations()

	// Verify basic structure
	assert.NotEmpty(t, locations)
	assert.Contains(t, locations, "/etc/consul.d/consul.hcl")
	assert.Contains(t, locations, "/etc/consul.d/consul.json")
}

// TestParseDataDirFromConfigFile_ComplexHCL tests parsing HCL with nested blocks
func TestParseDataDirFromConfigFile_ComplexHCL(t *testing.T) {
	// Create temp directory
	tmpDir := t.TempDir()

	// Create complex HCL config with nested blocks
	configPath := filepath.Join(tmpDir, "consul.hcl")
	complexHCL := `datacenter = "dc1"
node_name = "test-node"
data_dir = "/opt/consul"
server = true

ui_config {
  enabled = true
}

acl {
  enabled = true
  default_policy = "deny"
}
`
	err := os.WriteFile(configPath, []byte(complexHCL), 0644)
	require.NoError(t, err)

	// Create runtime context
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	// Parse config
	dataDir, err := ParseDataDirFromConfigFile(rc, []string{configPath})

	// Verify - parser should ignore nested blocks
	assert.NoError(t, err)
	assert.Equal(t, "/opt/consul", dataDir)
}
