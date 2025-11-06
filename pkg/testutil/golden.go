// Package testutil provides testing utilities for Eos
package testutil

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bradleyjkemp/cupaloy/v2"
)

// GoldenFile provides golden file testing utilities for snapshot testing
//
// Golden file testing (snapshot testing) is useful for:
// - Docker Compose file generation
// - Systemd unit file templates
// - Vault/Consul/Nomad configuration files
// - Complex multi-line output validation
//
// Usage:
//
//	func TestGenerateDockerCompose(t *testing.T) {
//	    config := &ServiceConfig{Port: 8080}
//	    output := GenerateDockerCompose(config)
//
//	    golden := testutil.NewGolden(t)
//	    golden.Assert(output)
//	}
//
// To update golden files when expected output changes:
//
//	go test -update
type GoldenFile struct {
	t          *testing.T
	snapshotter *cupaloy.Config
}

// NewGolden creates a new golden file tester
//
// Golden files are stored in: testdata/golden/<test_name>.golden
func NewGolden(t *testing.T) *GoldenFile {
	t.Helper()

	// Create testdata/golden directory if it doesn't exist
	goldenDir := filepath.Join("testdata", "golden")
	if err := os.MkdirAll(goldenDir, 0755); err != nil {
		t.Fatalf("Failed to create golden directory: %v", err)
	}

	// Configure cupaloy to use our directory structure
	snapshotter := cupaloy.New(
		cupaloy.SnapshotSubdirectory(goldenDir),
		cupaloy.ShouldUpdate(func() bool {
			// Check for -update flag
			for _, arg := range os.Args {
				if arg == "-update" || arg == "-test.update" {
					return true
				}
			}
			return false
		}),
	)

	return &GoldenFile{
		t:           t,
		snapshotter: snapshotter,
	}
}

// Assert compares the given value against the golden file
//
// On first run, it creates the golden file
// On subsequent runs, it compares against the golden file
// With -update flag, it updates the golden file
func (g *GoldenFile) Assert(got interface{}) {
	g.t.Helper()

	// Use test name as snapshot name
	err := g.snapshotter.Snapshot(got)
	if err != nil {
		g.t.Fatalf("Golden file assertion failed: %v\n\nTo update golden files, run:\n  go test -update", err)
	}
}

// AssertWithName compares with a custom snapshot name
//
// Useful when a single test has multiple golden files:
//
//	golden.AssertWithName("docker-compose", composeFile)
//	golden.AssertWithName("systemd-unit", unitFile)
func (g *GoldenFile) AssertWithName(name string, got interface{}) {
	g.t.Helper()

	err := g.snapshotter.SnapshotWithName(name, got)
	if err != nil {
		g.t.Fatalf("Golden file assertion failed for '%s': %v\n\nTo update golden files, run:\n  go test -update", name, err)
	}
}

// AssertMulti compares multiple values in table-driven tests
//
// Usage:
//
//	tests := []struct {
//	    name   string
//	    input  Config
//	    output string
//	}{
//	    {name: "basic", input: basicConfig, output: generateConfig(basicConfig)},
//	    {name: "advanced", input: advancedConfig, output: generateConfig(advancedConfig)},
//	}
//
//	golden := testutil.NewGolden(t)
//	for _, tt := range tests {
//	    t.Run(tt.name, func(t *testing.T) {
//	        golden.AssertWithName(tt.name, tt.output)
//	    })
//	}
func (g *GoldenFile) AssertMulti(testCases map[string]interface{}) {
	g.t.Helper()

	for name, got := range testCases {
		g.AssertWithName(name, got)
	}
}

// Update forces an update of the golden file
//
// Useful for programmatic updates without -update flag
func (g *GoldenFile) Update() *GoldenFile {
	g.snapshotter = cupaloy.New(
		cupaloy.SnapshotSubdirectory(filepath.Join("testdata", "golden")),
		cupaloy.ShouldUpdate(func() bool { return true }),
	)
	return g
}

// GoldenBytes is a convenience function for byte slice comparisons
//
// Usage:
//
//	generated := GenerateDockerCompose(config)
//	testutil.GoldenBytes(t, generated)
func GoldenBytes(t *testing.T, got []byte) {
	t.Helper()
	golden := NewGolden(t)
	golden.Assert(string(got))
}

// GoldenString is a convenience function for string comparisons
//
// Usage:
//
//	output := GenerateSystemdUnit(service)
//	testutil.GoldenString(t, output)
func GoldenString(t *testing.T, got string) {
	t.Helper()
	golden := NewGolden(t)
	golden.Assert(got)
}

// GoldenJSON is a convenience function for JSON comparisons
//
// Automatically marshals the struct to formatted JSON before comparison
//
// Usage:
//
//	config := &VaultConfig{Port: 8200}
//	testutil.GoldenJSON(t, config)
func GoldenJSON(t *testing.T, got interface{}) {
	t.Helper()

	// Note: We don't import encoding/json here to avoid forcing it on all users
	// The cupaloy library handles JSON marshaling internally
	golden := NewGolden(t)
	golden.Assert(got)
}
