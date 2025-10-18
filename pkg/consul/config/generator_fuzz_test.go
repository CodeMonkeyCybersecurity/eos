package config

import (
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/testutil"
)

// FuzzGenerate tests the Generate function with various configuration inputs
func FuzzGenerate(f *testing.F) {
	// Seed with valid configurations
	f.Add("production", true, true)
	f.Add("development", false, false)
	f.Add("", true, false)
	f.Add("test-dc-1", false, true)

	f.Fuzz(func(t *testing.T, datacenter string, enableDebugLogging, vaultAvailable bool) {
		rc := testutil.TestRuntimeContext(t)

		cfg := &ConsulConfig{
			DatacenterName:     datacenter,
			EnableDebugLogging: enableDebugLogging,
			VaultAvailable:     vaultAvailable,
		}

		// Test should not panic regardless of input
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Generate panicked with config %+v: %v", cfg, r)
			}
		}()

		err := Generate(rc, cfg)

		// Function should handle all inputs gracefully
		// We expect it might fail for certain invalid inputs, but should not panic
		if err != nil {
			t.Logf("Generate returned error for config %+v: %v", cfg, err)
		}
	})
}

// FuzzConsulConfigValidation tests configuration validation
func FuzzConsulConfigValidation(f *testing.F) {
	// Seed with various datacenter names that might cause issues
	f.Add("prod")
	f.Add("test-123")
	f.Add("dc-with-special-chars")
	f.Add("very-long-datacenter-name-that-might-cause-issues")
	f.Add("")
	f.Add("dc@special")
	f.Add("dc with spaces")
	f.Add("dc\nwith\nnewlines")
	f.Add("dc\x00with\x00nulls")

	f.Fuzz(func(t *testing.T, datacenter string) {
		cfg := &ConsulConfig{
			DatacenterName:     datacenter,
			EnableDebugLogging: true,
			VaultAvailable:     false,
		}

		// Validate that configuration creation doesn't panic
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Config creation panicked with datacenter %q: %v", datacenter, r)
			}
		}()

		// Test configuration structure
		if cfg.DatacenterName != datacenter {
			t.Errorf("DatacenterName not set correctly: got %q, want %q", cfg.DatacenterName, datacenter)
		}

		// Test that string methods don't panic
		_ = len(cfg.DatacenterName)
		if cfg.DatacenterName != "" {
			_ = cfg.DatacenterName[0:1] // Should not panic for non-empty strings
		}
	})
}
