package config_loader

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/testutil"
)

// FuzzLoadServicesFromFile tests loading services configuration with various inputs
func FuzzLoadServicesFromFile(f *testing.F) {
	// Seed with valid JSON configurations
	f.Add(`[]`)
	f.Add(`[{"name":"test","enabled":true}]`)
	f.Add(`[{"name":"","enabled":false}]`)
	f.Add(`{}`)
	f.Add(`null`)
	f.Add(`""`)
	f.Add(`invalid json`)
	f.Add(`[{"name":"test\x00null","enabled":true}]`)
	f.Add(`[{"name":"test\nservice","enabled":true}]`)

	f.Fuzz(func(t *testing.T, jsonContent string) {
		rc := testutil.TestRuntimeContext(t)
		
		// Create temporary file with fuzz content
		tmpFile, err := os.CreateTemp("", "services_fuzz_*.json")
		if err != nil {
			t.Skip("Cannot create temp file")
		}
		defer func() { _ = os.Remove(tmpFile.Name()) }()
		defer func() { _ = tmpFile.Close() }()

		if _, err := tmpFile.WriteString(jsonContent); err != nil {
			t.Skip("Cannot write to temp file")
		}
		_ = tmpFile.Close()

		// Test should not panic regardless of input
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("LoadServicesFromFile panicked with input %q: %v", jsonContent, r)
			}
		}()

		_, err = LoadServicesFromFile(rc, tmpFile.Name())
		// Function should handle invalid JSON gracefully by returning error
		if err != nil {
			t.Logf("LoadServicesFromFile returned error for input %q: %v", jsonContent, err)
		}
	})
}

// FuzzLoadSystemStateFromFile tests system state loading with various inputs
func FuzzLoadSystemStateFromFile(f *testing.F) {
	// Seed with various system state configurations
	f.Add(`{"services":[],"cron_jobs":[],"users":[],"packages":[],"files":[]}`)
	f.Add(`{"services":[{"name":"test"}]}`)
	f.Add(`{"metadata":{"key":"value"}}`)
	f.Add(`{"security":{"enabled":true}}`)
	f.Add(`invalid json`)
	f.Add(`{}`)
	f.Add(`null`)

	f.Fuzz(func(t *testing.T, jsonContent string) {
		rc := testutil.TestRuntimeContext(t)
		
		// Create temporary file with fuzz content
		tmpFile, err := os.CreateTemp("", "state_fuzz_*.json")
		if err != nil {
			t.Skip("Cannot create temp file")
		}
		defer func() { _ = os.Remove(tmpFile.Name()) }()
		defer func() { _ = tmpFile.Close() }()

		if _, err := tmpFile.WriteString(jsonContent); err != nil {
			t.Skip("Cannot write to temp file")
		}
		_ = tmpFile.Close()

		// Test should not panic regardless of input
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("LoadSystemStateFromFile panicked with input %q: %v", jsonContent, r)
			}
		}()

		_, err = LoadSystemStateFromFile(rc, tmpFile.Name())
		// Function should handle invalid JSON gracefully by returning error
		if err != nil {
			t.Logf("LoadSystemStateFromFile returned error for input %q: %v", jsonContent, err)
		}
	})
}

// FuzzFilePathHandling tests various file path inputs
func FuzzFilePathHandling(f *testing.F) {
	// Seed with various potentially problematic file paths
	f.Add("/etc/passwd")
	f.Add("/dev/null")
	f.Add("../../../etc/passwd")
	f.Add("")
	f.Add("nonexistent.json")
	f.Add("/tmp/test.json")
	f.Add("./test.json")
	f.Add("test\x00.json")
	f.Add("test\n.json")
	f.Add("very-long-" + string(make([]byte, 1000)) + ".json")

	f.Fuzz(func(t *testing.T, filePath string) {
		rc := testutil.TestRuntimeContext(t)

		// Test should not panic regardless of file path
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Function panicked with file path %q: %v", filePath, r)
			}
		}()

		// Test all loader functions with the fuzzed path
		_, err1 := LoadServicesFromFile(rc, filePath)
		_, err2 := LoadCronJobsFromFile(rc, filePath)
		_, err3 := LoadUsersFromFile(rc, filePath)
		_, err4 := LoadSystemStateFromFile(rc, filePath)

		// We expect errors for invalid paths, but no panics
		if err1 != nil {
			t.Logf("LoadServicesFromFile error for path %q: %v", filePath, err1)
		}
		if err2 != nil {
			t.Logf("LoadCronJobsFromFile error for path %q: %v", filePath, err2)
		}
		if err3 != nil {
			t.Logf("LoadUsersFromFile error for path %q: %v", filePath, err3)
		}
		if err4 != nil {
			t.Logf("LoadSystemStateFromFile error for path %q: %v", filePath, err4)
		}
	})
}

// FuzzJSONStructures tests various JSON structure variations
func FuzzJSONStructures(f *testing.F) {
	// Seed with edge case JSON structures
	f.Add(`{"services": null}`)
	f.Add(`{"services": "not an array"}`)
	f.Add(`{"services": [null]}`)
	f.Add(`{"services": [{}]}`)
	f.Add(`{"services": [{"name": null}]}`)
	f.Add(`{"services": [{"enabled": "not a bool"}]}`)
	f.Add(`{"metadata": null}`)
	f.Add(`{"security": "not an object"}`)

	f.Fuzz(func(t *testing.T, jsonContent string) {
		var state SystemState
		
		// Test JSON unmarshaling with fuzzed content
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("JSON unmarshaling panicked with input %q: %v", jsonContent, r)
			}
		}()

		err := json.Unmarshal([]byte(jsonContent), &state)
		if err != nil {
			t.Logf("JSON unmarshal error for input %q: %v", jsonContent, err)
		}
	})
}