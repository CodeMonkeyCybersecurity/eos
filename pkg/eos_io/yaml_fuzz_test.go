// pkg/eos_io/yaml_fuzz_test.go
package eos_io

import (
	"context"
	"os"
	"strings"
	"testing"
)

// FuzzParseYAMLString tests YAML parsing with malicious inputs
func FuzzParseYAMLString(f *testing.F) {
	// Seed with basic valid YAML
	f.Add("key: value")
	f.Add("list:\n  - item1\n  - item2")
	f.Add("nested:\n  inner:\n    value: test")
	
	// Seed with potentially problematic YAML
	f.Add("&anchor\nref: *anchor")  // YAML aliases
	f.Add("!!str value")            // YAML tags
	f.Add("---\nkey: value\n...")   // Document separators
	
	f.Fuzz(func(t *testing.T, yamlContent string) {
		ctx := context.Background()
		
		// Test that we don't panic on malicious YAML
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("YAML parsing panicked on input: %v", r)
			}
		}()
		
		// Test basic YAML parsing
		result, err := ParseYAMLString(ctx, yamlContent)
		if err == nil && result != nil {
			// If parsing succeeded, ensure result is reasonable
			if len(result) > 1000000 {
				t.Errorf("YAML parsing created unexpectedly large result: %d items", len(result))
			}
		}
	})
}

// FuzzReadYAML tests file-based YAML reading with malicious content
func FuzzReadYAML(f *testing.F) {
	f.Add("simple.yaml", "key: value")
	f.Add("complex.yaml", "list:\n  - item1\n  - item2")
	
	f.Fuzz(func(t *testing.T, filename, content string) {
		ctx := context.Background()
		
		// Skip empty filename or content that would cause obvious errors
		if filename == "" || strings.Contains(filename, "\x00") {
			return
		}
		
		// Create temporary file with fuzzed content
		tmpFile := t.TempDir() + "/" + filename
		if err := os.WriteFile(tmpFile, []byte(content), 0644); err != nil {
			return // Skip if we can't create the file
		}
		
		// Test reading the file
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("ReadYAML panicked on file %s with content: %s, panic: %v", filename, content, r)
			}
		}()
		
		var result map[string]interface{}
		err := ReadYAML(ctx, tmpFile, &result)
		if err == nil && result != nil {
			// Verify reasonable output size
			if len(result) > 1000000 {
				t.Errorf("ReadYAML produced unexpectedly large result from file %s", filename)
			}
		}
	})
}

// FuzzWriteYAML tests YAML marshaling with complex data structures
func FuzzWriteYAML(f *testing.F) {
	f.Add(map[string]interface{}{"key": "value"})
	f.Add(map[string]interface{}{"list": []string{"a", "b", "c"}})
	
	f.Fuzz(func(t *testing.T, data map[string]interface{}) {
		ctx := context.Background()
		tmpFile := t.TempDir() + "/test.yaml"
		
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("WriteYAML panicked on data: %v, panic: %v", data, r)
			}
		}()
		
		// Test writing YAML
		err := WriteYAML(ctx, tmpFile, data)
		if err != nil {
			return // Expected for some malformed data
		}
		
		// If write succeeded, verify we can read it back
		var result map[string]interface{}
		err = ReadYAML(ctx, tmpFile, &result)
		if err != nil {
			t.Errorf("Failed to read back written YAML file: %v", err)
		}
		
		// Verify round-trip didn't create infinite expansion
		if result != nil && len(result) > len(data)*100 {
			t.Errorf("YAML round-trip expanded data unexpectedly: original %d items, result %d items", 
				len(data), len(result))
		}
	})
}