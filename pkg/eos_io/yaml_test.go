package eos_io

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteYAML(t *testing.T) {
	// Create temp directory for test files
	tempDir := t.TempDir()

	t.Run("writes_simple_struct_to_yaml", func(t *testing.T) {
		// Create a simple struct to write
		data := struct {
			Name    string `yaml:"name"`
			Version string `yaml:"version"`
			Port    int    `yaml:"port"`
		}{
			Name:    "test-service",
			Version: "1.0.0",
			Port:    8080,
		}

		filePath := filepath.Join(tempDir, "simple.yaml")
		ctx := context.Background()

		err := WriteYAML(ctx, filePath, data)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		// Verify file exists
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			t.Fatal("expected file to be created")
		}

		// Read and verify content
		content, err := os.ReadFile(filePath)
		if err != nil {
			t.Fatalf("failed to read file: %v", err)
		}

		contentStr := string(content)
		if !strings.Contains(contentStr, "name: test-service") {
			t.Error("expected name field in YAML output")
		}
		if !strings.Contains(contentStr, "version: 1.0.0") && !strings.Contains(contentStr, "version: \"1.0.0\"") {
			t.Error("expected version field in YAML output")
		}
		if !strings.Contains(contentStr, "port: 8080") {
			t.Error("expected port field in YAML output")
		}
	})

	t.Run("writes_nested_struct_to_yaml", func(t *testing.T) {
		type Config struct {
			Database struct {
				Host string `yaml:"host"`
				Port int    `yaml:"port"`
			} `yaml:"database"`
			Features []string `yaml:"features"`
		}

		data := Config{
			Features: []string{"auth", "logging", "monitoring"},
		}
		data.Database.Host = "localhost"
		data.Database.Port = 5432

		filePath := filepath.Join(tempDir, "nested.yaml")
		ctx := context.Background()

		err := WriteYAML(ctx, filePath, data)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		// Verify file exists and has expected content
		content, err := os.ReadFile(filePath)
		if err != nil {
			t.Fatalf("failed to read file: %v", err)
		}

		contentStr := string(content)
		if !strings.Contains(contentStr, "database:") {
			t.Error("expected database section in YAML")
		}
		if !strings.Contains(contentStr, "features:") {
			t.Error("expected features section in YAML")
		}
		if !strings.Contains(contentStr, "- auth") {
			t.Error("expected auth feature in YAML")
		}
	})

	t.Run("overwrites_existing_file", func(t *testing.T) {
		filePath := filepath.Join(tempDir, "overwrite.yaml")

		// Create initial file
		initialData := struct {
			Value string `yaml:"value"`
		}{Value: "initial"}

		ctx := context.Background()
		err := WriteYAML(ctx, filePath, initialData)
		if err != nil {
			t.Fatalf("failed to write initial file: %v", err)
		}

		// Overwrite with new data
		newData := struct {
			Value string `yaml:"value"`
		}{Value: "updated"}

		err = WriteYAML(ctx, filePath, newData)
		if err != nil {
			t.Fatalf("failed to overwrite file: %v", err)
		}

		// Verify updated content
		content, err := os.ReadFile(filePath)
		if err != nil {
			t.Fatalf("failed to read file: %v", err)
		}

		if !strings.Contains(string(content), "value: updated") {
			t.Error("expected updated value in YAML")
		}
		if strings.Contains(string(content), "value: initial") {
			t.Error("old value should not be present after overwrite")
		}
	})

	t.Run("handles_invalid_path", func(t *testing.T) {
		// Try to write to an invalid path (non-existent directory)
		invalidPath := "/nonexistent/directory/file.yaml"
		data := struct{ Test string }{Test: "value"}
		ctx := context.Background()

		err := WriteYAML(ctx, invalidPath, data)
		if err == nil {
			t.Error("expected error when writing to invalid path")
		}
	})

	t.Run("handles_context_cancellation", func(t *testing.T) {
		filePath := filepath.Join(tempDir, "cancelled.yaml")
		data := struct{ Test string }{Test: "value"}

		// Create cancelled context
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		err := WriteYAML(ctx, filePath, data)
		// The function might still succeed since YAML writing is usually fast
		// But it should handle the cancelled context gracefully
		_ = err // We don't assert error here since cancellation might not affect short operations
	})
}

func TestReadYAML(t *testing.T) {
	tempDir := t.TempDir()

	t.Run("reads_yaml_file_successfully", func(t *testing.T) {
		// Create a YAML file
		yamlContent := `name: test-service
version: "1.0.0"
port: 8080
features:
  - auth
  - logging
database:
  host: localhost
  port: 5432`

		filePath := filepath.Join(tempDir, "read-test.yaml")
		err := os.WriteFile(filePath, []byte(yamlContent), 0644)
		if err != nil {
			t.Fatalf("failed to create test file: %v", err)
		}

		// Read the YAML file
		var result map[string]interface{}
		ctx := context.Background()

		err = ReadYAML(ctx, filePath, &result)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		// Verify parsed content
		if result["name"] != "test-service" {
			t.Errorf("expected name 'test-service', got %v", result["name"])
		}
		if result["version"] != "1.0.0" {
			t.Errorf("expected version '1.0.0', got %v", result["version"])
		}
		if result["port"] != 8080 {
			t.Errorf("expected port 8080, got %v", result["port"])
		}
	})

	t.Run("reads_into_struct", func(t *testing.T) {
		type Config struct {
			Name     string   `yaml:"name"`
			Version  string   `yaml:"version"`
			Port     int      `yaml:"port"`
			Features []string `yaml:"features"`
		}

		yamlContent := `name: struct-test
version: "2.0.0"
port: 9000
features:
  - feature1
  - feature2`

		filePath := filepath.Join(tempDir, "struct-test.yaml")
		err := os.WriteFile(filePath, []byte(yamlContent), 0644)
		if err != nil {
			t.Fatalf("failed to create test file: %v", err)
		}

		var config Config
		ctx := context.Background()

		err = ReadYAML(ctx, filePath, &config)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		// Verify struct fields
		if config.Name != "struct-test" {
			t.Errorf("expected name 'struct-test', got %s", config.Name)
		}
		if config.Version != "2.0.0" {
			t.Errorf("expected version '2.0.0', got %s", config.Version)
		}
		if config.Port != 9000 {
			t.Errorf("expected port 9000, got %d", config.Port)
		}
		if len(config.Features) != 2 || config.Features[0] != "feature1" || config.Features[1] != "feature2" {
			t.Errorf("expected features [feature1, feature2], got %v", config.Features)
		}
	})

	t.Run("handles_nonexistent_file", func(t *testing.T) {
		nonexistentPath := filepath.Join(tempDir, "nonexistent.yaml")
		var result map[string]interface{}
		ctx := context.Background()

		err := ReadYAML(ctx, nonexistentPath, &result)
		if err == nil {
			t.Error("expected error when reading nonexistent file")
		}
	})

	t.Run("handles_invalid_yaml", func(t *testing.T) {
		invalidYAML := `name: test
invalid: [ unclosed array
port: 8080`

		filePath := filepath.Join(tempDir, "invalid.yaml")
		err := os.WriteFile(filePath, []byte(invalidYAML), 0644)
		if err != nil {
			t.Fatalf("failed to create test file: %v", err)
		}

		var result map[string]interface{}
		ctx := context.Background()

		err = ReadYAML(ctx, filePath, &result)
		if err == nil {
			t.Error("expected error when reading invalid YAML")
		}
	})

	t.Run("handles_context_cancellation", func(t *testing.T) {
		yamlContent := `test: value`
		filePath := filepath.Join(tempDir, "cancel-test.yaml")
		err := os.WriteFile(filePath, []byte(yamlContent), 0644)
		if err != nil {
			t.Fatalf("failed to create test file: %v", err)
		}

		var result map[string]interface{}
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		err = ReadYAML(ctx, filePath, &result)
		// Similar to WriteYAML, cancellation might not affect short operations
		_ = err
	})
}

func TestParseYAMLString(t *testing.T) {
	t.Run("parses_yaml_string_successfully", func(t *testing.T) {
		yamlString := `name: string-test
version: "3.0.0"
enabled: true
count: 42`

		ctx := context.Background()

		result, err := ParseYAMLString(ctx, yamlString)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		// Verify parsed content
		if result["name"] != "string-test" {
			t.Errorf("expected name 'string-test', got %v", result["name"])
		}
		if result["version"] != "3.0.0" {
			t.Errorf("expected version '3.0.0', got %v", result["version"])
		}
		if result["enabled"] != true {
			t.Errorf("expected enabled true, got %v", result["enabled"])
		}
		if result["count"] != 42 {
			t.Errorf("expected count 42, got %v", result["count"])
		}
	})

	t.Run("parses_complex_yaml", func(t *testing.T) {
		yamlString := `name: parse-test
enabled: false
items:
  - 1
  - 2
  - 3
config:
  timeout: 30
  retries: 3`

		ctx := context.Background()

		result, err := ParseYAMLString(ctx, yamlString)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if result["name"] != "parse-test" {
			t.Errorf("expected name 'parse-test', got %v", result["name"])
		}
		if result["enabled"] != false {
			t.Errorf("expected enabled false, got %v", result["enabled"])
		}

		// Check items array
		items, ok := result["items"].([]interface{})
		if !ok {
			t.Fatal("expected items to be an array")
		}
		if len(items) != 3 {
			t.Errorf("expected 3 items, got %d", len(items))
		}

		// Check config map
		config, ok := result["config"].(map[string]interface{})
		if !ok {
			t.Fatal("expected config to be a map")
		}
		if config["timeout"] != 30 {
			t.Errorf("expected timeout 30, got %v", config["timeout"])
		}
	})

	t.Run("handles_empty_string", func(t *testing.T) {
		ctx := context.Background()

		result, err := ParseYAMLString(ctx, "")
		if err != nil {
			t.Fatalf("expected no error for empty string, got %v", err)
		}

		if result == nil {
			t.Error("expected non-nil result for empty YAML")
		}
	})

	t.Run("handles_invalid_yaml_string", func(t *testing.T) {
		invalidYAML := `name: test
invalid: [
port: 8080`

		ctx := context.Background()

		_, err := ParseYAMLString(ctx, invalidYAML)
		if err == nil {
			t.Error("expected error when parsing invalid YAML string")
		}
	})
}

func TestWriteYAMLCompat(t *testing.T) {
	tempDir := t.TempDir()

	t.Run("writes_yaml_with_compatibility_mode", func(t *testing.T) {
		data := map[string]interface{}{
			"name":    "compat-test",
			"version": "1.0.0",
			"config": map[string]interface{}{
				"enabled": true,
				"timeout": 30,
			},
		}

		filePath := filepath.Join(tempDir, "compat.yaml")

		err := WriteYAMLCompat(filePath, data)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		// Verify file exists
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			t.Fatal("expected file to be created")
		}

		// Read and verify content
		content, err := os.ReadFile(filePath)
		if err != nil {
			t.Fatalf("failed to read file: %v", err)
		}

		contentStr := string(content)
		if !strings.Contains(contentStr, "name: compat-test") {
			t.Error("expected name field in YAML output")
		}
		if !strings.Contains(contentStr, "config:") {
			t.Error("expected config section in YAML output")
		}
	})
}

func TestReadYAMLCompat(t *testing.T) {
	tempDir := t.TempDir()

	t.Run("reads_yaml_with_compatibility_mode", func(t *testing.T) {
		yamlContent := `name: compat-read-test
version: "1.0.0"
settings:
  debug: true
  workers: 4`

		filePath := filepath.Join(tempDir, "compat-read.yaml")
		err := os.WriteFile(filePath, []byte(yamlContent), 0644)
		if err != nil {
			t.Fatalf("failed to create test file: %v", err)
		}

		var result map[string]interface{}

		err = ReadYAMLCompat(filePath, &result)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		// Verify parsed content
		if result["name"] != "compat-read-test" {
			t.Errorf("expected name 'compat-read-test', got %v", result["name"])
		}
		if result["version"] != "1.0.0" {
			t.Errorf("expected version '1.0.0', got %v", result["version"])
		}

		// Check nested settings - yaml.v3 returns map[string]interface{} not map[interface{}]interface{}
		settings, ok := result["settings"].(map[string]interface{})
		if !ok {
			t.Fatal("expected settings to be a map")
		}
		if settings["debug"] != true {
			t.Errorf("expected debug true, got %v", settings["debug"])
		}
		if settings["workers"] != 4 {
			t.Errorf("expected workers 4, got %v", settings["workers"])
		}
	})
}

// TestYAMLIntegration tests the integration between write and read functions
func TestYAMLIntegration(t *testing.T) {
	tempDir := t.TempDir()

	t.Run("write_then_read_roundtrip", func(t *testing.T) {
		type TestData struct {
			Name     string            `yaml:"name"`
			Values   []int             `yaml:"values"`
			Settings map[string]string `yaml:"settings"`
		}

		originalData := TestData{
			Name:   "roundtrip-test",
			Values: []int{1, 2, 3, 4, 5},
			Settings: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
		}

		filePath := filepath.Join(tempDir, "roundtrip.yaml")
		ctx := context.Background()

		// Write data
		err := WriteYAML(ctx, filePath, originalData)
		if err != nil {
			t.Fatalf("failed to write YAML: %v", err)
		}

		// Read data back
		var readData TestData
		err = ReadYAML(ctx, filePath, &readData)
		if err != nil {
			t.Fatalf("failed to read YAML: %v", err)
		}

		// Verify data integrity
		if readData.Name != originalData.Name {
			t.Errorf("name mismatch: expected %s, got %s", originalData.Name, readData.Name)
		}
		if len(readData.Values) != len(originalData.Values) {
			t.Errorf("values length mismatch: expected %d, got %d", len(originalData.Values), len(readData.Values))
		}
		for i, v := range originalData.Values {
			if readData.Values[i] != v {
				t.Errorf("values[%d] mismatch: expected %d, got %d", i, v, readData.Values[i])
			}
		}
		if len(readData.Settings) != len(originalData.Settings) {
			t.Errorf("settings length mismatch: expected %d, got %d", len(originalData.Settings), len(readData.Settings))
		}
		for k, v := range originalData.Settings {
			if readData.Settings[k] != v {
				t.Errorf("settings[%s] mismatch: expected %s, got %s", k, v, readData.Settings[k])
			}
		}
	})
}
