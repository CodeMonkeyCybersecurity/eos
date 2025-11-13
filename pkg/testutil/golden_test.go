package testutil

import (
	"testing"
)

// TestGoldenFile_BasicUsage demonstrates basic golden file testing
func TestGoldenFile_BasicUsage(t *testing.T) {
	t.Parallel()

	// Example: Testing generated configuration
	generatedConfig := `version: "3.8"
services:
  app:
    image: myapp:latest
    ports:
      - "8080:8080"
    environment:
      - LOG_LEVEL=info
`

	golden := NewGolden(t)
	golden.Assert(generatedConfig)
}

// TestGoldenFile_MultipleSnapshots demonstrates using named snapshots
func TestGoldenFile_MultipleSnapshots(t *testing.T) {
	t.Parallel()

	golden := NewGolden(t)

	// Docker Compose file
	composeFile := `version: "3.8"
services:
  web:
    image: nginx:latest
    ports:
      - "80:80"
`
	golden.AssertWithName("docker-compose", composeFile)

	// Systemd unit file
	unitFile := `[Unit]
Description=My Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/myservice

[Install]
WantedBy=multi-user.target
`
	golden.AssertWithName("systemd-unit", unitFile)
}

// TestGoldenFile_TableDriven demonstrates table-driven tests with golden files
func TestGoldenFile_TableDriven(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		input  string
		output string
	}{
		{
			name:   "basic-service",
			input:  "nginx",
			output: "version: \"3.8\"\nservices:\n  nginx:\n    image: nginx:latest\n",
		},
		{
			name:   "database-service",
			input:  "postgres",
			output: "version: \"3.8\"\nservices:\n  postgres:\n    image: postgres:15\n",
		},
	}

	golden := NewGolden(t)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			golden.AssertWithName(tt.name, tt.output)
		})
	}
}

// TestGoldenFile_ConvenienceFunctions tests the convenience helper functions
func TestGoldenFile_ConvenienceFunctions(t *testing.T) {
	t.Parallel()

	t.Run("GoldenString", func(t *testing.T) {
		t.Parallel()
		output := "Hello, Golden Files!"
		GoldenString(t, output)
	})

	t.Run("GoldenBytes", func(t *testing.T) {
		t.Parallel()
		output := []byte("Binary data: \x00\x01\x02\x03")
		GoldenBytes(t, output)
	})
}

// Example test showing real-world Docker Compose generation
func Example_dockerComposeGeneration() {
	// This would be a real test in pkg/docker/compose_test.go
	type ServiceConfig struct {
		Name  string
		Image string
		Port  int
	}

	generateDockerCompose := func(config ServiceConfig) string {
		return `version: "3.8"
services:
  ` + config.Name + `:
    image: ` + config.Image + `
    ports:
      - "` + string(rune(config.Port)) + `:` + string(rune(config.Port)) + `"
`
	}

	// In actual test:
	// golden := NewGolden(t)
	// output := generateDockerCompose(config)
	// golden.Assert(output)

	_ = generateDockerCompose // Suppress unused warning
}

// Example test showing systemd unit file generation
func Example_systemdUnitGeneration() {
	// This would be a real test in pkg/systemd/unit_test.go
	type UnitConfig struct {
		Service     string
		Description string
		ExecStart   string
	}

	generateSystemdUnit := func(config UnitConfig) string {
		return `[Unit]
Description=` + config.Description + `
After=network.target

[Service]
Type=simple
ExecStart=` + config.ExecStart + `
Restart=on-failure

[Install]
WantedBy=multi-user.target
`
	}

	// In actual test:
	// golden := NewGolden(t)
	// output := generateSystemdUnit(config)
	// golden.Assert(output)

	_ = generateSystemdUnit // Suppress unused warning
}
