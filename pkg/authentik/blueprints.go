// pkg/authentik/blueprints.go
// Authentik Blueprint export/import functionality
// P1 #3: Switch to vendor-recommended Blueprint approach for configuration management
// RATIONALE: Blueprints handle UUID remapping, dependencies, and are officially supported

package authentik

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ExportBlueprint exports Authentik configuration as Blueprint YAML
// VENDOR APPROACH: Uses `ak export_blueprint` command in worker container
// BENEFITS: Automatic UUID handling, dependency resolution, official support
// FIXED: ak export_blueprint outputs to stdout (no --output flag exists)
// EVIDENCE: https://docs.goauthentik.io/customize/blueprints/export/
func (c *Client) ExportBlueprint(ctx context.Context, outputPath string) error {
	// CORRECTED: ak export_blueprint outputs to stdout, redirect to file
	// BEFORE (WRONG): "ak", "export_blueprint", "--output", "/tmp/blueprint.yaml"
	// AFTER (CORRECT): "ak", "export_blueprint" > file
	cmd := exec.CommandContext(ctx,
		"docker", "exec",
		"hecate-server-1", // Authentik server container
		"ak", "export_blueprint",
	)

	// Capture stdout (blueprint YAML)
	output, err := cmd.Output()
	if err != nil {
		// Include stderr for diagnostics
		if exitErr, ok := err.(*exec.ExitError); ok {
			return fmt.Errorf("blueprint export failed: %w\nStderr: %s", err, string(exitErr.Stderr))
		}
		return fmt.Errorf("blueprint export failed: %w", err)
	}

	// Write blueprint output directly to host file
	if err := os.WriteFile(outputPath, output, shared.SecretFilePerm); err != nil {
		return fmt.Errorf("failed to write blueprint to %s: %w", outputPath, err)
	}

	// Verify file has content
	if len(output) == 0 {
		return fmt.Errorf("blueprint export produced empty output")
	}

	return nil
}

// ExportBlueprintToDirectory exports Blueprint and saves to specified directory
// CONVENIENCE: Wrapper around ExportBlueprint with timestamped filename
// FIXED: ak export_blueprint outputs to stdout (no --output flag exists)
// EVIDENCE: https://docs.goauthentik.io/customize/blueprints/export/
func ExportBlueprintToDirectory(rc *eos_io.RuntimeContext, outputDir string) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Create Blueprint filename
	blueprintPath := filepath.Join(outputDir, "23_authentik_blueprint.yaml")

	// CORRECTED: ak export_blueprint outputs to stdout, redirect to file
	// BEFORE (WRONG): "ak", "export_blueprint", "--output", "/tmp/blueprint.yaml"
	// AFTER (CORRECT): "ak", "export_blueprint" > file
	cmd := exec.CommandContext(rc.Ctx,
		"docker", "exec",
		"hecate-server-1",
		"ak", "export_blueprint",
	)

	logger.Info("Exporting Authentik Blueprint via ak command",
		zap.String("container", "hecate-server-1"))

	// Capture stdout (blueprint YAML)
	output, err := cmd.Output()
	if err != nil {
		// Check if container exists
		checkCmd := exec.CommandContext(rc.Ctx, "docker", "ps", "-a", "--filter", "name=hecate-server-1", "--format", "{{.Names}}")
		checkOutput, _ := checkCmd.Output()
		if len(checkOutput) == 0 {
			return "", fmt.Errorf("Authentik server container not found (hecate-server-1) - is docker-compose running?")
		}

		// Include stderr for diagnostics
		if exitErr, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("blueprint export failed: %w\nStderr: %s", err, string(exitErr.Stderr))
		}
		return "", fmt.Errorf("blueprint export failed: %w", err)
	}

	// Write blueprint output directly to host file
	if err := os.WriteFile(blueprintPath, output, shared.SecretFilePerm); err != nil {
		return "", fmt.Errorf("failed to write blueprint to %s: %w", blueprintPath, err)
	}

	// Verify file was created and has content
	info, err := os.Stat(blueprintPath)
	if err != nil {
		return "", fmt.Errorf("blueprint file not created: %w", err)
	}

	if info.Size() == 0 {
		return "", fmt.Errorf("blueprint file is empty - export may have failed silently")
	}

	logger.Info("✓ Exported Authentik Blueprint",
		zap.String("file", "23_authentik_blueprint.yaml"),
		zap.Int64("size_bytes", info.Size()),
		zap.String("format", "YAML"))

	return blueprintPath, nil
}

// ImportBlueprint imports a Blueprint YAML file to Authentik
// VENDOR APPROACH: Uses /api/v3/managed/blueprints/ endpoint
// NOTE: Authentik automatically handles UUID remapping and dependency resolution
func (c *Client) ImportBlueprint(ctx context.Context, blueprintPath string) error {
	// Read YAML file
	data, err := os.ReadFile(blueprintPath)
	if err != nil {
		return fmt.Errorf("failed to read blueprint: %w", err)
	}

	// POST to /api/v3/managed/blueprints/
	// NOTE: Content-Type must be application/x-yaml
	respData, err := c.DoRequest(ctx, "POST", "/managed/blueprints/", data)
	if err != nil {
		return fmt.Errorf("blueprint import failed: %w", err)
	}

	// Authentik returns created blueprint metadata
	_ = respData // TODO: Parse response and log blueprint UUID

	return nil
}

// ValidateBlueprint checks if a Blueprint YAML file is valid
// BASIC: Simple YAML structure validation
// TODO: Could use Authentik's blueprint schema for full validation
func ValidateBlueprint(blueprintPath string) error {
	// Check file exists
	info, err := os.Stat(blueprintPath)
	if err != nil {
		return fmt.Errorf("blueprint file not found: %w", err)
	}

	// Check minimum size (empty files are invalid)
	if info.Size() < 10 {
		return fmt.Errorf("blueprint file is too small (%d bytes) - likely empty or corrupt", info.Size())
	}

	// Read and check for YAML structure markers
	data, err := os.ReadFile(blueprintPath)
	if err != nil {
		return fmt.Errorf("failed to read blueprint: %w", err)
	}

	content := string(data)

	// Basic validation - check for required YAML fields
	requiredFields := []string{"version:", "entries:"}
	for _, field := range requiredFields {
		if !stringContains(content, field) {
			return fmt.Errorf("blueprint missing required field: %s", field)
		}
	}

	return nil
}

// stringContains checks if string s contains substring
func stringContains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
