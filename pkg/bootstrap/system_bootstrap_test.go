// pkg/bootstrap/system_bootstrap_test.go

package bootstrap

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

func TestIsSystemBootstrapped(t *testing.T) {
	tests := []struct {
		name             string
		setupMarkerFiles []string
		wantBootstrapped bool
	}{
		{
			name:             "no markers - not bootstrapped",
			setupMarkerFiles: []string{},
			wantBootstrapped: false,
		},
		{
			name:             "bootstrap marker file exists - bootstrapped",
			setupMarkerFiles: []string{"/tmp/test-bootstrap/.bootstrapped"},
			wantBootstrapped: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save original values
			originalMarker := bootstrapMarkerFile
			originalVault := vaultMarkerFile

			defer func() {
				bootstrapMarkerFile = originalMarker
				vaultMarkerFile = originalVault
			}()

			if len(tt.setupMarkerFiles) > 0 {
				// Create temporary directory and file for testing
				tempDir := "/tmp/test-bootstrap"
				_ = os.MkdirAll(tempDir, 0755)
				defer os.RemoveAll(tempDir)

				// Override the variables temporarily for test
				bootstrapMarkerFile = filepath.Join(tempDir, ".bootstrapped")
				vaultMarkerFile = "/tmp/nonexistent-vault-marker"

				if tt.setupMarkerFiles[0] != "" {
					_ = os.WriteFile(bootstrapMarkerFile, []byte("test"), 0644)
				}
			} else {
				// Set to non-existent paths for negative test
				bootstrapMarkerFile = "/tmp/nonexistent-bootstrap-marker"
				vaultMarkerFile = "/tmp/nonexistent-vault-marker"
			}

			got := IsSystemBootstrapped()
			if got != tt.wantBootstrapped {
				t.Errorf("IsSystemBootstrapped() = %v, want %v", got, tt.wantBootstrapped)
			}
		})
	}
}

func TestShouldPromptForBootstrap(t *testing.T) {
	tests := []struct {
		name    string
		cmdName string
		want    bool
	}{
		{
			name:    "help command should not prompt",
			cmdName: "help",
			want:    false,
		},
		{
			name:    "version command should not prompt",
			cmdName: "version",
			want:    false,
		},
		{
			name:    "bootstrap command should not prompt",
			cmdName: "bootstrap",
			want:    false,
		},
		{
			name:    "self command should not prompt",
			cmdName: "self",
			want:    false,
		},
		{
			name:    "install command should not prompt",
			cmdName: "install",
			want:    false,
		},
		{
			name:    "test command should not prompt",
			cmdName: "test",
			want:    false,
		},
		{
			name:    "test-cmd should not prompt",
			cmdName: "test-cmd",
			want:    false,
		},
		{
			name:    "create command should prompt when not bootstrapped",
			cmdName: "create",
			want:    true,
		},
		{
			name:    "update command should not prompt (exempt command)",
			cmdName: "update",
			want:    false, // Fixed: update is in exempt commands list
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Mock system as not bootstrapped for these tests
			originalMarker := bootstrapMarkerFile
			originalVault := vaultMarkerFile

			// Setup non-bootstrapped state
			bootstrapMarkerFile = "/tmp/nonexistent-bootstrap-marker"
			vaultMarkerFile = "/tmp/nonexistent-vault-marker"

			defer func() {
				bootstrapMarkerFile = originalMarker
				vaultMarkerFile = originalVault
			}()

			got := ShouldPromptForBootstrap(tt.cmdName)
			if got != tt.want {
				t.Errorf("ShouldPromptForBootstrap(%q) = %v, want %v", tt.cmdName, got, tt.want)
			}
		})
	}
}

// TestStateValidation tests the core state validation functions
func TestStateValidation(t *testing.T) {
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	t.Run("IsBootstrapComplete with no validators", func(t *testing.T) {
		originalValidator := PhaseValidators
		PhaseValidators = map[string]PhaseValidator{}
		defer func() { PhaseValidators = originalValidator }()

		complete, missing := IsBootstrapComplete(rc)
		if complete {
			t.Errorf("IsBootstrapComplete() = %v, want false when no phases validated", complete)
		}
		if len(missing) != 2 { //  and -api are required
			t.Errorf("IsBootstrapComplete() missing phases = %v, want 2 missing phases", missing)
		}
	})

	t.Run("IsBootstrapComplete with all phases complete", func(t *testing.T) {
		originalValidator := PhaseValidators
		PhaseValidators = map[string]PhaseValidator{
			"":     func(rc *eos_io.RuntimeContext) (bool, error) { return true, nil },
			"-api": func(rc *eos_io.RuntimeContext) (bool, error) { return true, nil },
		}
		defer func() { PhaseValidators = originalValidator }()

		complete, missing := IsBootstrapComplete(rc)
		if !complete {
			t.Errorf("IsBootstrapComplete() = %v, want true when all phases validated", complete)
		}
		if len(missing) != 0 {
			t.Errorf("IsBootstrapComplete() missing phases = %v, want 0 missing phases", missing)
		}
	})
}
