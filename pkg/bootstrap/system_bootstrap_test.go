// pkg/bootstrap/system_bootstrap_test.go

package bootstrap

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsSystemBootstrapped(t *testing.T) {
	tests := []struct {
		name           string
		setupFiles     []string
		wantBootstrapped bool
	}{
		{
			name:           "no marker files exist",
			setupFiles:     []string{},
			wantBootstrapped: false,
		},
		{
			name:           "bootstrap marker exists",
			setupFiles:     []string{"/tmp/test-bootstrap/.bootstrapped"},
			wantBootstrapped: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save original values
			originalMarker := bootstrapMarkerFile
			originalVault := vaultMarkerFile
			
			if len(tt.setupFiles) > 0 {
				// Create temporary directory and file for testing
				tempDir := "/tmp/test-bootstrap"
				os.MkdirAll(tempDir, 0755)
				defer os.RemoveAll(tempDir)
				
				// Override the variables temporarily for test
				bootstrapMarkerFile = filepath.Join(tempDir, ".bootstrapped")
				vaultMarkerFile = "/tmp/nonexistent-vault-marker"
				defer func() { 
					bootstrapMarkerFile = originalMarker
					vaultMarkerFile = originalVault
				}()
				
				if tt.setupFiles[0] != "" {
					os.WriteFile(bootstrapMarkerFile, []byte("test"), 0644)
				}
			} else {
				// Set to non-existent paths for negative test
				bootstrapMarkerFile = "/tmp/nonexistent-bootstrap-marker"
				vaultMarkerFile = "/tmp/nonexistent-vault-marker"
				defer func() { 
					bootstrapMarkerFile = originalMarker
					vaultMarkerFile = originalVault
				}()
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
			name:    "update command should prompt when not bootstrapped",
			cmdName: "update",
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Ensure system appears not bootstrapped for these tests
			originalMarker := bootstrapMarkerFile
			originalVault := vaultMarkerFile
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