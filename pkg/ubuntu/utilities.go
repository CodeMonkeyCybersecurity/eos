package ubuntu

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

func installLynis(rc *eos_io.RuntimeContext) error {
	if rc == nil || rc.Ctx == nil {
		return fmt.Errorf("runtime context is nil")
	}
	logger := otelzap.Ctx(rc.Ctx)

	// Add Lynis repository key using wget and gpg commands
	keyURL := "https://packages.cisofy.com/keys/cisofy-software-public.key"

	// Download the key first
	if err := execute.RunSimple(rc.Ctx, "wget", "-O", "/tmp/cisofy-key.asc", keyURL); err != nil {
		return fmt.Errorf("download Lynis GPG key: %w", err)
	}

	// Dearmor and install the key
	if err := execute.RunSimple(rc.Ctx, "gpg", "--dearmor", "--output", "/usr/share/keyrings/cisofy-archive-keyring.gpg", "/tmp/cisofy-key.asc"); err != nil {
		return fmt.Errorf("add Lynis GPG key: %w", err)
	}

	// Clean up temporary file
	_ = os.Remove("/tmp/cisofy-key.asc") // Ignore error for cleanup

	// Add Lynis repository
	repoLine := "deb [signed-by=/usr/share/keyrings/cisofy-archive-keyring.gpg] https://packages.cisofy.com/community/lynis/deb/ stable main"
	repoPath := "/etc/apt/sources.list.d/cisofy-lynis.list"
	if err := os.WriteFile(repoPath, []byte(repoLine+"\n"), shared.ConfigFilePerm); err != nil {
		return fmt.Errorf("write Lynis repo file: %w", err)
	}

	// Update package list
	if err := execute.RunSimple(rc.Ctx, "apt-get", "update"); err != nil {
		return fmt.Errorf("update package list: %w", err)
	}

	// Install Lynis
	if err := execute.RunSimple(rc.Ctx, "apt-get", "install", "-y", "lynis"); err != nil {
		return fmt.Errorf("install Lynis: %w", err)
	}

	logger.Info(" Lynis security auditing tool installed")
	return nil
}

func installNeedrestart(rc *eos_io.RuntimeContext) error {
	if rc == nil || rc.Ctx == nil {
		return fmt.Errorf("runtime context is nil")
	}
	logger := otelzap.Ctx(rc.Ctx)

	// Install needrestart
	if err := execute.RunSimple(rc.Ctx, "apt-get", "install", "-y", "needrestart"); err != nil {
		return fmt.Errorf("install needrestart: %w", err)
	}

	// Configure needrestart for automatic mode
	configPath := "/etc/needrestart/conf.d/auto.conf"
	configContent := `# Automatically restart services
$nrconf{restart} = 'a';
`
	// Create config directory if it doesn't exist
	configDir := "/etc/needrestart/conf.d"
	if err := os.MkdirAll(configDir, shared.ServiceDirPerm); err != nil {
		return fmt.Errorf("create needrestart config dir: %w", err)
	}

	if err := os.WriteFile(configPath, []byte(configContent), shared.ConfigFilePerm); err != nil {
		return fmt.Errorf("write needrestart config: %w", err)
	}

	logger.Info(" Needrestart configured for automatic service restarts")
	return nil
}
