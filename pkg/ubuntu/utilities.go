package ubuntu

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

func installLynis(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Add Lynis repository key
	keyURL := "https://packages.cisofy.com/keys/cisofy-software-public.key"
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "sh",
		Args:    []string{"-c", fmt.Sprintf("wget -O - %s | gpg --dearmor | tee /usr/share/keyrings/cisofy-archive-keyring.gpg >/dev/null", keyURL)},
		Shell:   true,
	}); err != nil {
		return fmt.Errorf("add Lynis GPG key: %w", err)
	}

	// Add Lynis repository
	repoLine := "deb [signed-by=/usr/share/keyrings/cisofy-archive-keyring.gpg] https://packages.cisofy.com/community/lynis/deb/ stable main"
	repoPath := "/etc/apt/sources.list.d/cisofy-lynis.list"
	if err := os.WriteFile(repoPath, []byte(repoLine+"\n"), 0644); err != nil {
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
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("create needrestart config dir: %w", err)
	}

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		return fmt.Errorf("write needrestart config: %w", err)
	}

	logger.Info(" Needrestart configured for automatic service restarts")
	return nil
}