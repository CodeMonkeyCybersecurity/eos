package dockerlistener

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

const (
	pythonBinary       = "python3"
	installCommand     = "apt"
	systemctlBinary    = "systemctl"
	dockerListenerName = "wazuh-agent"
)

var (
	pythonPackages = []string{
		"docker==7.1.0",
		"urllib3==1.26.20",
		"requests==2.32.2",
	}
	aptPackages = []string{"python3-venv", "python3-pip"}
)

// Setup provisions the Python virtual environment used by the Wazuh Docker listener
// and updates the DockerListener script to point at that interpreter.
func Setup(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	steps := []struct {
		description string
		run         func() error
	}{
		{"apt update", func() error { return execute.RunSimple(rc.Ctx, installCommand, "update") }},
		{"install python3-venv + pip", func() error {
			args := append([]string{"install", "-y"}, aptPackages...)
			return execute.RunSimple(rc.Ctx, installCommand, args...)
		}},
		{"create venv dir", func() error {
			return execute.RunSimple(rc.Ctx, "mkdir", "-p", shared.VenvPath)
		}},
		{"create python venv", func() error {
			return execute.RunSimple(rc.Ctx, pythonBinary, "-m", "venv", shared.VenvPath)
		}},
		{"install Docker listener requirements", func() error {
			args := append([]string{shared.VenvPath + "/bin/pip", "install"}, pythonPackages...)
			return execute.RunSimple(rc.Ctx, args[0], args[1:]...)
		}},
		{"patch DockerListener script", func() error {
			return Patch(rc)
		}},
		{"restart wazuh-agent", func() error {
			return execute.RunSimple(rc.Ctx, systemctlBinary, "restart", dockerListenerName)
		}},
	}

	for _, step := range steps {
		logger.Info(step.description)
		if err := step.run(); err != nil {
			logger.Error("step failed", zap.String("step", step.description), zap.Error(err))
			return err
		}
	}

	logger.Info("DockerListener setup complete")
	return nil
}

// Patch rewrites the DockerListener shebang to use the managed virtual environment
// and retains a backup copy alongside the original file.
func Patch(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	path := shared.DockerListener

	if _, err := os.Stat(path); os.IsNotExist(err) {
		logger.Warn("DockerListener script not found", zap.String("path", path))
		return nil
	}

	backupPath := path + ".bak"
	if err := copyFile(path, backupPath); err != nil {
		logger.Warn("Failed to backup DockerListener", zap.Error(err))
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read DockerListener: %w", err)
	}

	lines := strings.Split(string(content), "\n")
	if len(lines) < 2 {
		// Unexpected format; keep original content.
		return nil
	}

	shebang := "#!" + shared.VenvPath + "/bin/" + pythonBinary
	newContent := shebang + "\n" + strings.Join(lines[1:], "\n")

	if err := os.WriteFile(path, []byte(newContent), shared.DirPermStandard); err != nil {
		return fmt.Errorf("failed to write DockerListener: %w", err)
	}

	logger.Info("DockerListener script patched", zap.String("path", path))
	return nil
}

// Backup copies the DockerListener script into the provided directory and returns
// the path to the created backup file.
func Backup(rc *eos_io.RuntimeContext, destDir string) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)
	source := shared.DockerListener

	if _, err := os.Stat(source); err != nil {
		return "", fmt.Errorf("source DockerListener missing: %w", err)
	}

	if destDir == "" {
		return "", fmt.Errorf("backup destination directory required")
	}

	if err := os.MkdirAll(destDir, shared.DirPermStandard); err != nil {
		return "", fmt.Errorf("failed to create backup directory: %w", err)
	}

	destPath := filepath.Join(destDir, "DockerListener")
	if err := copyFile(source, destPath); err != nil {
		return "", err
	}

	logger.Info("DockerListener backed up", zap.String("path", destPath))
	return destPath, nil
}

// Restore rewrites the DockerListener script from a backup copy and restarts the agent.
func Restore(rc *eos_io.RuntimeContext, backupPath string) error {
	logger := otelzap.Ctx(rc.Ctx)
	if backupPath == "" {
		return fmt.Errorf("backup path required for restore")
	}

	if err := copyFile(backupPath, shared.DockerListener); err != nil {
		return fmt.Errorf("failed to restore DockerListener: %w", err)
	}

	if err := execute.RunSimple(rc.Ctx, systemctlBinary, "restart", dockerListenerName); err != nil {
		logger.Warn("Failed to restart wazuh-agent after restore", zap.Error(err))
		return err
	}

	logger.Info("DockerListener restored", zap.String("backup", backupPath))
	return nil
}

// Verify ensures the DockerListener is pointed at the managed virtual environment
// and that the wazuh-agent service reports healthy.
func Verify(rc *eos_io.RuntimeContext) error {
	path := shared.DockerListener
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read DockerListener: %w", err)
	}

	expected := "#!" + shared.VenvPath + "/bin/" + pythonBinary
	if !strings.HasPrefix(string(data), expected) {
		return fmt.Errorf("DockerListener shebang mismatch: expected prefix %q", expected)
	}

	if err := execute.RunSimple(rc.Ctx, systemctlBinary, "is-active", dockerListenerName); err != nil {
		return fmt.Errorf("wazuh-agent service not active: %w", err)
	}

	return nil
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, shared.DirPermStandard)
}
