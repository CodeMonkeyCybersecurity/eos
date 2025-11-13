package ubuntu

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

const osqueryConfig = `{
  "options": {
    "config_plugin": "filesystem",
    "logger_plugin": "filesystem",
    "logger_path": "/var/log/osquery",
    "disable_logging": "false",
    "schedule_splay_percent": "10",
    "worker_threads": "2",
    "enable_monitor": "true"
  },
  "schedule": {
    "system_info": {
      "query": "SELECT hostname, cpu_brand, physical_memory FROM system_info;",
      "interval": 3600
    },
    "open_sockets": {
      "query": "SELECT distinct pid, family, protocol, local_address, local_port, remote_address, remote_port, path FROM process_open_sockets WHERE path <> '' or remote_address <> '';",
      "interval": 60
    },
    "logged_in_users": {
      "query": "SELECT liu.*, p.name, p.cmdline, p.cwd, p.root FROM logged_in_users liu, processes p WHERE liu.pid = p.pid;",
      "interval": 60
    },
    "crontab_snapshot": {
      "query": "SELECT * FROM crontab;",
      "interval": 300
    },
    "kernel_modules": {
      "query": "SELECT * FROM kernel_modules;",
      "interval": 300
    }
  }
}`

func installOsquery(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Add osquery official repository GPG key
	logger.Info(" Adding osquery repository GPG key")

	// Download GPG key to temporary file first
	keyPath := "/tmp/osquery-key.gpg"
	if err := execute.RunSimple(rc.Ctx, "curl", "-fsSL", "https://pkg.osquery.io/deb/pubkey.gpg", "-o", keyPath); err != nil {
		return fmt.Errorf("download osquery GPG key: %w", err)
	}
	defer func() {
		if err := os.Remove(keyPath); err != nil {
			logger.Warn("Failed to remove temporary GPG key file", zap.String("path", keyPath), zap.Error(err))
		}
	}()

	// Convert and install GPG key
	keyringPath := "/usr/share/keyrings/osquery-keyring.gpg"
	if err := execute.RunSimple(rc.Ctx, "gpg", "--dearmor", "--output", keyringPath, keyPath); err != nil {
		// Fallback: use apt-key (deprecated but more reliable)
		logger.Warn("GPG keyring method failed, trying apt-key fallback")
		if err := execute.RunSimple(rc.Ctx, "apt-key", "add", keyPath); err != nil {
			return fmt.Errorf("add osquery GPG key: %w", err)
		}
		// Use legacy repository line for apt-key
		repoLine := "deb https://pkg.osquery.io/deb deb main"
		repoPath := "/etc/apt/sources.list.d/osquery.list"
		if err := os.WriteFile(repoPath, []byte(repoLine+"\n"), shared.ConfigFilePerm); err != nil {
			return fmt.Errorf("create osquery repo file: %w", err)
		}
	} else {
		// Use modern signed-by syntax
		repoLine := "deb [signed-by=/usr/share/keyrings/osquery-keyring.gpg] https://pkg.osquery.io/deb deb main"
		repoPath := "/etc/apt/sources.list.d/osquery.list"
		if err := os.WriteFile(repoPath, []byte(repoLine+"\n"), shared.ConfigFilePerm); err != nil {
			return fmt.Errorf("create osquery repo file: %w", err)
		}
	}

	// Update package lists
	logger.Info(" Updating package lists")
	if err := execute.RunSimple(rc.Ctx, "apt-get", "update"); err != nil {
		return fmt.Errorf("update package lists: %w", err)
	}

	// Install osquery via apt
	logger.Info(" Installing osquery from repository")
	if err := execute.RunSimple(rc.Ctx, "apt-get", "install", "-y", "osquery"); err != nil {
		return fmt.Errorf("install osquery: %w", err)
	}

	// Create osquery configuration directory if it doesn't exist
	configDir := "/etc/osquery"
	if err := os.MkdirAll(configDir, shared.ServiceDirPerm); err != nil {
		return fmt.Errorf("create osquery config dir: %w", err)
	}

	// Write osquery configuration
	configPath := "/etc/osquery/osquery.conf"
	if err := os.WriteFile(configPath, []byte(osqueryConfig), shared.ConfigFilePerm); err != nil {
		return fmt.Errorf("write osquery config: %w", err)
	}
	logger.Info("Osquery configuration written", zap.String("path", configPath))

	// Start and enable osqueryd
	if err := execute.RunSimple(rc.Ctx, "systemctl", "restart", "osqueryd"); err != nil {
		return fmt.Errorf("restart osqueryd: %w", err)
	}

	if err := execute.RunSimple(rc.Ctx, "systemctl", "enable", "osqueryd"); err != nil {
		return fmt.Errorf("enable osqueryd: %w", err)
	}

	logger.Info(" Osquery installed and configured")
	return nil
}
