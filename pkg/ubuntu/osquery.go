package ubuntu

import (
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

	// Download osquery package
	osqueryURL := "https://github.com/osquery/osquery/releases/download/5.11.0/osquery_5.11.0-1.linux_amd64.deb"
	osqueryPath := "/tmp/osquery.deb"

	logger.Info("Downloading osquery", zap.String("url", osqueryURL))
	if err := execute.RunSimple(rc.Ctx, "curl", "-L", osqueryURL, "-o", osqueryPath); err != nil {
		return fmt.Errorf("download osquery: %w", err)
	}

	// Install osquery
	if err := execute.RunSimple(rc.Ctx, "dpkg", "-i", osqueryPath); err != nil {
		// Try to fix dependencies if installation fails
		logger.Warn("dpkg install failed, attempting to fix dependencies")
		if fixErr := execute.RunSimple(rc.Ctx, "apt-get", "install", "-f", "-y"); fixErr != nil {
			return fmt.Errorf("fix dependencies: %w", fixErr)
		}
	}

	// Clean up
	os.Remove(osqueryPath)

	// Create osquery configuration directory if it doesn't exist
	configDir := "/etc/osquery"
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("create osquery config dir: %w", err)
	}

	// Write osquery configuration
	configPath := "/etc/osquery/osquery.conf"
	if err := os.WriteFile(configPath, []byte(osqueryConfig), 0644); err != nil {
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

	logger.Info("✅ Osquery installed and configured")
	return nil
}