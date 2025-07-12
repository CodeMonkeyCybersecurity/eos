// pkg/osquery/config.go

package osquery

// defaultOsqueryConfig is the default configuration for osquery
// This configuration provides a balanced security monitoring setup
const defaultOsqueryConfig = `{
  "options": {
    "config_plugin": "filesystem",
    "logger_plugin": "filesystem",
    "logger_path": "/var/log/osquery",
    "disable_logging": "false",
    "schedule_splay_percent": "10",
    "worker_threads": "2",
    "enable_monitor": "true",
    "verbose": "false",
    "host_identifier": "hostname",
    "enable_syslog": "true"
  },
  "schedule": {
    "system_info": {
      "query": "SELECT hostname, cpu_brand, physical_memory, hardware_vendor, hardware_model FROM system_info;",
      "interval": 3600,
      "description": "Basic system information"
    },
    "os_version": {
      "query": "SELECT * FROM os_version;",
      "interval": 3600,
      "description": "Operating system version details"
    },
    "network_interfaces": {
      "query": "SELECT interface, address, mask, type FROM interface_addresses WHERE type = 'ipv4';",
      "interval": 300,
      "description": "Network interface information"
    },
    "open_sockets": {
      "query": "SELECT distinct pid, family, protocol, local_address, local_port, remote_address, remote_port, path FROM process_open_sockets WHERE path <> '' or remote_address <> '';",
      "interval": 60,
      "description": "Open network connections"
    },
    "listening_ports": {
      "query": "SELECT pid, port, protocol, path FROM listening_ports;",
      "interval": 300,
      "description": "Listening network ports"
    },
    "logged_in_users": {
      "query": "SELECT liu.*, p.name, p.cmdline, p.cwd, p.root FROM logged_in_users liu, processes p WHERE liu.pid = p.pid;",
      "interval": 60,
      "description": "Currently logged in users"
    },
    "crontab_snapshot": {
      "query": "SELECT * FROM crontab;",
      "interval": 300,
      "platform": "posix",
      "description": "Scheduled cron jobs"
    },
    "kernel_modules": {
      "query": "SELECT * FROM kernel_modules;",
      "interval": 300,
      "platform": "linux",
      "description": "Loaded kernel modules"
    },
    "startup_items": {
      "query": "SELECT * FROM startup_items;",
      "interval": 3600,
      "platform": "darwin",
      "description": "macOS startup items"
    },
    "windows_services": {
      "query": "SELECT * FROM services WHERE start_type = 'AUTO_START';",
      "interval": 3600,
      "platform": "windows",
      "description": "Windows auto-start services"
    },
    "installed_applications": {
      "query": "SELECT name, version, install_date FROM programs;",
      "interval": 3600,
      "platform": "windows",
      "description": "Installed Windows applications"
    },
    "chrome_extensions": {
      "query": "SELECT uid, name, identifier, version, description, locale, update_url, author, persistent, path FROM chrome_extensions;",
      "interval": 3600,
      "description": "Chrome browser extensions"
    },
    "firefox_addons": {
      "query": "SELECT uid, name, identifier, creator, type, version, description, source_url, visible, active, disabled, autoupdate, native, location, path FROM firefox_addons;",
      "interval": 3600,
      "description": "Firefox browser addons"
    },
    "usb_devices": {
      "query": "SELECT * FROM usb_devices;",
      "interval": 300,
      "description": "Connected USB devices"
    },
    "kernel_info": {
      "query": "SELECT * FROM kernel_info;",
      "interval": 3600,
      "platform": "posix",
      "description": "Kernel information"
    },
    "suid_bins": {
      "query": "SELECT * FROM suid_bin;",
      "interval": 3600,
      "platform": "posix",
      "description": "SUID binaries"
    }
  },
  "decorators": {
    "load": [
      "SELECT uuid AS host_uuid FROM system_info;",
      "SELECT user AS username FROM logged_in_users ORDER BY time DESC LIMIT 1;"
    ]
  },
  "packs": {
    "osquery-monitoring": "/var/osquery/packs/osquery-monitoring.conf",
    "incident-response": "/var/osquery/packs/incident-response.conf",
    "it-compliance": "/var/osquery/packs/it-compliance.conf"
  }
}`

// GetWindowsConfig returns Windows-specific osquery configuration
func GetWindowsConfig() string {
	return `{
  "options": {
    "config_plugin": "filesystem",
    "logger_plugin": "filesystem",
    "logger_path": "C:\\Program Files\\osquery\\log",
    "disable_logging": "false",
    "schedule_splay_percent": "10",
    "worker_threads": "2",
    "enable_monitor": "true",
    "verbose": "false",
    "host_identifier": "hostname"
  },
  "schedule": {
    "system_info": {
      "query": "SELECT hostname, cpu_brand, physical_memory, hardware_vendor, hardware_model FROM system_info;",
      "interval": 3600
    },
    "windows_security_products": {
      "query": "SELECT * FROM windows_security_products;",
      "interval": 3600
    },
    "windows_security_center": {
      "query": "SELECT * FROM windows_security_center;",
      "interval": 3600
    },
    "certificates": {
      "query": "SELECT * FROM certificates WHERE path = 'CurrentUser' OR path = 'LocalMachine';",
      "interval": 3600
    },
    "scheduled_tasks": {
      "query": "SELECT * FROM scheduled_tasks;",
      "interval": 3600
    },
    "windows_eventlog": {
      "query": "SELECT * FROM windows_eventlog WHERE channel = 'Security' AND eventid IN (4624, 4625, 4634, 4672, 4720, 4726, 4732, 4740);",
      "interval": 300
    }
  }
}`
}
