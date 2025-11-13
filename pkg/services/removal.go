package services

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ServiceRemovalConfig defines how to remove a service
type ServiceRemovalConfig struct {
	Name          string
	ServiceNames  []string // systemd service names
	PackageNames  []string // APT package names
	Processes     []string // Process names to kill
	ConfigDirs    []string // Configuration directories
	DataDirs      []string // Data directories
	LogDirs       []string // Log directories
	Users         []string // System users to remove
	Groups        []string // System groups to remove
	CustomCleanup func(rc *eos_io.RuntimeContext) error
}

// RemoveService removes a service using the provided configuration
func RemoveService(rc *eos_io.RuntimeContext, config ServiceRemovalConfig, keepData bool) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Removing service",
		zap.String("service", config.Name),
		zap.Bool("keep_data", keepData))

	// Stop and disable services
	for _, service := range config.ServiceNames {
		if err := stopAndDisableService(rc, service); err != nil {
			logger.Debug("Failed to stop service",
				zap.String("service", service),
				zap.Error(err))
		}
	}

	// Kill processes
	for _, process := range config.Processes {
		killProcess(rc, process)
	}

	// Remove packages
	if len(config.PackageNames) > 0 {
		removePackages(rc, config.PackageNames)
	}

	// Remove directories
	if !keepData {
		// Remove all directories
		allDirs := append(config.ConfigDirs, config.DataDirs...)
		allDirs = append(allDirs, config.LogDirs...)
		for _, dir := range allDirs {
			if err := os.RemoveAll(dir); err != nil {
				logger.Debug("Failed to remove directory",
					zap.String("dir", dir),
					zap.Error(err))
			}
		}
	} else {
		// Only remove config directories
		for _, dir := range config.ConfigDirs {
			if err := os.RemoveAll(dir); err != nil {
				logger.Debug("Failed to remove config directory",
					zap.String("dir", dir),
					zap.Error(err))
			}
		}
	}

	// Remove users and groups
	for _, user := range config.Users {
		_, _ = execute.Run(rc.Ctx, execute.Options{
			Command: "userdel",
			Args:    []string{"-r", user},
			Timeout: 5 * time.Second,
		})
	}
	for _, group := range config.Groups {
		_, _ = execute.Run(rc.Ctx, execute.Options{
			Command: "groupdel",
			Args:    []string{group},
			Timeout: 5 * time.Second,
		})
	}

	// Run custom cleanup if provided
	if config.CustomCleanup != nil {
		if err := config.CustomCleanup(rc); err != nil {
			logger.Warn("Custom cleanup failed",
				zap.String("service", config.Name),
				zap.Error(err))
		}
	}

	logger.Info("Service removal completed", zap.String("service", config.Name))
	return nil
}

// GetAdditionalServicesConfigs returns removal configs for additional services
func GetAdditionalServicesConfigs() []ServiceRemovalConfig {
	return []ServiceRemovalConfig{
		{
			Name:         "fail2ban",
			ServiceNames: []string{"fail2ban"},
			PackageNames: []string{"fail2ban"},
			Processes:    []string{"fail2ban-server", "fail2ban-client"},
			ConfigDirs:   []string{"/etc/fail2ban"},
			DataDirs:     []string{"/var/lib/fail2ban"},
			LogDirs:      []string{"/var/log/fail2ban"},
		},
		{
			Name:         "trivy",
			ServiceNames: []string{"trivy"},
			PackageNames: []string{"trivy"},
			Processes:    []string{"trivy"},
			ConfigDirs:   []string{"/etc/trivy"},
			DataDirs:     []string{"/var/lib/trivy", "/var/cache/trivy"},
			LogDirs:      []string{"/var/log/trivy"},
			CustomCleanup: func(rc *eos_io.RuntimeContext) error {
				// Remove trivy binary if installed manually
				binPaths := []string{"/usr/local/bin/trivy", "/usr/bin/trivy"}
				for _, path := range binPaths {
					_ = os.Remove(path)
				}
				return nil
			},
		},
		{
			Name:         "wazuh-agent",
			ServiceNames: []string{"wazuh-agent"},
			PackageNames: []string{"wazuh-agent"},
			Processes:    []string{"wazuh-agentd", "wazuh-execd", "wazuh-syscheckd"},
			ConfigDirs:   []string{"/var/ossec/etc"},
			DataDirs:     []string{"/var/ossec/var", "/var/ossec/queue"},
			LogDirs:      []string{"/var/ossec/logs"},
			Users:        []string{"ossec", "ossecm", "ossecr"},
			Groups:       []string{"ossec"},
			CustomCleanup: func(rc *eos_io.RuntimeContext) error {
				// Remove entire ossec directory
				_ = os.RemoveAll("/var/ossec")
				return nil
			},
		},
		{
			Name:         "prometheus",
			ServiceNames: []string{"prometheus", "prometheus-node-exporter"},
			PackageNames: []string{"prometheus", "prometheus-node-exporter"},
			Processes:    []string{"prometheus", "node_exporter"},
			ConfigDirs:   []string{"/etc/prometheus"},
			DataDirs:     []string{"/var/lib/prometheus"},
			LogDirs:      []string{"/var/log/prometheus"},
			Users:        []string{"prometheus"},
			Groups:       []string{"prometheus"},
		},
		{
			Name:         "grafana",
			ServiceNames: []string{"grafana-server"},
			PackageNames: []string{"grafana", "grafana-enterprise"},
			Processes:    []string{"grafana-server"},
			ConfigDirs:   []string{"/etc/grafana"},
			DataDirs:     []string{"/var/lib/grafana"},
			LogDirs:      []string{"/var/log/grafana"},
			Users:        []string{"grafana"},
			Groups:       []string{"grafana"},
			CustomCleanup: func(rc *eos_io.RuntimeContext) error {
				// Remove Grafana APT repository
				_ = os.Remove("/etc/apt/sources.list.d/grafana.list")
				_ = os.Remove("/usr/share/keyrings/grafana.key")
				return nil
			},
		},
		{
			Name:         "glances",
			ServiceNames: []string{"glances"},
			PackageNames: []string{"glances"},
			Processes:    []string{"glances"},
			ConfigDirs:   []string{"/etc/glances"},
			DataDirs:     []string{"/var/lib/glances"},
			LogDirs:      []string{"/var/log/glances"},
		},
		{
			Name:         "nginx",
			ServiceNames: []string{"nginx"},
			PackageNames: []string{"nginx", "nginx-common", "nginx-core"},
			Processes:    []string{"nginx"},
			ConfigDirs:   []string{"/etc/nginx"},
			DataDirs:     []string{"/var/www", "/usr/share/nginx"},
			LogDirs:      []string{"/var/log/nginx"},
			Users:        []string{"www-data"}, // Only if no other services use it
		},
		{
			Name:         "code-server",
			ServiceNames: []string{"code-server@*"}, // Wildcard for user services
			Processes:    []string{"code-server", "node"},
			ConfigDirs:   []string{"/etc/code-server"},
			DataDirs:     []string{"/var/lib/code-server"},
			LogDirs:      []string{"/var/log/code-server"},
			CustomCleanup: func(rc *eos_io.RuntimeContext) error {
				// Find and stop all code-server user services
				if output, err := execute.Run(rc.Ctx, execute.Options{
					Command: "systemctl",
					Args:    []string{"list-units", "--type=service", "--all", "code-server@*"},
					Capture: true,
					Timeout: 5 * time.Second,
				}); err == nil {
					lines := strings.Split(output, "\n")
					for _, line := range lines {
						fields := strings.Fields(line)
						if len(fields) > 0 && strings.HasPrefix(fields[0], "code-server@") {
							_ = stopAndDisableService(rc, fields[0])
						}
					}
				}
				// Remove binary if installed manually
				_ = os.Remove("/usr/local/bin/code-server")
				return nil
			},
		},
		{
			Name:         "eos-storage-monitor",
			ServiceNames: []string{"eos-storage-monitor"},
			Processes:    []string{"eos-storage-monitor"},
			ConfigDirs:   []string{"/etc/eos"},
			DataDirs:     []string{"/var/lib/eos/storage-monitor"},
			LogDirs:      []string{"/var/log/eos"},
		},
		{
			Name:         "tailscale",
			ServiceNames: []string{"tailscaled"},
			PackageNames: []string{"tailscale"},
			Processes:    []string{"tailscaled", "tailscale"},
			ConfigDirs:   []string{"/etc/tailscale"},
			DataDirs:     []string{"/var/lib/tailscale"},
			LogDirs:      []string{"/var/log/tailscale"},
			CustomCleanup: func(rc *eos_io.RuntimeContext) error {
				// Logout from tailscale before removal
				_, _ = execute.Run(rc.Ctx, execute.Options{
					Command: "tailscale",
					Args:    []string{"logout"},
					Timeout: 10 * time.Second,
				})
				// Remove APT repository
				_ = os.Remove("/etc/apt/sources.list.d/tailscale.list")
				_ = os.Remove("/usr/share/keyrings/tailscale-archive-keyring.gpg")
				return nil
			},
		},
	}
}

// Helper functions

func stopAndDisableService(rc *eos_io.RuntimeContext, service string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if service exists first
	if output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"list-unit-files", "--no-pager", service},
		Capture: true,
		Timeout: 5 * time.Second,
	}); err != nil || output == "" {
		return fmt.Errorf("service %s not found", service)
	}

	// Stop service
	_, _ = execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"stop", service},
		Timeout: 30 * time.Second,
	})

	// Disable service
	_, _ = execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"disable", service},
		Timeout: 10 * time.Second,
	})

	logger.Debug("Stopped and disabled service", zap.String("service", service))
	return nil
}

func killProcess(rc *eos_io.RuntimeContext, process string) {
	// First try graceful termination
	_, _ = execute.Run(rc.Ctx, execute.Options{
		Command: "pkill",
		Args:    []string{"-TERM", "-f", process},
		Timeout: 5 * time.Second,
	})

	time.Sleep(2 * time.Second)

	// Force kill if still running
	_, _ = execute.Run(rc.Ctx, execute.Options{
		Command: "pkill",
		Args:    []string{"-KILL", "-f", process},
		Timeout: 5 * time.Second,
	})
}

func removePackages(rc *eos_io.RuntimeContext, packages []string) {
	logger := otelzap.Ctx(rc.Ctx)

	// Check which packages are actually installed
	installedPackages := []string{}
	for _, pkg := range packages {
		if _, err := execute.Run(rc.Ctx, execute.Options{
			Command: "dpkg",
			Args:    []string{"-l", pkg},
			Capture: true,
			Timeout: 2 * time.Second,
		}); err == nil {
			installedPackages = append(installedPackages, pkg)
		}
	}

	if len(installedPackages) == 0 {
		return
	}

	logger.Info("Removing packages", zap.Strings("packages", installedPackages))

	args := append([]string{"remove", "--purge", "-y"}, installedPackages...)
	_, _ = execute.Run(rc.Ctx, execute.Options{
		Command: "apt-get",
		Args:    args,
		Timeout: 120 * time.Second,
	})
}
