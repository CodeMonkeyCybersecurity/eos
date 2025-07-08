// cmd/delphi/services/read.go
package read

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ReadPipelinePrompts creates the read command
func ReadPipelinePrompts() *cobra.Command {
	var showConfig bool

	cmd := &cobra.Command{
		Use:   "read <service-name>",
		Short: "Display detailed information about a Delphi service",
		Long: `Display comprehensive information about a Delphi service including:
- Service status and health
- Configuration files and their existence
- Worker script details
- Systemd service configuration
- Dependencies and requirements
- Recent logs (last 10 lines)

Available services:
- delphi-listener: Webhook listener for Wazuh alerts
- delphi-agent-enricher: Agent enrichment service
- llm-worker: LLM processing service
- prompt-ab-tester: A/B testing worker for prompt optimization

Examples:
  eos delphi services read llm-worker
  eos delphi services read prompt-ab-tester --show-config`,
		Args: cobra.ExactArgs(1),
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			configs := pipeline.GetServiceConfigurations()
			var services []string
			for name := range configs {
				services = append(services, name)
			}
			return services, cobra.ShellCompDirectiveNoFileComp
		},
		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)
			serviceName := args[0]

			logger.Info(" Reading Delphi service information",
				zap.String("service", serviceName))

			// Get service configuration
			configs := pipeline.GetServiceConfigurations()
			config, exists := configs[serviceName]
			if !exists {
				return fmt.Errorf("unknown service: %s", serviceName)
			}

			// Display basic service information
			logger.Info(" Service Information",
				zap.String("name", config.Name),
				zap.String("description", config.Description))

			// Check service status
			status, err := getServiceStatus(rc, serviceName)
			if err != nil {
				logger.Warn(" Failed to get service status", zap.Error(err))
			} else {
				logger.Info(" Service Status",
					zap.String("status", status.Status),
					zap.String("active", status.Active),
					zap.String("enabled", status.Enabled),
					zap.String("uptime", status.Uptime))
			}

			// Check worker script
			workerExists := eos_unix.FileExists(config.WorkerFile)
			workerInfo := getFileInfo(config.WorkerFile)
			logger.Info(" Worker Script",
				zap.String("path", config.WorkerFile),
				zap.Bool("exists", workerExists),
				zap.String("permissions", workerInfo.Permissions),
				zap.String("size", workerInfo.Size),
				zap.String("modified", workerInfo.Modified))

			// Check service file
			serviceExists := eos_unix.FileExists(config.ServiceFile)
			serviceInfo := getFileInfo(config.ServiceFile)
			logger.Info(" Service File",
				zap.String("path", config.ServiceFile),
				zap.Bool("exists", serviceExists),
				zap.String("permissions", serviceInfo.Permissions),
				zap.String("size", serviceInfo.Size),
				zap.String("modified", serviceInfo.Modified))

			// Check configuration files
			logger.Info(" Configuration Files")
			for _, configFile := range config.ConfigFiles {
				configExists := eos_unix.FileExists(configFile)
				configInfo := getFileInfo(configFile)
				logger.Info(" "+filepath.Base(configFile),
					zap.String("path", configFile),
					zap.Bool("exists", configExists),
					zap.String("permissions", configInfo.Permissions),
					zap.String("size", configInfo.Size))
			}

			// Display dependencies
			logger.Info(" Dependencies",
				zap.Strings("required", config.Dependencies))

			// Show recent logs
			if err := showRecentLogs(rc, serviceName); err != nil {
				logger.Warn(" Failed to retrieve recent logs", zap.Error(err))
			}

			// Show configuration content if requested
			if showConfig {
				if err := showServiceConfiguration(rc, config); err != nil {
					logger.Warn(" Failed to display configuration", zap.Error(err))
				}
			}

			return nil
		}),
	}

	cmd.Flags().BoolVarP(&showConfig, "show-config", "c", false, "Display service configuration file content")
	return cmd
}

// ServiceStatus represents systemd service status information
type ServiceStatus struct {
	Status  string
	Active  string
	Enabled string
	Uptime  string
}

// FileInfo represents file information
type FileInfo struct {
	Permissions string
	Size        string
	Modified    string
}

// getServiceStatus retrieves systemd service status
func getServiceStatus(rc *eos_io.RuntimeContext, serviceName string) (*ServiceStatus, error) {
	status := &ServiceStatus{}

	// Get service status
	cmd := exec.Command("systemctl", "is-active", serviceName)
	output, err := cmd.Output()
	if err == nil {
		status.Active = strings.TrimSpace(string(output))
	} else {
		status.Active = "inactive"
	}

	// Get enabled status
	cmd = exec.Command("systemctl", "is-enabled", serviceName)
	output, err = cmd.Output()
	if err == nil {
		status.Enabled = strings.TrimSpace(string(output))
	} else {
		status.Enabled = "disabled"
	}

	// Get overall status
	cmd = exec.Command("systemctl", "show", "-p", "SubState", serviceName)
	output, err = cmd.Output()
	if err == nil {
		parts := strings.Split(strings.TrimSpace(string(output)), "=")
		if len(parts) == 2 {
			status.Status = parts[1]
		}
	}

	// Get uptime if active
	if status.Active == "active" {
		cmd = exec.Command("systemctl", "show", "-p", "ActiveEnterTimestamp", serviceName)
		output, err = cmd.Output()
		if err == nil {
			parts := strings.Split(strings.TrimSpace(string(output)), "=")
			if len(parts) == 2 {
				status.Uptime = parts[1]
			}
		}
	}

	return status, nil
}

// getFileInfo retrieves file information
func getFileInfo(path string) FileInfo {
	info := FileInfo{
		Permissions: "unknown",
		Size:        "unknown",
		Modified:    "unknown",
	}

	stat, err := os.Stat(path)
	if err != nil {
		return info
	}

	info.Permissions = stat.Mode().String()
	info.Size = fmt.Sprintf("%d bytes", stat.Size())
	info.Modified = stat.ModTime().Format("2006-01-02 15:04:05")

	return info
}

// showRecentLogs displays recent service logs
func showRecentLogs(rc *eos_io.RuntimeContext, serviceName string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info(" Recent Logs (last 10 lines)")

	cmd := exec.Command("journalctl", "-u", serviceName, "-n", "10", "--no-pager")
	output, err := cmd.Output()
	if err != nil {
		return err
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			logger.Info("  " + line)
		}
	}

	return nil
}

// showServiceConfiguration displays service configuration file content
func showServiceConfiguration(rc *eos_io.RuntimeContext, config ServiceConfiguration) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info(" Service Configuration Content")

	if eos_unix.FileExists(config.ServiceFile) {
		content, err := os.ReadFile(config.ServiceFile)
		if err != nil {
			return err
		}

		logger.Info(" " + filepath.Base(config.ServiceFile) + " content:")
		lines := strings.Split(string(content), "\n")
		for _, line := range lines {
			logger.Info("  " + line)
		}
	}

	return nil
}
