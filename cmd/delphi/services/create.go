// cmd/delphi/services/create.go
package services

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ServiceConfiguration represents a service and its configuration files
type ServiceConfiguration struct {
	Name           string
	ServiceFile    string
	WorkerFile     string
	Description    string
	Dependencies   []string
	ConfigFiles    []string
	CreateFunction func(*eos_io.RuntimeContext) error
}

// GetServiceConfigurations returns all available service configurations
func GetServiceConfigurations() map[string]ServiceConfiguration {
	return map[string]ServiceConfiguration{
		"delphi-listener": {
			Name:        "delphi-listener",
			ServiceFile: "/etc/systemd/system/delphi-listener.service",
			WorkerFile:  "/usr/local/bin/delphi-listener.py",
			Description: "Webhook listener for Wazuh alerts",
			Dependencies: []string{"python3", "requests", "psycopg2"},
			ConfigFiles: []string{"/opt/stackstorm/packs/delphi/.env"},
		},
		"delphi-agent-enricher": {
			Name:        "delphi-agent-enricher",
			ServiceFile: "/etc/systemd/system/delphi-agent-enricher.service",
			WorkerFile:  "/usr/local/bin/delphi-agent-enricher.py",
			Description: "Agent enrichment service",
			Dependencies: []string{"python3", "requests", "psycopg2"},
			ConfigFiles: []string{"/opt/stackstorm/packs/delphi/.env"},
		},
		"email-structurer": {
			Name:        "email-structurer",
			ServiceFile: "/etc/systemd/system/email-structurer.service",
			WorkerFile:  "/usr/local/bin/email-structurer.py",
			Description: "Email structuring service (processes alerts from summarized to structured state)",
			Dependencies: []string{"python3", "psycopg2", "python-dotenv"},
			ConfigFiles: []string{"/opt/stackstorm/packs/delphi/.env"},
		},
		"email-formatter": {
			Name:        "email-formatter",
			ServiceFile: "/etc/systemd/system/email-formatter.service",
			WorkerFile:  "/usr/local/bin/email-formatter.py",
			Description: "Email formatting service (formats structured data into HTML/plain text emails)",
			Dependencies: []string{"python3", "psycopg2", "python-dotenv"},
			ConfigFiles: []string{"/opt/stackstorm/packs/delphi/.env", "/opt/stackstorm/packs/delphi/email.html"},
		},
		"email-sender": {
			Name:        "email-sender",
			ServiceFile: "/etc/systemd/system/email-sender.service",
			WorkerFile:  "/usr/local/bin/email-sender.py",
			Description: "Email sending service (delivers formatted emails via SMTP)",
			Dependencies: []string{"python3", "psycopg2", "python-dotenv", "smtplib"},
			ConfigFiles: []string{"/opt/stackstorm/packs/delphi/.env"},
		},
		"parser-monitor": {
			Name:        "parser-monitor",
			ServiceFile: "/etc/systemd/system/parser-monitor.service",
			WorkerFile:  "/usr/local/bin/parser-monitor.py",
			Description: "Parser health monitoring dashboard (provides observability for prompt-aware parsing system)",
			Dependencies: []string{"python3", "psycopg2", "python-dotenv", "tabulate"},
			ConfigFiles: []string{"/opt/stackstorm/packs/delphi/.env"},
		},
		"delphi-emailer": {
			Name:        "delphi-emailer",
			ServiceFile: "/etc/systemd/system/delphi-emailer.service",
			WorkerFile:  "/usr/local/bin/delphi-emailer.py",
			Description: "Email notification service (DEPRECATED - being replaced by modular email workers)",
			Dependencies: []string{"python3", "smtplib", "psycopg2"},
			ConfigFiles: []string{"/opt/stackstorm/packs/delphi/.env", "/opt/delphi/email-template.html"},
		},
		"llm-worker": {
			Name:        "llm-worker",
			ServiceFile: "/etc/systemd/system/llm-worker.service",
			WorkerFile:  "/usr/local/bin/llm-worker.py",
			Description: "LLM processing service",
			Dependencies: []string{"python3", "requests", "psycopg2", "openai"},
			ConfigFiles: []string{"/opt/stackstorm/packs/delphi/.env", "/srv/eos/system-prompts/default.txt"},
		},
		"prompt-ab-tester": {
			Name:        "prompt-ab-tester",
			ServiceFile: "/etc/systemd/system/prompt-ab-tester.service",
			WorkerFile:  "/usr/local/bin/prompt-ab-tester.py",
			Description: "A/B testing worker for prompt optimization",
			Dependencies: []string{"python3", "requests", "psycopg2", "openai"},
			ConfigFiles: []string{"/opt/stackstorm/packs/delphi/.env", "/opt/delphi/ab-test-config.json", "/srv/eos/system-prompts/"},
		},
	}
}

// NewCreateCmd creates the create command
func NewCreateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create <service-name>",
		Short: "Create and deploy a Delphi service",
		Long: `Create and deploy a Delphi service with all required files and configurations.

This command will:
1. Deploy the service worker script to /usr/local/bin/
2. Create the systemd service file
3. Set appropriate permissions and ownership
4. Create required configuration directories
5. Deploy default configuration files

Available services:
- delphi-listener: Webhook listener for Wazuh alerts
- delphi-agent-enricher: Agent enrichment service
- email-structurer: Email structuring service (processes alerts from summarized to structured state)
- email-formatter: Email formatting service (formats structured data into HTML/plain text emails)
- email-sender: Email sending service (delivers formatted emails via SMTP)
- parser-monitor: Parser health monitoring dashboard (provides observability for prompt-aware parsing system)
- delphi-emailer: Email notification service (DEPRECATED - being replaced by modular email workers)
- llm-worker: LLM processing service
- prompt-ab-tester: A/B testing worker for prompt optimization

Examples:
  eos delphi services create llm-worker
  eos delphi services create prompt-ab-tester`,
		Args: cobra.ExactArgs(1),
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			configs := GetServiceConfigurations()
			var services []string
			for name := range configs {
				services = append(services, name)
			}
			return services, cobra.ShellCompDirectiveNoFileComp
		},
		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)
			serviceName := args[0]

			logger.Info(" Creating Delphi service",
				zap.String("service", serviceName))

			// Check if running as root
			if !eos_unix.IsPrivilegedUser(rc.Ctx) {
				return fmt.Errorf("service creation requires root privileges")
			}

			// Get service configuration
			configs := GetServiceConfigurations()
			config, exists := configs[serviceName]
			if !exists {
				return fmt.Errorf("unknown service: %s", serviceName)
			}

			// Check if service already exists
			if _, err := os.Stat(config.ServiceFile); err == nil {
				logger.Warn(" Service already exists",
					zap.String("service", serviceName),
					zap.String("service_file", config.ServiceFile))
			}

			// Deploy worker script
			workerSourcePath := filepath.Join("/opt/eos/assets/python_workers", filepath.Base(config.WorkerFile))
			if err := deployWorkerScript(rc, workerSourcePath, config.WorkerFile); err != nil {
				return fmt.Errorf("failed to deploy worker script: %w", err)
			}

			// Deploy service file
			serviceSourcePath := filepath.Join("/opt/eos/assets/services", filepath.Base(config.ServiceFile))
			if err := deployServiceFile(rc, serviceSourcePath, config.ServiceFile); err != nil {
				return fmt.Errorf("failed to deploy service file: %w", err)
			}

			// Create configuration directories
			for _, configFile := range config.ConfigFiles {
				configDir := filepath.Dir(configFile)
				if err := os.MkdirAll(configDir, 0755); err != nil {
					logger.Warn(" Failed to create config directory",
						zap.String("directory", configDir),
						zap.Error(err))
				} else {
					logger.Info(" Created configuration directory",
						zap.String("directory", configDir))
				}
			}

			// Reload systemd
			if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
				logger.Warn(" Failed to reload systemd daemon", zap.Error(err))
			} else {
				logger.Info(" Systemd daemon reloaded")
			}

			logger.Info("✨ Service created successfully",
				zap.String("service", serviceName),
				zap.String("description", config.Description),
				zap.String("worker_file", config.WorkerFile),
				zap.String("service_file", config.ServiceFile))

			logger.Info(" Next steps",
				zap.String("enable", fmt.Sprintf("eos delphi services enable %s", serviceName)),
				zap.String("start", fmt.Sprintf("eos delphi services start %s", serviceName)))

			return nil
		}),
	}

	return cmd
}

// deployWorkerScript deploys a worker script with correct permissions
func deployWorkerScript(rc *eos_io.RuntimeContext, sourcePath, targetPath string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if source exists
	if _, err := os.Stat(sourcePath); err != nil {
		return fmt.Errorf("worker script not found: %s", sourcePath)
	}

	// Copy file
	if err := eos_unix.CopyFile(rc.Ctx, sourcePath, targetPath, 0755); err != nil {
		return fmt.Errorf("failed to copy worker script: %w", err)
	}

	// Set ownership
	if err := exec.Command("chown", "root:root", targetPath).Run(); err != nil {
		logger.Warn(" Failed to set ownership", zap.String("file", targetPath), zap.Error(err))
	}

	logger.Info(" Worker script deployed",
		zap.String("source", sourcePath),
		zap.String("target", targetPath))

	return nil
}

// deployServiceFile deploys a systemd service file
func deployServiceFile(rc *eos_io.RuntimeContext, sourcePath, targetPath string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if source exists
	if _, err := os.Stat(sourcePath); err != nil {
		return fmt.Errorf("service file not found: %s", sourcePath)
	}

	// Copy file
	if err := eos_unix.CopyFile(rc.Ctx, sourcePath, targetPath, 0644); err != nil {
		return fmt.Errorf("failed to copy service file: %w", err)
	}

	// Set ownership
	if err := exec.Command("chown", "root:root", targetPath).Run(); err != nil {
		logger.Warn(" Failed to set ownership", zap.String("file", targetPath), zap.Error(err))
	}

	logger.Info(" Service file deployed",
		zap.String("source", sourcePath),
		zap.String("target", targetPath))

	return nil
}