// cmd/create/metis.go
package create

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/metis"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var createMetisCmd = &cobra.Command{
	Use:   "metis",
	Short: "Install Metis security alert processing system",
	Long: `Install Metis (Delphi Notify) for automated processing of Wazuh security alerts.

Metis uses:
- Temporal workflows for durable execution
- Azure OpenAI for alert analysis
- Email notifications via SMTP
- Webhook receiver for Wazuh integration

Installation creates:
- /opt/metis project directory
- Worker and webhook Go programs
- Configuration files
- Systemd services
- Test scripts

Prerequisites:
- Go 1.21+
- Temporal server (will be installed if missing)
- Azure OpenAI account
- SMTP server for email

Example:
  eos create metis`,
	RunE: eos.Wrap(runCreateMetis),
}

func init() {
	CreateCmd.AddCommand(createMetisCmd)
}

func runCreateMetis(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting Metis installation")

	projectDir := "/opt/metis"

	// Step 1: Check prerequisites
	logger.Info("Step 1/8: Checking prerequisites")
	if err := checkPrerequisites(rc); err != nil {
		return fmt.Errorf("prerequisite check failed: %w", err)
	}

	// Step 2: Install Temporal if needed
	logger.Info("Step 2/8: Ensuring Temporal is installed")
	if err := installTemporal(rc); err != nil {
		return fmt.Errorf("temporal installation failed: %w", err)
	}

	// Step 3: Create project structure
	logger.Info("Step 3/8: Creating project structure")
	if err := createProjectStructure(rc, projectDir); err != nil {
		return fmt.Errorf("failed to create project structure: %w", err)
	}

	// Step 4: Create configuration file
	logger.Info("Step 4/8: Creating configuration file")
	if err := createConfigFile(rc, projectDir); err != nil {
		return fmt.Errorf("failed to create config: %w", err)
	}

	// Step 5: Generate worker and webhook source
	logger.Info("Step 5/8: Generating worker and webhook source code")
	if err := generateSourceFiles(rc, projectDir); err != nil {
		return fmt.Errorf("failed to generate source: %w", err)
	}

	// Step 6: Initialize Go module and dependencies
	logger.Info("Step 6/8: Installing Go dependencies")
	if err := installDependencies(rc, projectDir); err != nil {
		return fmt.Errorf("failed to install dependencies: %w", err)
	}

	// Step 7: Create systemd service files
	logger.Info("Step 7/8: Creating systemd service files")
	if err := createSystemdServices(rc, projectDir); err != nil {
		return fmt.Errorf("failed to create systemd services: %w", err)
	}

	// Step 8: Create test script and README
	logger.Info("Step 8/8: Creating test script and documentation")
	if err := createTestScriptAndDocs(rc, projectDir); err != nil {
		return fmt.Errorf("failed to create test script: %w", err)
	}

	logger.Info("Metis installation completed successfully",
		zap.String("project_dir", projectDir))
	logger.Info("terminal prompt: Next steps:")
	logger.Info("terminal prompt:   1. Edit config: nano /opt/metis/config.yaml")
	logger.Info("terminal prompt:   2. Start Temporal: temporal server start-dev")
	logger.Info("terminal prompt:   3. Test install: eos debug metis")
	logger.Info("terminal prompt:   4. Start services: sudo systemctl start metis-worker metis-webhook")
	logger.Info("terminal prompt:   5. View Temporal UI: http://localhost:8233")

	return nil
}

func checkPrerequisites(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check Go
	if _, err := exec.LookPath("go"); err != nil {
		return fmt.Errorf("Go is not installed - please install Go 1.21+")
	}
	goVersion := exec.CommandContext(rc.Ctx, "go", "version")
	if output, err := goVersion.CombinedOutput(); err == nil {
		logger.Info("Go found", zap.String("version", string(output)))
	}

	// Check if Temporal CLI is available (optional - we'll install if missing)
	if _, err := exec.LookPath("temporal"); err != nil {
		logger.Warn("Temporal CLI not found - will be installed")
	} else {
		logger.Info("Temporal CLI found")
	}

	return nil
}

func installTemporal(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	if _, err := exec.LookPath("temporal"); err == nil {
		logger.Info("Temporal CLI already installed")
		return nil
	}

	logger.Info("Installing Temporal CLI")
	installCmd := exec.CommandContext(rc.Ctx, "sh", "-c",
		"curl -sSf https://temporal.download/cli.sh | sh")
	if output, err := installCmd.CombinedOutput(); err != nil {
		logger.Warn("Temporal CLI installation failed - you may need to install manually",
			zap.Error(err),
			zap.String("output", string(output)))
		logger.Info("terminal prompt: Install Temporal manually: https://docs.temporal.io/cli")
		return nil // Don't fail - user can install manually
	}

	logger.Info("Temporal CLI installed successfully")
	return nil
}

func createProjectStructure(rc *eos_io.RuntimeContext, projectDir string) error {
	logger := otelzap.Ctx(rc.Ctx)

	dirs := []string{
		projectDir,
		filepath.Join(projectDir, "worker"),
		filepath.Join(projectDir, "webhook"),
		filepath.Join(projectDir, "scripts"),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
		logger.Debug("Created directory", zap.String("path", dir))
	}

	return nil
}

func createConfigFile(rc *eos_io.RuntimeContext, projectDir string) error {
	logger := otelzap.Ctx(rc.Ctx)

	configContent := `# Metis/Delphi Notify Configuration

temporal:
  host_port: "localhost:7233"
  namespace: "default"
  task_queue: "wazuh-alerts"

azure_openai:
  endpoint: "https://YOUR-RESOURCE.openai.azure.com/"
  api_key: "YOUR-API-KEY-HERE"
  deployment_name: "gpt-4"
  api_version: "2024-02-15-preview"

email:
  smtp_host: "mail.example.com"
  smtp_port: 587
  username: "alerts@example.com"
  password: "YOUR-SMTP-PASSWORD"
  from: "security-alerts@example.com"
  to: "admin@example.com"

webhook:
  port: 8080
`

	configPath := filepath.Join(projectDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(configContent), 0640); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	logger.Info("Configuration file created", zap.String("path", configPath))
	logger.Warn("IMPORTANT: Edit config.yaml with your Azure OpenAI and SMTP credentials")

	return nil
}

func generateSourceFiles(rc *eos_io.RuntimeContext, projectDir string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Generate worker/main.go
	workerPath := filepath.Join(projectDir, "worker", "main.go")
	if err := os.WriteFile(workerPath, []byte(metis.GetWorkerSource()), 0644); err != nil {
		return fmt.Errorf("failed to write worker source: %w", err)
	}
	logger.Info("Worker source generated", zap.String("path", workerPath))

	// Generate webhook/main.go
	webhookPath := filepath.Join(projectDir, "webhook", "main.go")
	if err := os.WriteFile(webhookPath, []byte(metis.GetWebhookSource()), 0644); err != nil {
		return fmt.Errorf("failed to write webhook source: %w", err)
	}
	logger.Info("Webhook source generated", zap.String("path", webhookPath))

	return nil
}

func installDependencies(rc *eos_io.RuntimeContext, projectDir string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Initialize go.mod in worker directory
	workerDir := filepath.Join(projectDir, "worker")
	initCmd := exec.CommandContext(rc.Ctx, "go", "mod", "init", "metis/worker")
	initCmd.Dir = workerDir
	if output, err := initCmd.CombinedOutput(); err != nil {
		logger.Debug("go mod init output", zap.String("output", string(output)))
	}

	// Install worker dependencies
	logger.Info("Installing worker dependencies (this may take a minute)")
	tidyCmd := exec.CommandContext(rc.Ctx, "go", "mod", "tidy")
	tidyCmd.Dir = workerDir
	if output, err := tidyCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to install worker dependencies: %s", string(output))
	}

	// Initialize go.mod in webhook directory
	webhookDir := filepath.Join(projectDir, "webhook")
	initCmd = exec.CommandContext(rc.Ctx, "go", "mod", "init", "metis/webhook")
	initCmd.Dir = webhookDir
	if output, err := initCmd.CombinedOutput(); err != nil {
		logger.Debug("go mod init output", zap.String("output", string(output)))
	}

	// Install webhook dependencies
	logger.Info("Installing webhook dependencies")
	tidyCmd = exec.CommandContext(rc.Ctx, "go", "mod", "tidy")
	tidyCmd.Dir = webhookDir
	if output, err := tidyCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to install webhook dependencies: %s", string(output))
	}

	logger.Info("Dependencies installed successfully")
	return nil
}

func createSystemdServices(rc *eos_io.RuntimeContext, projectDir string) error {
	logger := otelzap.Ctx(rc.Ctx)

	workerService := `[Unit]
Description=Metis Temporal Worker
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/metis/worker
ExecStart=/usr/bin/go run main.go
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
`

	webhookService := `[Unit]
Description=Metis Webhook Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/metis/webhook
ExecStart=/usr/bin/go run main.go
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
`

	workerServicePath := filepath.Join(projectDir, "metis-worker.service")
	if err := os.WriteFile(workerServicePath, []byte(workerService), 0644); err != nil {
		return fmt.Errorf("failed to write worker service: %w", err)
	}

	webhookServicePath := filepath.Join(projectDir, "metis-webhook.service")
	if err := os.WriteFile(webhookServicePath, []byte(webhookService), 0644); err != nil {
		return fmt.Errorf("failed to write webhook service: %w", err)
	}

	logger.Info("Systemd service files created",
		zap.String("worker", workerServicePath),
		zap.String("webhook", webhookServicePath))
	logger.Info("terminal prompt: To enable services: sudo cp /opt/metis/*.service /etc/systemd/system/ && sudo systemctl daemon-reload")

	return nil
}

func createTestScriptAndDocs(rc *eos_io.RuntimeContext, projectDir string) error {
	logger := otelzap.Ctx(rc.Ctx)

	testScript := `#!/bin/bash
# Test script for Metis installation

echo "Testing Metis alert processing..."

curl -X POST http://localhost:8080/webhook \
  -H "Content-Type: application/json" \
  -d '{
    "agent": {
      "name": "test-server",
      "id": "001"
    },
    "data": {
      "vulnerability": {
        "severity": "High",
        "package": {
          "name": "openssl"
        },
        "title": "CVE-2024-TEST: Test vulnerability in OpenSSL"
      }
    }
  }'

echo ""
echo "Alert sent! Check:"
echo "  - Temporal UI: http://localhost:8233"
echo "  - Worker logs: journalctl -u metis-worker -f"
echo "  - Email inbox for notification"
`

	testScriptPath := filepath.Join(projectDir, "scripts", "test-alert.sh")
	if err := os.WriteFile(testScriptPath, []byte(testScript), 0755); err != nil {
		return fmt.Errorf("failed to write test script: %w", err)
	}
	logger.Info("Test script created", zap.String("path", testScriptPath))

	// Create README
	readmePath := filepath.Join(projectDir, "README.md")
	if err := os.WriteFile(readmePath, []byte(metis.GetReadmeContent()), 0644); err != nil {
		return fmt.Errorf("failed to write README: %w", err)
	}
	logger.Info("README created", zap.String("path", readmePath))

	return nil
}
