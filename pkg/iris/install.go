// pkg/iris/install.go

package iris

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CreateProjectStructure creates the directory structure for Iris
//
// This function implements the Assess → Intervene → Evaluate pattern:
// - Assess: Define required directories
// - Intervene: Create all directories
// - Evaluate: Verify directories were created
func CreateProjectStructure(rc *eos_io.RuntimeContext, projectDir string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Creating Iris project structure",
		zap.String("project_dir", projectDir))

	dirs := []string{
		projectDir,
		filepath.Join(projectDir, "worker"),
		filepath.Join(projectDir, "webhook"),
		filepath.Join(projectDir, "scripts"),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, shared.ServiceDirPerm); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
		logger.Debug("Created directory", zap.String("path", dir))
	}

	return nil
}

// GenerateSourceFiles generates worker and webhook Go source files
//
// This function implements the Assess → Intervene → Evaluate pattern:
// - Assess: Get source code from templates
// - Intervene: Write source files to disk
// - Evaluate: Verify files were created successfully
func GenerateSourceFiles(rc *eos_io.RuntimeContext, projectDir string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Generating Iris source files",
		zap.String("project_dir", projectDir))

	// Generate worker/main.go
	workerPath := filepath.Join(projectDir, "worker", "main.go")
	if err := os.WriteFile(workerPath, []byte(GetWorkerSource()), shared.ConfigFilePerm); err != nil {
		return fmt.Errorf("failed to write worker source: %w", err)
	}
	logger.Info("Worker source generated", zap.String("path", workerPath))

	// Generate webhook/main.go
	webhookPath := filepath.Join(projectDir, "webhook", "main.go")
	if err := os.WriteFile(webhookPath, []byte(GetWebhookSource()), shared.ConfigFilePerm); err != nil {
		return fmt.Errorf("failed to write webhook source: %w", err)
	}
	logger.Info("Webhook source generated", zap.String("path", webhookPath))

	return nil
}

// InstallDependencies initializes Go modules and installs dependencies
//
// This function implements the Assess → Intervene → Evaluate pattern:
// - Assess: Identify worker and webhook directories
// - Intervene: Run go mod init and go mod tidy for each
// - Evaluate: Check for errors during dependency installation
func InstallDependencies(rc *eos_io.RuntimeContext, projectDir string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Installing Iris dependencies",
		zap.String("project_dir", projectDir))

	// Initialize go.mod in worker directory
	workerDir := filepath.Join(projectDir, "worker")
	initCmd := exec.CommandContext(rc.Ctx, "go", "mod", "init", "iris/worker")
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
	initCmd = exec.CommandContext(rc.Ctx, "go", "mod", "init", "iris/webhook")
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

// CreateSystemdServices creates systemd service files for Iris components
//
// This function implements the Assess → Intervene → Evaluate pattern:
// - Assess: Define service configurations
// - Intervene: Write service files and enable Temporal service
// - Evaluate: Report status of service creation
func CreateSystemdServices(rc *eos_io.RuntimeContext, projectDir string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Creating systemd services",
		zap.String("project_dir", projectDir))

	// Temporal server service
	temporalService := `[Unit]
Description=Temporal Server (Development Mode)
After=network.target
Documentation=https://docs.temporal.io/

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/temporal server start-dev --db-filename /var/lib/temporal/temporal.db
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Create data directory if it doesn't exist
RuntimeDirectory=temporal
StateDirectory=temporal

[Install]
WantedBy=multi-user.target
`

	workerService := `[Unit]
Description=Iris Temporal Worker
After=network.target temporal.service
Requires=temporal.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/iris/worker
ExecStart=/usr/bin/go run main.go
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
`

	webhookService := `[Unit]
Description=Iris Webhook Server
After=network.target temporal.service
Requires=temporal.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/iris/webhook
ExecStart=/usr/bin/go run main.go
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
`

	// Write Temporal service to /etc/systemd/system directly (requires root)
	temporalServicePath := "/etc/systemd/system/temporal.service"
	if err := os.WriteFile(temporalServicePath, []byte(temporalService), shared.ConfigFilePerm); err != nil {
		return fmt.Errorf("failed to write temporal service: %w", err)
	}

	workerServicePath := filepath.Join(projectDir, "iris-worker.service")
	if err := os.WriteFile(workerServicePath, []byte(workerService), shared.ConfigFilePerm); err != nil {
		return fmt.Errorf("failed to write worker service: %w", err)
	}

	webhookServicePath := filepath.Join(projectDir, "iris-webhook.service")
	if err := os.WriteFile(webhookServicePath, []byte(webhookService), shared.ConfigFilePerm); err != nil {
		return fmt.Errorf("failed to write webhook service: %w", err)
	}

	logger.Info("Systemd service files created",
		zap.String("temporal", temporalServicePath),
		zap.String("worker", workerServicePath),
		zap.String("webhook", webhookServicePath))

	// Enable and start Temporal service
	logger.Info("Enabling Temporal service")
	if err := exec.CommandContext(rc.Ctx, "systemctl", "daemon-reload").Run(); err != nil {
		logger.Warn("Failed to reload systemd daemon", zap.Error(err))
	}

	if err := exec.CommandContext(rc.Ctx, "systemctl", "enable", "temporal.service").Run(); err != nil {
		logger.Warn("Failed to enable temporal service", zap.Error(err))
	}

	if err := exec.CommandContext(rc.Ctx, "systemctl", "start", "temporal.service").Run(); err != nil {
		logger.Warn("Failed to start temporal service", zap.Error(err))
	}

	logger.Info("terminal prompt: To enable Iris services: sudo cp /opt/iris/*.service /etc/systemd/system/ && sudo systemctl daemon-reload && sudo systemctl enable iris-worker iris-webhook && sudo systemctl start iris-worker iris-webhook")

	return nil
}

// CreateTestScriptAndDocs creates test scripts and documentation
//
// This function implements the Assess → Intervene → Evaluate pattern:
// - Assess: Define test script and documentation content
// - Intervene: Write files to disk
// - Evaluate: Verify files were created successfully
func CreateTestScriptAndDocs(rc *eos_io.RuntimeContext, projectDir string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Creating test script and documentation",
		zap.String("project_dir", projectDir))

	testScript := `#!/bin/bash
# Test script for Iris installation

echo "Testing Iris alert processing..."

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
echo "  - Worker logs: journalctl -u iris-worker -f"
echo "  - Email inbox for notification"
`

	testScriptPath := filepath.Join(projectDir, "scripts", "test-alert.sh")
	if err := os.WriteFile(testScriptPath, []byte(testScript), shared.ExecutablePerm); err != nil {
		return fmt.Errorf("failed to write test script: %w", err)
	}
	logger.Info("Test script created", zap.String("path", testScriptPath))

	// Create README
	readmePath := filepath.Join(projectDir, "README.md")
	if err := os.WriteFile(readmePath, []byte(GetReadmeContent()), shared.ConfigFilePerm); err != nil {
		return fmt.Errorf("failed to write README: %w", err)
	}
	logger.Info("README created", zap.String("path", readmePath))

	return nil
}
