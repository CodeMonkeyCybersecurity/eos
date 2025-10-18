// cmd/create/iris.go
package create

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/iris"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"golang.org/x/term"
	"gopkg.in/yaml.v3"
)

var (
	interactiveConfig bool
	skipConfig        bool
	azureEndpoint     string
	azureAPIKey       string
	azureDeployment   string
	smtpHost          string
	smtpPort          int
	smtpUsername      string
	smtpPassword      string
	emailFrom         string
	emailTo           string
)

var createIrisCmd = &cobra.Command{
	Use:   "iris",
	Short: "Install Iris security alert processing system",
	Long: `Install Iris (Delphi Notify) for automated processing of Wazuh security alerts.

Iris uses:
- Temporal workflows for durable execution
- Azure OpenAI for alert analysis
- Email notifications via SMTP
- Webhook receiver for Wazuh integration

Installation creates:
- /opt/iris project directory
- Worker and webhook Go programs
- Configuration files
- Systemd services
- Test scripts

Prerequisites:
- Go 1.21+
- Temporal server (will be installed if missing)
- Azure OpenAI account
- SMTP server for email

Examples:
  eos create iris                                    # Interactive (default)
  eos create iris --skip-config                      # Use placeholders
  eos create iris --azure-endpoint=https://...       # Non-interactive`,
	RunE: eos.Wrap(runCreateIris),
}

func init() {
	CreateCmd.AddCommand(createIrisCmd)

	createIrisCmd.Flags().BoolVar(&interactiveConfig, "interactive", true, "Interactive configuration (default)")
	createIrisCmd.Flags().BoolVar(&skipConfig, "skip-config", false, "Skip configuration, use placeholders")

	// Azure OpenAI flags
	createIrisCmd.Flags().StringVar(&azureEndpoint, "azure-endpoint", "", "Azure OpenAI endpoint")
	createIrisCmd.Flags().StringVar(&azureAPIKey, "azure-key", "", "Azure OpenAI API key")
	createIrisCmd.Flags().StringVar(&azureDeployment, "azure-deployment", "gpt-4o", "Azure deployment name")

	// SMTP flags
	createIrisCmd.Flags().StringVar(&smtpHost, "smtp-host", "", "SMTP server host")
	createIrisCmd.Flags().IntVar(&smtpPort, "smtp-port", 587, "SMTP server port")
	createIrisCmd.Flags().StringVar(&smtpUsername, "smtp-user", "", "SMTP username")
	createIrisCmd.Flags().StringVar(&smtpPassword, "smtp-pass", "", "SMTP password")
	createIrisCmd.Flags().StringVar(&emailFrom, "email-from", "", "From email address")
	createIrisCmd.Flags().StringVar(&emailTo, "email-to", "", "To email address")
}

type IrisConfiguration struct {
	Azure struct {
		Endpoint       string
		APIKey         string
		DeploymentName string
		APIVersion     string
	}
	Email struct {
		SMTPHost string
		SMTPPort int
		Username string
		Password string
		From     string
		To       string
	}
	Webhook struct {
		Port int
	}
	Temporal struct {
		HostPort  string
		Namespace string
		TaskQueue string
	}
}

func runCreateIris(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting Iris installation")

	projectDir := "/opt/iris"

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

	// Step 4: Gather configuration (interactive or from flags)
	logger.Info("Step 4/8: Configuration setup")
	irisConfig := IrisConfiguration{
		Temporal: struct {
			HostPort  string
			Namespace string
			TaskQueue string
		}{
			HostPort:  "localhost:7233",
			Namespace: "default",
			TaskQueue: "wazuh-alerts",
		},
		Webhook: struct {
			Port int
		}{
			Port: 8080,
		},
		Azure: struct {
			Endpoint       string
			APIKey         string
			DeploymentName string
			APIVersion     string
		}{
			APIVersion: "2024-08-01-preview",
		},
	}

	if skipConfig {
		logger.Info("Skipping configuration - using placeholders")
		irisConfig = getPlaceholderConfig()
	} else if hasConfigFlags() {
		logger.Info("Using configuration from flags")
		irisConfig = getConfigFromFlags()
		if err := validateConfiguration(irisConfig); err != nil {
			return fmt.Errorf("configuration validation failed: %w", err)
		}
	} else if interactiveConfig {
		logger.Info("Starting interactive configuration")
		if err := gatherInteractiveConfig(rc, &irisConfig); err != nil {
			return fmt.Errorf("configuration failed: %w", err)
		}
	}

	// Create configuration file with gathered config
	if err := createConfigFile(rc, projectDir, irisConfig); err != nil {
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

	logger.Info("Iris installation completed successfully",
		zap.String("project_dir", projectDir))
	logger.Info("terminal prompt: Next steps:")
	logger.Info("terminal prompt:   1. Edit config: nano /opt/iris/config.yaml")
	logger.Info("terminal prompt:   2. Start Temporal: temporal server start-dev")
	logger.Info("terminal prompt:   3. Test install: eos debug iris")
	logger.Info("terminal prompt:   4. Start services: sudo systemctl start iris-worker iris-webhook")
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

	// Step 1: Check if Temporal is already accessible
	logger.Info("Checking if Temporal CLI is installed...")
	if temporalPath, err := exec.LookPath("temporal"); err == nil {
		// Verify it actually works
		versionCmd := exec.CommandContext(rc.Ctx, temporalPath, "--version")
		if output, err := versionCmd.CombinedOutput(); err == nil {
			version := strings.TrimSpace(string(output))
			logger.Info("Temporal CLI already installed and working",
				zap.String("path", temporalPath),
				zap.String("version", version))
			return nil
		}
		logger.Warn("Temporal found in PATH but not working", zap.String("path", temporalPath))
	}

	// Step 2: Check common installation locations (might be installed but not in PATH)
	logger.Info("Checking common Temporal installation locations...")
	commonPaths := []string{
		"/usr/local/bin/temporal",
		"/usr/bin/temporal",
		os.ExpandEnv("$HOME/.local/bin/temporal"),
		os.ExpandEnv("$HOME/.temporalio/bin/temporal"),
		"/root/.temporalio/bin/temporal",
	}

	for _, path := range commonPaths {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			// Found it! Verify it works
			versionCmd := exec.CommandContext(rc.Ctx, path, "--version")
			if output, err := versionCmd.CombinedOutput(); err == nil {
				version := strings.TrimSpace(string(output))
				logger.Info("Found working Temporal CLI (not in PATH)",
					zap.String("path", path),
					zap.String("version", version))

				// Fix PATH issue by symlinking
				return fixTemporalPath(rc, path)
			}
		}
	}

	// Step 3: Need to install - detect OS and architecture
	logger.Info("Temporal CLI not found, will install")
	goOS, goArch := detectOSAndArch()
	logger.Info("Detected system architecture",
		zap.String("os", goOS),
		zap.String("arch", goArch))

	// Step 4: Download and install using official installer
	logger.Info("Downloading Temporal CLI installer...")
	logger.Info("This may take a minute for the ~40MB download")

	// Use the official install script with explicit error handling
	installCmd := exec.CommandContext(rc.Ctx, "sh", "-c",
		"curl -sSf https://temporal.download/cli.sh | sh")

	// Capture output for debugging
	output, err := installCmd.CombinedOutput()
	outputStr := strings.TrimSpace(string(output))

	if err != nil {
		logger.Error("Temporal CLI installation failed",
			zap.Error(err),
			zap.String("output", outputStr))

		// Provide actionable error message
		return fmt.Errorf(`Temporal CLI installation failed

Problem: Installation script returned error
Output: %s
Error: %w

This could mean:
1. No internet connection or firewall blocking https://temporal.download
2. Installation script has changed or is temporarily unavailable
3. Insufficient disk space in download directory
4. Permissions issue writing to installation directory

To fix:
1. Check internet: curl -I https://temporal.download/cli.sh
2. Try manual install:
   curl -sSf https://temporal.download/cli.sh | sh
3. Or download from GitHub releases:
   https://github.com/temporalio/cli/releases
4. Ensure /usr/local/bin is writable or use sudo

After manual install, verify with: temporal --version`,
			outputStr, err)
	}

	// Log installation output for diagnostics
	if outputStr != "" {
		logger.Info("Installation output", zap.String("output", outputStr))
	}

	// Step 5: CRITICAL - Verify installation succeeded
	logger.Info("Verifying Temporal CLI installation...")

	// Check all possible locations again
	var workingPath string
	var version string

	// First try PATH
	if temporalPath, err := exec.LookPath("temporal"); err == nil {
		versionCmd := exec.CommandContext(rc.Ctx, temporalPath, "--version")
		if output, err := versionCmd.CombinedOutput(); err == nil {
			workingPath = temporalPath
			version = strings.TrimSpace(string(output))
		}
	}

	// If not in PATH, check common locations
	if workingPath == "" {
		for _, path := range commonPaths {
			if info, err := os.Stat(path); err == nil && !info.IsDir() {
				versionCmd := exec.CommandContext(rc.Ctx, path, "--version")
				if output, err := versionCmd.CombinedOutput(); err == nil {
					workingPath = path
					version = strings.TrimSpace(string(output))
					break
				}
			}
		}
	}

	if workingPath == "" {
		return fmt.Errorf(`Temporal CLI installation verification failed

Problem: Installation script completed but 'temporal' command not found

Checked locations:
- All directories in PATH: %s
- Common locations: /usr/local/bin, /usr/bin, ~/.local/bin, ~/.temporalio/bin

This usually means:
1. Installation script succeeded but installed to unexpected location
2. Installation directory is not in PATH
3. Installation script failed silently

To debug:
1. Search for temporal binary: sudo find / -name temporal -type f 2>/dev/null
2. Check installation logs above for clues
3. Try manual installation: https://docs.temporal.io/cli

If you find the binary, add its directory to PATH:
  export PATH="/path/to/temporal/dir:$PATH"
  echo 'export PATH="/path/to/temporal/dir:$PATH"' >> ~/.bashrc`,
			os.Getenv("PATH"))
	}

	// Step 6: Binary found - check if it needs PATH fixing
	logger.Info("Temporal CLI installed successfully",
		zap.String("path", workingPath),
		zap.String("version", version))

	// If not in PATH, fix it
	if _, err := exec.LookPath("temporal"); err != nil {
		logger.Warn("Temporal installed but not in PATH, fixing...")
		return fixTemporalPath(rc, workingPath)
	}

	logger.Info("Temporal CLI is ready to use")
	return nil
}

func fixTemporalPath(rc *eos_io.RuntimeContext, temporalPath string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// We copy the binary instead of symlinking, so no permission fixes needed on source
	// This keeps /root/ secure with its default 0700 permissions

	// Check if /usr/local/bin is in PATH
	pathEnv := os.Getenv("PATH")
	hasUsrLocalBin := false
	for _, dir := range strings.Split(pathEnv, ":") {
		if dir == "/usr/local/bin" {
			hasUsrLocalBin = true
			break
		}
	}

	if !hasUsrLocalBin {
		return fmt.Errorf(`Temporal CLI found at %s but /usr/local/bin not in PATH

Cannot create symlink because /usr/local/bin is not in your PATH.

Your PATH: %s

Fix Option 1 (Recommended): Add binary directory to PATH
  echo 'export PATH="%s:$PATH"' >> ~/.bashrc
  source ~/.bashrc

Fix Option 2: Add /usr/local/bin to PATH
  echo 'export PATH="/usr/local/bin:$PATH"' >> ~/.bashrc
  source ~/.bashrc
  Then re-run: eos create iris`,
			temporalPath, pathEnv, filepath.Dir(temporalPath))
	}

	// Copy binary to /usr/local/bin instead of symlinking
	// Reason: If source is in /root/, symlink won't work for non-root users
	targetPath := "/usr/local/bin/temporal"

	// Check if target already exists and works
	if info, err := os.Stat(targetPath); err == nil {
		versionCmd := exec.CommandContext(rc.Ctx, targetPath, "--version")
		if versionCmd.Run() == nil {
			logger.Info("Temporal already installed in /usr/local/bin",
				zap.String("path", targetPath),
				zap.Int64("size", info.Size()))
			return nil
		}
		// Exists but doesn't work - remove and replace
		logger.Info("Existing temporal binary doesn't work, replacing")
		_ = os.Remove(targetPath)
	}

	// Copy the binary to /usr/local/bin
	logger.Info("Copying temporal binary to /usr/local/bin",
		zap.String("from", temporalPath),
		zap.String("to", targetPath))

	sourceData, err := os.ReadFile(temporalPath)
	if err != nil {
		return fmt.Errorf("failed to read source binary: %w", err)
	}

	// Write with executable permissions
	if err := os.WriteFile(targetPath, sourceData, 0755); err != nil {
		return fmt.Errorf("failed to write binary to %s: %w", targetPath, err)
	}

	logger.Info("Binary copied successfully",
		zap.String("path", targetPath),
		zap.Int("size_bytes", len(sourceData)))

	// Verify it works
	versionCmd := exec.CommandContext(rc.Ctx, "temporal", "--version")
	if output, err := versionCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("binary copied but temporal command still not working: %w\nOutput: %s", err, string(output))
	}

	logger.Info("Temporal CLI is now available system-wide")
	return nil
}

func detectOSAndArch() (string, string) {
	// Use Go's runtime to detect OS and arch
	// This matches what Temporal's install script does
	goOS := os.Getenv("GOOS")
	if goOS == "" {
		goOS = "linux" // Default assumption for eos
	}

	goArch := os.Getenv("GOARCH")
	if goArch == "" {
		// Try to detect from `uname -m`
		if unameCmd := exec.Command("uname", "-m"); true {
			if output, err := unameCmd.Output(); err == nil {
				machine := strings.TrimSpace(string(output))
				switch machine {
				case "x86_64", "amd64":
					goArch = "amd64"
				case "aarch64", "arm64":
					goArch = "arm64"
				case "armv7l":
					goArch = "arm"
				default:
					goArch = "amd64" // Default
				}
			}
		}
	}

	return goOS, goArch
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

func createConfigFile(rc *eos_io.RuntimeContext, projectDir string, irisConfig IrisConfiguration) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Generate config.yaml from template with actual values
	configYAML := fmt.Sprintf(`# Iris/Delphi Configuration
# Generated by eos create iris

temporal:
  host_port: "%s"
  namespace: "%s"
  task_queue: "%s"

azure_openai:
  endpoint: "%s"
  api_key: "%s"
  deployment_name: "%s"
  api_version: "%s"

email:
  smtp_host: "%s"
  smtp_port: %d
  username: "%s"
  password: "%s"
  from: "%s"
  to: "%s"

webhook:
  port: %d

logging:
  level: "info"
  file: "logs/iris.log"
`,
		irisConfig.Temporal.HostPort,
		irisConfig.Temporal.Namespace,
		irisConfig.Temporal.TaskQueue,
		irisConfig.Azure.Endpoint,
		irisConfig.Azure.APIKey,
		irisConfig.Azure.DeploymentName,
		irisConfig.Azure.APIVersion,
		irisConfig.Email.SMTPHost,
		irisConfig.Email.SMTPPort,
		irisConfig.Email.Username,
		irisConfig.Email.Password,
		irisConfig.Email.From,
		irisConfig.Email.To,
		irisConfig.Webhook.Port,
	)

	configPath := filepath.Join(projectDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(configYAML), 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	logger.Info("Configuration file created",
		zap.String("path", configPath),
		zap.String("permissions", "0600"))

	// Validate YAML structure
	var testConfig map[string]interface{}
	if err := yaml.Unmarshal([]byte(configYAML), &testConfig); err != nil {
		logger.Warn("Generated YAML may be invalid", zap.Error(err))
	} else {
		logger.Info("Configuration validated")
	}

	// Only show edit message if using placeholders
	hasPlaceholders := strings.Contains(configYAML, "YOUR-")
	if hasPlaceholders {
		logger.Warn("IMPORTANT: Edit config.yaml with your actual credentials",
			zap.String("command", fmt.Sprintf("nano %s", configPath)))
	}

	return nil
}

func generateSourceFiles(rc *eos_io.RuntimeContext, projectDir string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Generate worker/main.go
	workerPath := filepath.Join(projectDir, "worker", "main.go")
	if err := os.WriteFile(workerPath, []byte(iris.GetWorkerSource()), 0644); err != nil {
		return fmt.Errorf("failed to write worker source: %w", err)
	}
	logger.Info("Worker source generated", zap.String("path", workerPath))

	// Generate webhook/main.go
	webhookPath := filepath.Join(projectDir, "webhook", "main.go")
	if err := os.WriteFile(webhookPath, []byte(iris.GetWebhookSource()), 0644); err != nil {
		return fmt.Errorf("failed to write webhook source: %w", err)
	}
	logger.Info("Webhook source generated", zap.String("path", webhookPath))

	return nil
}

func installDependencies(rc *eos_io.RuntimeContext, projectDir string) error {
	logger := otelzap.Ctx(rc.Ctx)

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

func createSystemdServices(rc *eos_io.RuntimeContext, projectDir string) error {
	logger := otelzap.Ctx(rc.Ctx)

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
	if err := os.WriteFile(temporalServicePath, []byte(temporalService), 0644); err != nil {
		return fmt.Errorf("failed to write temporal service: %w", err)
	}

	workerServicePath := filepath.Join(projectDir, "iris-worker.service")
	if err := os.WriteFile(workerServicePath, []byte(workerService), 0644); err != nil {
		return fmt.Errorf("failed to write worker service: %w", err)
	}

	webhookServicePath := filepath.Join(projectDir, "iris-webhook.service")
	if err := os.WriteFile(webhookServicePath, []byte(webhookService), 0644); err != nil {
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

func createTestScriptAndDocs(rc *eos_io.RuntimeContext, projectDir string) error {
	logger := otelzap.Ctx(rc.Ctx)

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
	if err := os.WriteFile(testScriptPath, []byte(testScript), 0755); err != nil {
		return fmt.Errorf("failed to write test script: %w", err)
	}
	logger.Info("Test script created", zap.String("path", testScriptPath))

	// Create README
	readmePath := filepath.Join(projectDir, "README.md")
	if err := os.WriteFile(readmePath, []byte(iris.GetReadmeContent()), 0644); err != nil {
		return fmt.Errorf("failed to write README: %w", err)
	}
	logger.Info("README created", zap.String("path", readmePath))

	return nil
}

// Configuration helper functions

func hasConfigFlags() bool {
	return azureEndpoint != "" || azureAPIKey != "" ||
		smtpHost != "" || smtpUsername != ""
}

func getPlaceholderConfig() IrisConfiguration {
	return IrisConfiguration{
		Azure: struct {
			Endpoint       string
			APIKey         string
			DeploymentName string
			APIVersion     string
		}{
			Endpoint:       "https://YOUR-RESOURCE.openai.azure.com/",
			APIKey:         "YOUR-AZURE-OPENAI-API-KEY",
			DeploymentName: "gpt-4o",
			APIVersion:     "2024-08-01-preview",
		},
		Email: struct {
			SMTPHost string
			SMTPPort int
			Username string
			Password string
			From     string
			To       string
		}{
			SMTPHost: "mail.cybermonkey.sh",
			SMTPPort: 587,
			Username: "alerts@cybermonkey.sh",
			Password: "YOUR-SMTP-PASSWORD",
			From:     "Delphi Notify <alerts@cybermonkey.sh>",
			To:       "support@cybermonkey.net.au",
		},
		Webhook: struct{ Port int }{Port: 8080},
		Temporal: struct {
			HostPort  string
			Namespace string
			TaskQueue string
		}{
			HostPort:  "localhost:7233",
			Namespace: "default",
			TaskQueue: "wazuh-alerts",
		},
	}
}

func getConfigFromFlags() IrisConfiguration {
	config := IrisConfiguration{
		Azure: struct {
			Endpoint       string
			APIKey         string
			DeploymentName string
			APIVersion     string
		}{
			Endpoint:       azureEndpoint,
			APIKey:         azureAPIKey,
			DeploymentName: azureDeployment,
			APIVersion:     "2024-08-01-preview",
		},
		Email: struct {
			SMTPHost string
			SMTPPort int
			Username string
			Password string
			From     string
			To       string
		}{
			SMTPHost: smtpHost,
			SMTPPort: smtpPort,
			Username: smtpUsername,
			Password: smtpPassword,
			From:     emailFrom,
			To:       emailTo,
		},
		Webhook: struct{ Port int }{Port: 8080},
		Temporal: struct {
			HostPort  string
			Namespace string
			TaskQueue string
		}{
			HostPort:  "localhost:7233",
			Namespace: "default",
			TaskQueue: "wazuh-alerts",
		},
	}

	// Fill in defaults if not provided
	if config.Azure.DeploymentName == "" {
		config.Azure.DeploymentName = "gpt-4o"
	}
	if config.Email.From == "" && config.Email.Username != "" {
		config.Email.From = fmt.Sprintf("Delphi Notify <%s>", config.Email.Username)
	}

	return config
}

func gatherInteractiveConfig(rc *eos_io.RuntimeContext, config *IrisConfiguration) error {
	logger := otelzap.Ctx(rc.Ctx)
	reader := bufio.NewReader(os.Stdin)

	logger.Info("terminal prompt: === Azure OpenAI Configuration ===")
	logger.Info("terminal prompt: Find these values in Azure Portal → Your OpenAI Resource")

	// Azure Endpoint
	for {
		logger.Info("terminal prompt: Azure OpenAI Endpoint (e.g., https://YOUR-RESOURCE.openai.azure.com/)")
		fmt.Print("Azure OpenAI Endpoint: ")
		config.Azure.Endpoint = strings.TrimSpace(mustReadLine(reader))

		if err := validateAzureEndpoint(config.Azure.Endpoint); err != nil {
			logger.Warn("Invalid endpoint", zap.Error(err))
			continue
		}
		break
	}

	// Azure API Key
	for {
		logger.Info("terminal prompt: Azure OpenAI API Key (hidden input)")
		fmt.Print("Azure OpenAI API Key: ")

		if password, err := term.ReadPassword(int(os.Stdin.Fd())); err == nil {
			fmt.Println() // New line after hidden input
			config.Azure.APIKey = strings.TrimSpace(string(password))
		} else {
			logger.Warn("Could not hide input", zap.Error(err))
			config.Azure.APIKey = strings.TrimSpace(mustReadLine(reader))
		}

		if config.Azure.APIKey == "" {
			logger.Warn("API key is required")
			continue
		}
		if len(config.Azure.APIKey) < 32 {
			logger.Warn("API key seems too short")
			continue
		}
		break
	}

	// Azure Deployment Name
	logger.Info("terminal prompt: Deployment Name [gpt-4o]")
	fmt.Print("Deployment Name [gpt-4o]: ")
	input := strings.TrimSpace(mustReadLine(reader))
	if input == "" {
		config.Azure.DeploymentName = "gpt-4o"
	} else {
		config.Azure.DeploymentName = input
	}

	config.Azure.APIVersion = "2024-08-01-preview"

	logger.Info("terminal prompt: === Email/SMTP Configuration ===")

	// SMTP Host
	for {
		logger.Info("terminal prompt: SMTP Host (e.g., mail.cybermonkey.sh)")
		fmt.Print("SMTP Host: ")
		config.Email.SMTPHost = strings.TrimSpace(mustReadLine(reader))

		if config.Email.SMTPHost == "" {
			logger.Warn("SMTP host is required")
			continue
		}
		break
	}

	// SMTP Port
	logger.Info("terminal prompt: SMTP Port [587]")
	fmt.Print("SMTP Port [587]: ")
	portStr := strings.TrimSpace(mustReadLine(reader))
	if portStr == "" {
		config.Email.SMTPPort = 587
	} else {
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			logger.Warn("Invalid port, using default 587")
			config.Email.SMTPPort = 587
		} else {
			config.Email.SMTPPort = port
		}
	}

	// SMTP Username
	for {
		logger.Info("terminal prompt: SMTP Username (e.g., alerts@cybermonkey.sh)")
		fmt.Print("SMTP Username: ")
		config.Email.Username = strings.TrimSpace(mustReadLine(reader))

		if err := validateEmail(config.Email.Username); err != nil {
			logger.Warn("Invalid email", zap.Error(err))
			continue
		}
		break
	}

	// SMTP Password
	for {
		logger.Info("terminal prompt: SMTP Password (hidden input)")
		fmt.Print("SMTP Password: ")

		if password, err := term.ReadPassword(int(os.Stdin.Fd())); err == nil {
			fmt.Println() // New line
			config.Email.Password = strings.TrimSpace(string(password))
		} else {
			logger.Warn("Could not hide input", zap.Error(err))
			config.Email.Password = strings.TrimSpace(mustReadLine(reader))
		}

		if config.Email.Password == "" {
			logger.Warn("SMTP password is required")
			continue
		}
		break
	}

	// From Address
	defaultFrom := fmt.Sprintf("Delphi Notify <%s>", config.Email.Username)
	logger.Info("terminal prompt: From Address", zap.String("default", defaultFrom))
	fmt.Printf("From Address [%s]: ", defaultFrom)
	input = strings.TrimSpace(mustReadLine(reader))
	if input == "" {
		config.Email.From = defaultFrom
	} else {
		config.Email.From = input
	}

	// To Address
	for {
		logger.Info("terminal prompt: To Address (where alerts go, e.g., support@cybermonkey.net.au)")
		fmt.Print("To Address: ")
		config.Email.To = strings.TrimSpace(mustReadLine(reader))

		if err := validateEmail(config.Email.To); err != nil {
			logger.Warn("Invalid email", zap.Error(err))
			continue
		}
		break
	}

	logger.Info("Configuration complete")
	logger.Info("Configuration summary",
		zap.String("azure_endpoint", config.Azure.Endpoint),
		zap.String("azure_deployment", config.Azure.DeploymentName),
		zap.String("smtp_host", fmt.Sprintf("%s:%d", config.Email.SMTPHost, config.Email.SMTPPort)),
		zap.String("smtp_username", config.Email.Username),
		zap.String("alert_recipient", config.Email.To))

	logger.Info("terminal prompt: Proceed with this configuration? [y/N]")
	fmt.Print("Proceed with this configuration? [y/N]: ")
	response := strings.TrimSpace(strings.ToLower(mustReadLine(reader)))
	if response != "y" && response != "yes" {
		return fmt.Errorf("configuration cancelled by user")
	}

	return nil
}

// Validation functions

func validateAzureEndpoint(endpoint string) error {
	if endpoint == "" {
		return fmt.Errorf("endpoint cannot be empty")
	}
	if !strings.HasPrefix(endpoint, "https://") {
		return fmt.Errorf("endpoint must start with https://")
	}
	if !strings.Contains(endpoint, ".openai.azure.com") {
		return fmt.Errorf("endpoint must contain .openai.azure.com")
	}
	if !strings.HasSuffix(endpoint, "/") {
		return fmt.Errorf("endpoint must end with /")
	}
	return nil
}

func validateEmail(email string) error {
	if email == "" {
		return fmt.Errorf("email cannot be empty")
	}
	// Simple email validation
	if !strings.Contains(email, "@") || !strings.Contains(email, ".") {
		return fmt.Errorf("invalid email format")
	}
	return nil
}

func validateConfiguration(config IrisConfiguration) error {
	// Validate Azure
	if err := validateAzureEndpoint(config.Azure.Endpoint); err != nil {
		return fmt.Errorf("azure endpoint: %w", err)
	}
	if config.Azure.APIKey == "" || len(config.Azure.APIKey) < 32 {
		return fmt.Errorf("azure API key is required and must be at least 32 characters")
	}
	if config.Azure.DeploymentName == "" {
		return fmt.Errorf("azure deployment name is required")
	}

	// Validate Email
	if config.Email.SMTPHost == "" {
		return fmt.Errorf("SMTP host is required")
	}
	if config.Email.SMTPPort < 1 || config.Email.SMTPPort > 65535 {
		return fmt.Errorf("SMTP port must be between 1 and 65535")
	}
	if err := validateEmail(config.Email.Username); err != nil {
		return fmt.Errorf("SMTP username: %w", err)
	}
	if config.Email.Password == "" {
		return fmt.Errorf("SMTP password is required")
	}
	if err := validateEmail(config.Email.To); err != nil {
		return fmt.Errorf("email recipient: %w", err)
	}

	return nil
}

func mustReadLine(reader *bufio.Reader) string {
	input, err := reader.ReadString('\n')
	if err != nil {
		return ""
	}
	return strings.TrimSpace(input)
}
