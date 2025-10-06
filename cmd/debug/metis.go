// cmd/debug/metis.go
package debug

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

var debugMetisCmd = &cobra.Command{
	Use:   "metis",
	Short: "Debug Metis installation and configuration",
	Long: `Comprehensive diagnostic tool for Metis security alert processing system.

Checks performed:
1. Project structure and files
2. Configuration file validity
3. Temporal server connectivity
4. Worker process status
5. Webhook server status
6. Azure OpenAI configuration
7. SMTP configuration
8. Recent workflows in Temporal
9. Go module dependencies

Flags:
  --test      Send a test alert through the system
  --verbose   Show detailed diagnostic output`,
	RunE: eos.Wrap(runDebugMetis),
}

var (
	testAlert bool
	verbose   bool
)

func init() {
	debugMetisCmd.Flags().BoolVar(&testAlert, "test", false, "Send a test alert")
	debugMetisCmd.Flags().BoolVar(&verbose, "verbose", false, "Verbose output")
	debugCmd.AddCommand(debugMetisCmd)
}

func runDebugMetis(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting Metis diagnostic checks")

	projectDir := "/opt/metis"
	passed := 0
	failed := 0

	// Check 1: Project structure
	logger.Info("Check 1/9: Verifying project structure")
	if err := checkProjectStructure(rc, projectDir); err != nil {
		logger.Error("Project structure check failed", zap.Error(err))
		failed++
	} else {
		logger.Info("✓ Project structure OK")
		passed++
	}

	// Check 2: Configuration file
	logger.Info("Check 2/9: Validating configuration file")
	config, err := checkConfiguration(rc, projectDir)
	if err != nil {
		logger.Error("Configuration check failed", zap.Error(err))
		failed++
	} else {
		logger.Info("✓ Configuration valid")
		passed++
	}

	// Check 3: Temporal server
	logger.Info("Check 3/9: Testing Temporal server connectivity")
	if err := checkTemporalServer(rc, config); err != nil {
		logger.Error("Temporal server check failed", zap.Error(err))
		logger.Info("terminal prompt: Start Temporal with: temporal server start-dev")
		failed++
	} else {
		logger.Info("✓ Temporal server reachable")
		passed++
	}

	// Check 4: Worker process
	logger.Info("Check 4/9: Checking worker process")
	if err := checkWorkerProcess(rc); err != nil {
		logger.Warn("Worker process check failed", zap.Error(err))
		logger.Info("terminal prompt: Start worker: cd /opt/metis/worker && go run main.go")
		failed++
	} else {
		logger.Info("✓ Worker process running")
		passed++
	}

	// Check 5: Webhook server
	logger.Info("Check 5/9: Checking webhook server")
	if err := checkWebhookServer(rc, config); err != nil {
		logger.Warn("Webhook server check failed", zap.Error(err))
		logger.Info("terminal prompt: Start webhook: cd /opt/metis/webhook && go run main.go")
		failed++
	} else {
		logger.Info("✓ Webhook server responding")
		passed++
	}

	// Check 6: Azure OpenAI configuration
	logger.Info("Check 6/9: Validating Azure OpenAI configuration")
	if err := checkAzureOpenAI(rc, config); err != nil {
		logger.Warn("Azure OpenAI configuration check failed", zap.Error(err))
		logger.Info("terminal prompt: Update config.yaml with valid Azure OpenAI credentials")
		failed++
	} else {
		logger.Info("✓ Azure OpenAI configuration valid")
		passed++
	}

	// Check 7: SMTP configuration
	logger.Info("Check 7/9: Validating SMTP configuration")
	if err := checkSMTPConfig(rc, config); err != nil {
		logger.Warn("SMTP configuration check failed", zap.Error(err))
		logger.Info("terminal prompt: Update config.yaml with valid SMTP credentials")
		failed++
	} else {
		logger.Info("✓ SMTP configuration valid")
		passed++
	}

	// Check 8: Recent workflows
	logger.Info("Check 8/9: Checking recent Temporal workflows")
	if err := checkRecentWorkflows(rc, config); err != nil {
		logger.Debug("Recent workflows check skipped", zap.Error(err))
		// Don't count as failure - might be fresh install
	} else {
		logger.Info("✓ Temporal workflows accessible")
		passed++
	}

	// Check 9: Go dependencies
	logger.Info("Check 9/9: Verifying Go dependencies")
	if err := checkGoDependencies(rc, projectDir); err != nil {
		logger.Warn("Go dependencies check failed", zap.Error(err))
		logger.Info("terminal prompt: Run: cd /opt/metis/worker && go mod tidy")
		failed++
	} else {
		logger.Info("✓ Go dependencies OK")
		passed++
	}

	// Summary
	logger.Info("Diagnostic summary",
		zap.Int("passed", passed),
		zap.Int("failed", failed),
		zap.Int("total", 9))

	// Test alert if requested
	if testAlert {
		logger.Info("Sending test alert")
		if err := sendTestAlert(rc, config); err != nil {
			logger.Error("Test alert failed", zap.Error(err))
			return fmt.Errorf("test alert failed: %w", err)
		}
		logger.Info("✓ Test alert sent - check Temporal UI at http://localhost:8233")
	}

	if failed > 0 {
		logger.Warn("Some checks failed - see messages above for remediation")
		return fmt.Errorf("%d diagnostic checks failed", failed)
	}

	logger.Info("All diagnostic checks passed")
	return nil
}

func checkProjectStructure(rc *eos_io.RuntimeContext, projectDir string) error {
	logger := otelzap.Ctx(rc.Ctx)

	requiredPaths := []string{
		projectDir,
		filepath.Join(projectDir, "worker"),
		filepath.Join(projectDir, "webhook"),
		filepath.Join(projectDir, "worker", "main.go"),
		filepath.Join(projectDir, "webhook", "main.go"),
		filepath.Join(projectDir, "config.yaml"),
	}

	for _, path := range requiredPaths {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return fmt.Errorf("missing required path: %s", path)
		}
		if verbose {
			logger.Debug("Found", zap.String("path", path))
		}
	}

	return nil
}

type MetisConfig struct {
	Temporal struct {
		HostPort  string `yaml:"host_port"`
		Namespace string `yaml:"namespace"`
		TaskQueue string `yaml:"task_queue"`
	} `yaml:"temporal"`
	AzureOpenAI struct {
		Endpoint       string `yaml:"endpoint"`
		APIKey         string `yaml:"api_key"`
		DeploymentName string `yaml:"deployment_name"`
		APIVersion     string `yaml:"api_version"`
	} `yaml:"azure_openai"`
	Email struct {
		SMTPHost string `yaml:"smtp_host"`
		SMTPPort int    `yaml:"smtp_port"`
		Username string `yaml:"username"`
		Password string `yaml:"password"`
		From     string `yaml:"from"`
		To       string `yaml:"to"`
	} `yaml:"email"`
	Webhook struct {
		Port int `yaml:"port"`
	} `yaml:"webhook"`
}

func checkConfiguration(rc *eos_io.RuntimeContext, projectDir string) (*MetisConfig, error) {
	logger := otelzap.Ctx(rc.Ctx)

	configPath := filepath.Join(projectDir, "config.yaml")
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	var config MetisConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Validate required fields
	if config.Temporal.HostPort == "" {
		return nil, fmt.Errorf("temporal.host_port not configured")
	}
	if config.AzureOpenAI.Endpoint == "" || strings.Contains(config.AzureOpenAI.Endpoint, "YOUR-") {
		return nil, fmt.Errorf("azure_openai.endpoint not configured")
	}
	if config.Email.SMTPHost == "" {
		return nil, fmt.Errorf("email.smtp_host not configured")
	}

	if verbose {
		logger.Debug("Configuration loaded",
			zap.String("temporal_host", config.Temporal.HostPort),
			zap.String("openai_endpoint", config.AzureOpenAI.Endpoint),
			zap.String("smtp_host", config.Email.SMTPHost))
	}

	return &config, nil
}

func checkTemporalServer(rc *eos_io.RuntimeContext, config *MetisConfig) error {
	if config == nil {
		return fmt.Errorf("config not loaded")
	}

	// Try to connect to Temporal health endpoint
	ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Second)
	defer cancel()

	healthURL := fmt.Sprintf("http://%s/", strings.Replace(config.Temporal.HostPort, ":7233", ":7233", 1))
	req, err := http.NewRequestWithContext(ctx, "GET", healthURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("temporal server not reachable at %s: %w", config.Temporal.HostPort, err)
	}
	defer resp.Body.Close()

	return nil
}

func checkWorkerProcess(rc *eos_io.RuntimeContext) error {
	// Check if worker is running via systemd
	checkCmd := exec.CommandContext(rc.Ctx, "systemctl", "is-active", "metis-worker")
	if output, err := checkCmd.Output(); err == nil {
		status := strings.TrimSpace(string(output))
		if status == "active" {
			return nil
		}
	}

	// Check if running as standalone process
	psCmd := exec.CommandContext(rc.Ctx, "pgrep", "-f", "worker/main.go")
	if err := psCmd.Run(); err == nil {
		return nil // Process found
	}

	return fmt.Errorf("worker process not running")
}

func checkWebhookServer(rc *eos_io.RuntimeContext, config *MetisConfig) error {
	if config == nil {
		return fmt.Errorf("config not loaded")
	}

	// Check if webhook is running via systemd
	checkCmd := exec.CommandContext(rc.Ctx, "systemctl", "is-active", "metis-webhook")
	if output, err := checkCmd.Output(); err == nil {
		status := strings.TrimSpace(string(output))
		if status == "active" {
			// Also check HTTP endpoint
			return checkWebhookHTTP(rc, config)
		}
	}

	// Check if running as standalone process
	psCmd := exec.CommandContext(rc.Ctx, "pgrep", "-f", "webhook/main.go")
	if err := psCmd.Run(); err == nil {
		return checkWebhookHTTP(rc, config)
	}

	return fmt.Errorf("webhook server not running")
}

func checkWebhookHTTP(rc *eos_io.RuntimeContext, config *MetisConfig) error {
	ctx, cancel := context.WithTimeout(rc.Ctx, 3*time.Second)
	defer cancel()

	webhookURL := fmt.Sprintf("http://localhost:%d/health", config.Webhook.Port)
	req, err := http.NewRequestWithContext(ctx, "GET", webhookURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook health endpoint not responding: %w", err)
	}
	defer resp.Body.Close()

	return nil
}

func checkAzureOpenAI(rc *eos_io.RuntimeContext, config *MetisConfig) error {
	if config == nil {
		return fmt.Errorf("config not loaded")
	}

	// Basic validation
	if strings.Contains(config.AzureOpenAI.APIKey, "YOUR-") {
		return fmt.Errorf("azure_openai.api_key contains placeholder text")
	}
	if config.AzureOpenAI.DeploymentName == "" {
		return fmt.Errorf("azure_openai.deployment_name not set")
	}
	if !strings.HasPrefix(config.AzureOpenAI.Endpoint, "https://") {
		return fmt.Errorf("azure_openai.endpoint must start with https://")
	}

	return nil
}

func checkSMTPConfig(rc *eos_io.RuntimeContext, config *MetisConfig) error {
	if config == nil {
		return fmt.Errorf("config not loaded")
	}

	if config.Email.SMTPHost == "" {
		return fmt.Errorf("email.smtp_host not set")
	}
	if config.Email.SMTPPort == 0 {
		return fmt.Errorf("email.smtp_port not set")
	}
	if config.Email.From == "" {
		return fmt.Errorf("email.from not set")
	}
	if config.Email.To == "" {
		return fmt.Errorf("email.to not set")
	}

	return nil
}

func checkRecentWorkflows(rc *eos_io.RuntimeContext, config *MetisConfig) error {
	if config == nil {
		return fmt.Errorf("config not loaded")
	}

	// Use temporal CLI if available
	if _, err := exec.LookPath("temporal"); err != nil {
		return fmt.Errorf("temporal CLI not available")
	}

	listCmd := exec.CommandContext(rc.Ctx, "temporal", "workflow", "list",
		"--address", config.Temporal.HostPort,
		"--namespace", config.Temporal.Namespace,
		"--limit", "5")
	if output, err := listCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to list workflows: %s", string(output))
	}

	return nil
}

func checkGoDependencies(rc *eos_io.RuntimeContext, projectDir string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check worker dependencies
	workerDir := filepath.Join(projectDir, "worker")
	if _, err := os.Stat(filepath.Join(workerDir, "go.mod")); os.IsNotExist(err) {
		return fmt.Errorf("worker/go.mod not found")
	}

	workerVerify := exec.CommandContext(rc.Ctx, "go", "mod", "verify")
	workerVerify.Dir = workerDir
	if output, err := workerVerify.CombinedOutput(); err != nil {
		logger.Debug("Worker go mod verify failed", zap.String("output", string(output)))
		return fmt.Errorf("worker dependencies invalid: %s", string(output))
	}

	// Check webhook dependencies
	webhookDir := filepath.Join(projectDir, "webhook")
	if _, err := os.Stat(filepath.Join(webhookDir, "go.mod")); os.IsNotExist(err) {
		return fmt.Errorf("webhook/go.mod not found")
	}

	webhookVerify := exec.CommandContext(rc.Ctx, "go", "mod", "verify")
	webhookVerify.Dir = webhookDir
	if output, err := webhookVerify.CombinedOutput(); err != nil {
		logger.Debug("Webhook go mod verify failed", zap.String("output", string(output)))
		return fmt.Errorf("webhook dependencies invalid: %s", string(output))
	}

	return nil
}

func sendTestAlert(rc *eos_io.RuntimeContext, config *MetisConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	if config == nil {
		return fmt.Errorf("config not loaded")
	}

	testAlert := map[string]interface{}{
		"agent": map[string]string{
			"name": "test-server",
			"id":   "001",
		},
		"data": map[string]interface{}{
			"vulnerability": map[string]interface{}{
				"severity": "High",
				"package": map[string]string{
					"name": "test-package",
				},
				"title": "TEST: Metis diagnostic test alert",
			},
		},
	}

	alertJSON, err := json.Marshal(testAlert)
	if err != nil {
		return fmt.Errorf("failed to marshal test alert: %w", err)
	}

	webhookURL := fmt.Sprintf("http://localhost:%d/webhook", config.Webhook.Port)
	logger.Info("Sending test alert", zap.String("url", webhookURL))

	ctx, cancel := context.WithTimeout(rc.Ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", webhookURL, strings.NewReader(string(alertJSON)))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send test alert: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	logger.Info("Test alert sent successfully - check Temporal UI and email")
	return nil
}
